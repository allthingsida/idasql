/**
 * database.hpp - IDASQL API
 *
 * Two-tier API design reflecting IDA's singleton nature:
 *
 * TIER 1: QueryEngine (recommended for most use)
 *   - Use when IDA is already initialized (plugins, scripts, idalib)
 *   - Just creates SQLite + virtual tables
 *   - No IDA lifecycle management
 *
 * TIER 2: Session (for standalone CLI tools)
 *   - Full IDA lifecycle: init_library + open_database + close
 *   - Use for tools like idasql.exe that manage everything
 *
 * TIER 3: Free functions (quick one-liners)
 *   - idasql::query(), idasql::exec(), idasql::execute()
 *   - Use global engine, lazily initialized
 *
 * IMPORTANT: IDA SDK is a singleton. Only ONE database can be open.
 * The Session class doesn't create "a database" - it manages THE database.
 */

#pragma once

#include <idasql/platform.hpp>

#include <xsql/database.hpp>
#include <xsql/json.hpp>
#include <xsql/script.hpp>
#include <idasql/runtime_settings.hpp>
#include <string>
#include <vector>
#include <memory>
#include <cctype>
#include <limits>

#include <idasql/platform_undef.hpp>

// IDA SDK
#include <ida.hpp>
#include <idalib.hpp>
#include <auto.hpp>
#include <strlist.hpp>
#include <algorithm>

// IDASQL components
#include <idasql/entities.hpp>
#include <idasql/entities_ext.hpp>
#include <idasql/entities_types.hpp>
#include <idasql/metadata.hpp>
#include <idasql/functions.hpp>
#include <idasql/disassembly.hpp>
#include <idasql/search_bytes.hpp>
#include <idasql/entities_dbg.hpp>

// Optional: Decompiler (may not be available)
#ifdef USE_HEXRAYS
#include <idasql/decompiler.hpp>
#endif

namespace idasql {

// ============================================================================
// Result Types
// ============================================================================

/**
 * Single row from a query result
 */
struct Row {
    std::vector<std::string> values;

    const std::string& operator[](size_t i) const { return values[i]; }
    size_t size() const { return values.size(); }
};

/**
 * Query result set
 */
struct QueryResult {
    std::vector<std::string> columns;
    std::vector<Row> rows;
    std::string error;
    std::vector<std::string> warnings;
    bool success = false;
    bool timed_out = false;
    bool partial = false;
    int elapsed_ms = 0;

    // Convenience accessors
    size_t row_count() const { return rows.size(); }
    size_t column_count() const { return columns.size(); }
    bool empty() const { return rows.empty(); }

    // Get first cell as scalar (for single-value queries)
    std::string scalar() const {
        return (!empty() && rows[0].size() > 0) ? rows[0][0] : "";
    }

    // Iterator support
    auto begin() { return rows.begin(); }
    auto end() { return rows.end(); }
    auto begin() const { return rows.begin(); }
    auto end() const { return rows.end(); }

    // Format as string for display
    std::string to_string() const {
        if (!success) return error;
        if (empty()) return "(0 rows)";

        std::string result;
        // Header
        for (size_t i = 0; i < columns.size(); ++i) {
            if (i > 0) result += " | ";
            result += columns[i];
        }
        result += "\n";
        // Separator
        for (size_t i = 0; i < columns.size(); ++i) {
            if (i > 0) result += "-+-";
            result += std::string(columns[i].size(), '-');
        }
        result += "\n";
        // Rows
        for (const auto& row : rows) {
            for (size_t i = 0; i < row.size(); ++i) {
                if (i > 0) result += " | ";
                result += row[i];
            }
            result += "\n";
        }
        result += "(" + std::to_string(row_count()) + " rows)";
        if (!warnings.empty()) {
            result += "\nWarnings:";
            for (const auto& warning : warnings) {
                result += "\n  - " + warning;
            }
        }
        if (timed_out) {
            result += "\n(timed out after " + std::to_string(elapsed_ms) + " ms)";
        }
        return result;
    }
};

// ============================================================================
// TIER 1: QueryEngine - SQL interface (no IDA lifecycle)
// ============================================================================

/**
 * QueryEngine - SQLite query interface to the current IDA database
 *
 * Use this when IDA is already initialized. Does NOT manage IDA lifecycle.
 * You can have multiple QueryEngine instances - they all query the same
 * IDA database (because IDA is singleton).
 *
 * Example:
 *   idasql::QueryEngine qe;
 *   auto result = qe.query("SELECT name, size FROM funcs LIMIT 10");
 *   for (const auto& row : result) {
 *       msg("%s: %s\n", row[0].c_str(), row[1].c_str());
 *   }
 */
class QueryEngine {
public:
    QueryEngine() {
        init();
    }

    ~QueryEngine() = default;

    // Moveable but not copyable
    QueryEngine(QueryEngine&&) noexcept = default;
    QueryEngine& operator=(QueryEngine&&) noexcept = default;

    QueryEngine(const QueryEngine&) = delete;
    QueryEngine& operator=(const QueryEngine&) = delete;

    /**
     * Execute SQL and return results
     */
    QueryResult query(const std::string& sql) {
        return query(sql.c_str());
    }

    QueryResult query(const char* sql) {
        QueryResult result;

        if (!db_.is_open()) {
            result.error = "QueryEngine not initialized";
            return result;
        }

        if (handle_runtime_pragma(sql, result)) {
            error_ = result.success ? "" : result.error;
            return result;
        }

        xsql::QueryOptions options;
        options.timeout_ms = runtime_settings().query_timeout_ms();
        xsql::Result raw = db_.query(sql, options);
        result.columns = std::move(raw.columns);
        result.rows.reserve(raw.rows.size());
        for (auto& raw_row : raw.rows) {
            Row row;
            row.values = std::move(raw_row.values);
            result.rows.push_back(std::move(row));
        }
        result.error = std::move(raw.error);
        result.warnings = std::move(raw.warnings);
        result.timed_out = raw.timed_out;
        result.partial = raw.partial;
        result.elapsed_ms = raw.elapsed_ms;
        append_query_hints(sql ? std::string(sql) : std::string(), result);
        result.success = result.error.empty();
        error_ = result.success ? "" : result.error;

        return result;
    }

    /**
     * Execute SQL, ignoring rows
     */
    xsql::Status exec(const char* sql) {
        if (!db_.is_open()) {
            error_ = "QueryEngine not initialized";
            return xsql::Status::error;
        }

        QueryResult pragma_result;
        if (handle_runtime_pragma(sql, pragma_result)) {
            error_ = pragma_result.success ? "" : pragma_result.error;
            return pragma_result.success ? xsql::Status::ok : xsql::Status::error;
        }

        xsql::Status rc = db_.exec(sql);
        error_ = db_.last_error();
        return rc;
    }

    /**
     * Execute SQL, ignore results (for INSERT/UPDATE/DELETE)
     */
    bool execute(const char* sql) {
        return xsql::is_ok(exec(sql));
    }

    /**
     * Execute multi-statement SQL script and collect statement results.
     */
    bool execute_script(const std::string& script,
                        std::vector<xsql::StatementResult>& results,
                        std::string& error) {
        if (!db_.is_open()) {
            error_ = "QueryEngine not initialized";
            error = error_;
            return false;
        }

        bool ok = db_.execute_script(script, results, error);
        error_ = ok ? "" : error;
        return ok;
    }

    /**
     * Export tables to a SQL file.
     */
    bool export_tables(const std::vector<std::string>& tables,
                       const std::string& output_path,
                       std::string& error) {
        if (!db_.is_open()) {
            error_ = "QueryEngine not initialized";
            error = error_;
            return false;
        }

        bool ok = db_.export_tables(tables, output_path, error);
        error_ = ok ? "" : error;
        return ok;
    }

    /**
     * Get single value (first column of first row)
     */
    std::string scalar(const std::string& sql) {
        return scalar(sql.c_str());
    }

    std::string scalar(const char* sql) {
        auto result = query(sql);
        if (result.success && !result.empty()) {
            return result.rows[0].values[0];
        }
        return "";
    }

    /**
     * Get last error message
     */
    const std::string& error() const { return error_; }

    /**
     * Check if initialized
     */
    bool is_valid() const { return db_.is_open(); }

    /**
     * Advanced access to the underlying xsql database wrapper.
     * Use this for module registration workflows (custom virtual tables).
     */
    xsql::Database& database() { return db_; }
    const xsql::Database& database() const { return db_; }

private:
    static std::string trim_copy(const std::string& s) {
        size_t begin = 0;
        while (begin < s.size() && std::isspace(static_cast<unsigned char>(s[begin]))) {
            ++begin;
        }
        size_t end = s.size();
        while (end > begin && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
            --end;
        }
        return s.substr(begin, end - begin);
    }

    static std::string to_lower_copy(std::string value) {
        for (char& c : value) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return value;
    }

    static std::string strip_optional_quotes(const std::string& s) {
        if (s.size() >= 2) {
            char a = s.front();
            char b = s.back();
            if ((a == '\'' && b == '\'') || (a == '"' && b == '"')) {
                return s.substr(1, s.size() - 2);
            }
        }
        return s;
    }

    static bool parse_int_value(const std::string& text, int& value) {
        try {
            size_t consumed = 0;
            long long parsed = std::stoll(text, &consumed, 10);
            if (consumed != text.size()) {
                return false;
            }
            if (parsed < (std::numeric_limits<int>::min)() ||
                parsed > (std::numeric_limits<int>::max)()) {
                return false;
            }
            value = static_cast<int>(parsed);
            return true;
        } catch (...) {
            return false;
        }
    }

    static bool parse_bool_value(const std::string& text, bool& value) {
        const std::string lower = to_lower_copy(trim_copy(text));
        if (lower == "1" || lower == "on" || lower == "true" || lower == "yes") {
            value = true;
            return true;
        }
        if (lower == "0" || lower == "off" || lower == "false" || lower == "no") {
            value = false;
            return true;
        }
        return false;
    }

    static QueryResult make_pragma_result(const std::string& key, const std::string& value) {
        QueryResult result;
        result.columns = {"name", "value"};
        Row row;
        row.values = {key, value};
        result.rows.push_back(std::move(row));
        result.success = true;
        return result;
    }

    static QueryResult make_pragma_error(const std::string& error) {
        QueryResult result;
        result.success = false;
        result.error = error;
        return result;
    }

    bool handle_runtime_pragma(const char* sql, QueryResult& out) {
        if (sql == nullptr) {
            return false;
        }

        std::string text = trim_copy(sql);
        if (text.empty()) {
            return false;
        }
        if (!text.empty() && text.back() == ';') {
            text.pop_back();
            text = trim_copy(text);
        }

        std::string lower = to_lower_copy(text);
        const std::string pragma_prefix = "pragma";
        if (lower.rfind(pragma_prefix, 0) != 0) {
            return false;
        }

        std::string body = trim_copy(text.substr(pragma_prefix.size()));
        std::string body_lower = to_lower_copy(body);
        const std::string idasql_prefix = "idasql.";
        if (body_lower.rfind(idasql_prefix, 0) != 0) {
            return false;
        }

        std::string key_expr = trim_copy(body.substr(idasql_prefix.size()));
        std::string value_expr;
        size_t eq_pos = key_expr.find('=');
        if (eq_pos != std::string::npos) {
            value_expr = trim_copy(key_expr.substr(eq_pos + 1));
            key_expr = trim_copy(key_expr.substr(0, eq_pos));
            value_expr = strip_optional_quotes(value_expr);
        }

        const std::string key = to_lower_copy(key_expr);
        auto& settings = runtime_settings();

        if (key == "query_timeout_ms") {
            if (value_expr.empty()) {
                out = make_pragma_result("query_timeout_ms", std::to_string(settings.query_timeout_ms()));
                return true;
            }
            int timeout_ms = 0;
            if (!parse_int_value(value_expr, timeout_ms) || !settings.set_query_timeout_ms(timeout_ms)) {
                out = make_pragma_error("Invalid idasql.query_timeout_ms value");
                return true;
            }
            out = make_pragma_result("query_timeout_ms", std::to_string(settings.query_timeout_ms()));
            return true;
        }

        if (key == "queue_admission_timeout_ms") {
            if (value_expr.empty()) {
                out = make_pragma_result("queue_admission_timeout_ms",
                                         std::to_string(settings.queue_admission_timeout_ms()));
                return true;
            }
            int timeout_ms = 0;
            if (!parse_int_value(value_expr, timeout_ms) ||
                !settings.set_queue_admission_timeout_ms(timeout_ms)) {
                out = make_pragma_error("Invalid idasql.queue_admission_timeout_ms value");
                return true;
            }
            out = make_pragma_result("queue_admission_timeout_ms",
                                     std::to_string(settings.queue_admission_timeout_ms()));
            return true;
        }

        if (key == "max_queue") {
            if (value_expr.empty()) {
                out = make_pragma_result("max_queue", std::to_string(settings.max_queue()));
                return true;
            }
            int queue_limit = 0;
            if (!parse_int_value(value_expr, queue_limit) || queue_limit < 0 ||
                !settings.set_max_queue(static_cast<size_t>(queue_limit))) {
                out = make_pragma_error("Invalid idasql.max_queue value");
                return true;
            }
            out = make_pragma_result("max_queue", std::to_string(settings.max_queue()));
            return true;
        }

        if (key == "hints_enabled") {
            if (value_expr.empty()) {
                out = make_pragma_result("hints_enabled", settings.hints_enabled() ? "1" : "0");
                return true;
            }
            bool enabled = false;
            if (!parse_bool_value(value_expr, enabled)) {
                out = make_pragma_error("Invalid idasql.hints_enabled value");
                return true;
            }
            settings.set_hints_enabled(enabled);
            out = make_pragma_result("hints_enabled", settings.hints_enabled() ? "1" : "0");
            return true;
        }

        if (key == "timeout_push") {
            if (value_expr.empty()) {
                out = make_pragma_error("idasql.timeout_push requires a timeout value");
                return true;
            }
            int timeout_ms = 0;
            if (!parse_int_value(value_expr, timeout_ms)) {
                out = make_pragma_error("Invalid idasql.timeout_push value");
                return true;
            }
            int effective_timeout = 0;
            if (!settings.timeout_push(timeout_ms, &effective_timeout)) {
                out = make_pragma_error("Invalid idasql.timeout_push value");
                return true;
            }
            out = make_pragma_result("query_timeout_ms", std::to_string(effective_timeout));
            return true;
        }

        if (key == "timeout_pop") {
            int effective_timeout = 0;
            if (!settings.timeout_pop(&effective_timeout)) {
                out = make_pragma_error("idasql.timeout_pop stack is empty");
                return true;
            }
            out = make_pragma_result("query_timeout_ms", std::to_string(effective_timeout));
            return true;
        }

        out = make_pragma_error("Unknown idasql pragma key");
        return true;
    }

    void append_query_hints(const std::string& sql, QueryResult& result) const {
        if (!runtime_settings().hints_enabled()) {
            return;
        }

        const std::string lower = to_lower_copy(sql);
        const bool touches_decompiler_table =
            lower.find("ctree_lvars") != std::string::npos ||
            lower.find("ctree_call_args") != std::string::npos ||
            lower.find("ctree ") != std::string::npos ||
            lower.find("ctree\n") != std::string::npos ||
            lower.find("pseudocode") != std::string::npos;
        const bool has_func_filter = lower.find("func_addr") != std::string::npos;

        auto add_warning_once = [&result](const std::string& warning) {
            for (const auto& existing : result.warnings) {
                if (existing == warning) {
                    return;
                }
            }
            result.warnings.push_back(warning);
        };

        if (touches_decompiler_table && !has_func_filter) {
            add_warning_once(
                "Decompiler tables are expensive without func_addr filtering; add WHERE func_addr = <addr> and LIMIT.");
        }
        if (result.timed_out && touches_decompiler_table) {
            add_warning_once(
                "Decompiler query timed out; resolve candidate functions first, then query ctree_* per function.");
        }
    }

    xsql::Database db_;
    std::string error_;

    // Table registries (prevent dangling virtual table pointers)
    std::unique_ptr<entities::TableRegistry> entities_;
    std::unique_ptr<metadata::MetadataRegistry> metadata_;
    std::unique_ptr<extended::ExtendedRegistry> extended_;
    std::unique_ptr<disassembly::DisassemblyRegistry> disassembly_;
    std::unique_ptr<types::TypesRegistry> types_;
    std::unique_ptr<debugger::DebuggerRegistry> debugger_;
    std::unique_ptr<decompiler::DecompilerRegistry> decompiler_;  // Runtime detection

    void init() {
        // db_ auto-opens :memory: via xsql::Database constructor

        // Register all virtual tables
        entities_ = std::make_unique<entities::TableRegistry>();
        entities_->register_all(db_);

        metadata_ = std::make_unique<metadata::MetadataRegistry>();
        metadata_->register_all(db_);

        extended_ = std::make_unique<extended::ExtendedRegistry>();
        extended_->register_all(db_);

        disassembly_ = std::make_unique<disassembly::DisassemblyRegistry>();
        disassembly_->register_all(db_);

        types_ = std::make_unique<types::TypesRegistry>();
        types_->register_all(db_);

        debugger_ = std::make_unique<debugger::DebuggerRegistry>();
        debugger_->register_all(db_);

        // Decompiler registry - register_all() handles runtime Hex-Rays detection
        // Must be registered before SQL functions so hexrays_available() is set
        decompiler_ = std::make_unique<decompiler::DecompilerRegistry>();
        decompiler_->register_all(db_);

        functions::register_sql_functions(db_);
        search::register_search_bytes(db_);
    }
};

// ============================================================================
// TIER 2: Session - Full IDA lifecycle management
// ============================================================================

/**
 * Session - Manages THE IDA database session
 *
 * Use this for standalone tools that need to open/close IDA databases.
 * Remember: IDA is singleton, so there's only ever ONE session.
 *
 * Example (CLI tool):
 *   idasql::Session session;
 *   if (!session.open("binary.i64")) {
 *       std::cerr << session.error() << std::endl;
 *       return 1;
 *   }
 *   auto result = session.query("SELECT * FROM funcs");
 *   session.close();
 */
class Session {
public:
    Session() = default;
    ~Session() { close(); }

    // Non-copyable, non-moveable (singleton semantics)
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&) = delete;
    Session& operator=(Session&&) = delete;

    /**
     * Open an IDA database
     * @param idb_path Path to .idb/.i64 file
     * @return true on success
     */
    bool open(const char* idb_path) {
        if (engine_) close();

        // Initialize IDA library
        int rc = init_library();
        if (rc != 0) {
            error_ = "Failed to initialize IDA library: " + std::to_string(rc);
            return false;
        }

        // Open the database
        rc = open_database(idb_path, true, nullptr);
        if (rc != 0) {
            error_ = "Failed to open database: " + std::string(idb_path);
            return false;
        }
        ida_opened_ = true;

        // Wait for auto-analysis
        auto_wait();

        // For new analysis (exe/dll/etc), build strings after auto-analysis completes
        // For existing databases (i64/idb), strings are already saved
        std::string path_lower = idb_path;
        std::transform(path_lower.begin(), path_lower.end(), path_lower.begin(), ::tolower);
        auto ends_with = [](const std::string& s, const std::string& suffix) {
            return s.size() >= suffix.size() &&
                   s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
        };
        bool is_new_analysis = !(
            ends_with(path_lower, ".i64") ||
            ends_with(path_lower, ".idb")
        );
        if (is_new_analysis) {
            // Configure and build string list with sensible defaults
            strwinsetup_t* opts = const_cast<strwinsetup_t*>(get_strlist_options());
            opts->strtypes.clear();
            opts->strtypes.push_back(STRTYPE_C);      // ASCII
            opts->strtypes.push_back(STRTYPE_C_16);   // UTF-16
            opts->minlen = 5;
            opts->only_7bit = 0;
            clear_strlist();  // Clear before building (like rebuild_strings)
            build_strlist();
        }

        // Create query engine
        engine_ = std::make_unique<QueryEngine>();
        if (!engine_->is_valid()) {
            error_ = engine_->error();
            close();
            return false;
        }

        return true;
    }

    /**
     * Close the session
     */
    void close() {
        engine_.reset();
        if (ida_opened_) {
            close_database(false);
            ida_opened_ = false;
        }
    }

    /**
     * Check if session is open
     */
    bool is_open() const { return engine_ && engine_->is_valid() && ida_opened_; }

    /**
     * Get last error
     */
    const std::string& error() const {
        return engine_ ? engine_->error() : error_;
    }

    // Delegate query methods to engine (with string overloads)
    QueryResult query(const std::string& sql) { return query(sql.c_str()); }
    QueryResult query(const char* sql) {
        if (!engine_) {
            QueryResult r;
            r.error = "Session not open";
            return r;
        }
        return engine_->query(sql);
    }

    xsql::Status exec(const char* sql) {
        return engine_ ? engine_->exec(sql) : xsql::Status::error;
    }

    bool execute(const std::string& sql) { return execute(sql.c_str()); }
    bool execute(const char* sql) {
        return engine_ ? engine_->execute(sql) : false;
    }

    bool execute_script(const std::string& script,
                        std::vector<xsql::StatementResult>& results,
                        std::string& error) {
        if (!engine_) {
            error = "Session not open";
            return false;
        }
        return engine_->execute_script(script, results, error);
    }

    bool export_tables(const std::vector<std::string>& tables,
                       const std::string& output_path,
                       std::string& error) {
        if (!engine_) {
            error = "Session not open";
            return false;
        }
        return engine_->export_tables(tables, output_path, error);
    }

    std::string scalar(const std::string& sql) { return scalar(sql.c_str()); }
    std::string scalar(const char* sql) {
        return engine_ ? engine_->scalar(sql) : "";
    }

    /**
     * Get query engine (for advanced use)
     */
    QueryEngine* engine() { return engine_.get(); }

    /**
     * Get database info
     */
    std::string info() const {
        if (!ida_opened_) return "Not opened";

        std::string s;
        s += "Processor: " + std::string(inf_get_procname().c_str()) + "\n";
        s += "Functions: " + std::to_string(get_func_qty()) + "\n";
        s += "Segments:  " + std::to_string(get_segm_qty()) + "\n";
        s += "Names:     " + std::to_string(get_nlist_size()) + "\n";
        return s;
    }

private:
    std::unique_ptr<QueryEngine> engine_;
    bool ida_opened_ = false;
    std::string error_;
};

// ============================================================================
// TIER 3: Free Functions - Quick one-liners
// ============================================================================

namespace detail {
    inline QueryEngine& global_engine() {
        static QueryEngine engine;
        return engine;
    }
}

/**
 * Quick query - uses global engine
 *
 * Example:
 *   auto funcs = idasql::query("SELECT name FROM funcs LIMIT 5");
 *   for (const auto& row : funcs) {
 *       msg("%s\n", row[0].c_str());
 *   }
 */
inline QueryResult query(const char* sql) {
    return detail::global_engine().query(sql);
}

/**
 * Quick exec (no result rows)
 */
inline xsql::Status exec(const char* sql) {
    return detail::global_engine().exec(sql);
}

/**
 * Quick execute (no results)
 */
inline bool execute(const char* sql) {
    return detail::global_engine().execute(sql);
}

/**
 * Quick scalar query
 */
inline std::string scalar(const char* sql) {
    return detail::global_engine().scalar(sql);
}

// ============================================================================
// Backwards Compatibility Alias
// ============================================================================

// For existing code using idasql::Database
using Database = Session;

} // namespace idasql
