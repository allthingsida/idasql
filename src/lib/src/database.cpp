// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

#include <idasql/database.hpp>

#include <idasql/platform.hpp>

#include <cctype>
#include <limits>
#include <algorithm>

#include "ida_headers.hpp"

// Private headers for registry implementations
#include "entities.hpp"
#include "entities_ext.hpp"
#include "entities_dbg.hpp"
#include "entities_search.hpp"
#include "entities_types.hpp"
#include "functions.hpp"
#include "decompiler.hpp"
#include "disassembly.hpp"
#include "search_bytes.hpp"
#include "metadata.hpp"

namespace idasql {

// ============================================================================
// QueryEngine
// ============================================================================

QueryEngine::QueryEngine() {
    init();
}

QueryEngine::~QueryEngine() = default;

QueryResult QueryEngine::query(const char* sql) {
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

xsql::Status QueryEngine::exec(const char* sql) {
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

bool QueryEngine::execute(const char* sql) {
    return xsql::is_ok(exec(sql));
}

bool QueryEngine::execute_script(const std::string& script,
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

bool QueryEngine::export_tables(const std::vector<std::string>& tables,
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

std::string QueryEngine::scalar(const char* sql) {
    auto result = query(sql);
    if (result.success && !result.empty()) {
        return result.rows[0].values[0];
    }
    return "";
}

std::string QueryEngine::trim_copy(const std::string& s) {
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

std::string QueryEngine::to_lower_copy(std::string value) {
    for (char& c : value) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return value;
}

std::string QueryEngine::strip_optional_quotes(const std::string& s) {
    if (s.size() >= 2) {
        char a = s.front();
        char b = s.back();
        if ((a == '\'' && b == '\'') || (a == '"' && b == '"')) {
            return s.substr(1, s.size() - 2);
        }
    }
    return s;
}

bool QueryEngine::parse_int_value(const std::string& text, int& value) {
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

bool QueryEngine::parse_bool_value(const std::string& text, bool& value) {
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

QueryResult QueryEngine::make_pragma_result(const std::string& key, const std::string& value) {
    QueryResult result;
    result.columns = {"name", "value"};
    Row row;
    row.values = {key, value};
    result.rows.push_back(std::move(row));
    result.success = true;
    return result;
}

QueryResult QueryEngine::make_pragma_error(const std::string& error) {
    QueryResult result;
    result.success = false;
    result.error = error;
    return result;
}

bool QueryEngine::handle_runtime_pragma(const char* sql, QueryResult& out) {
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

    if (key == "enable_idapython") {
        if (value_expr.empty()) {
            out = make_pragma_result("enable_idapython", settings.enable_idapython() ? "1" : "0");
            return true;
        }
        bool enabled = false;
        if (!parse_bool_value(value_expr, enabled)) {
            out = make_pragma_error("Invalid idasql.enable_idapython value");
            return true;
        }
        settings.set_enable_idapython(enabled);
        out = make_pragma_result("enable_idapython", settings.enable_idapython() ? "1" : "0");
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

void QueryEngine::append_query_hints(const std::string& sql, QueryResult& result) const {
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

void QueryEngine::init() {
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

// ============================================================================
// Session
// ============================================================================

Session::~Session() { close(); }

bool Session::open(const char* idb_path) {
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

void Session::close() {
    engine_.reset();
    if (ida_opened_) {
        close_database(false);
        ida_opened_ = false;
    }
}

QueryResult Session::query(const char* sql) {
    if (!engine_) {
        QueryResult r;
        r.error = "Session not open";
        return r;
    }
    return engine_->query(sql);
}

xsql::Status Session::exec(const char* sql) {
    return engine_ ? engine_->exec(sql) : xsql::Status::error;
}

bool Session::execute(const char* sql) {
    return engine_ ? engine_->execute(sql) : false;
}

bool Session::execute_script(const std::string& script,
                              std::vector<xsql::StatementResult>& results,
                              std::string& error) {
    if (!engine_) {
        error = "Session not open";
        return false;
    }
    return engine_->execute_script(script, results, error);
}

bool Session::export_tables(const std::vector<std::string>& tables,
                             const std::string& output_path,
                             std::string& error) {
    if (!engine_) {
        error = "Session not open";
        return false;
    }
    return engine_->export_tables(tables, output_path, error);
}

std::string Session::scalar(const char* sql) {
    return engine_ ? engine_->scalar(sql) : "";
}

std::string Session::info() const {
    if (!ida_opened_) return "Not opened";

    std::string s;
    s += "Processor: " + std::string(inf_get_procname().c_str()) + "\n";
    s += "Functions: " + std::to_string(get_func_qty()) + "\n";
    s += "Segments:  " + std::to_string(get_segm_qty()) + "\n";
    s += "Names:     " + std::to_string(get_nlist_size()) + "\n";
    return s;
}

// ============================================================================
// TIER 3: Free Functions - Quick one-liners
// ============================================================================

namespace detail {
    QueryEngine& global_engine() {
        static QueryEngine engine;
        return engine;
    }
}

QueryResult query(const char* sql) {
    return detail::global_engine().query(sql);
}

xsql::Status exec(const char* sql) {
    return detail::global_engine().exec(sql);
}

bool execute(const char* sql) {
    return detail::global_engine().execute(sql);
}

std::string scalar(const char* sql) {
    return detail::global_engine().scalar(sql);
}

} // namespace idasql
