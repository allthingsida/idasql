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
 *   - idasql::query(), idasql::exec()
 *   - Use global engine, lazily initialized
 *
 * IMPORTANT: IDA SDK is a singleton. Only ONE database can be open.
 * The Session class doesn't create "a database" - it manages THE database.
 */

#pragma once

#include <idasql/platform.hpp>

#include <sqlite3.h>
#include <xsql/database.hpp>
#include <xsql/json.hpp>
#include <string>
#include <vector>
#include <functional>
#include <memory>

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
    bool success = false;

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

        struct QueryData {
            QueryResult* result;
            bool first_row;
        } qd = { &result, true };

        auto callback = [](void* data, int argc, char** argv, char** cols) -> int {
            auto* qd = static_cast<QueryData*>(data);

            if (qd->first_row) {
                for (int i = 0; i < argc; i++) {
                    qd->result->columns.push_back(cols[i] ? cols[i] : "");
                }
                qd->first_row = false;
            }

            Row row;
            row.values.reserve(argc);
            for (int i = 0; i < argc; i++) {
                row.values.push_back(argv[i] ? argv[i] : "NULL");
            }
            qd->result->rows.push_back(std::move(row));

            return 0;
        };

        int rc = exec(sql, callback, &qd);
        result.success = (rc == SQLITE_OK);
        if (!result.success && result.error.empty()) {
            result.error = sqlite3_errmsg(db_.handle());
        }

        return result;
    }

    /**
     * Execute SQL with callback (for streaming large results)
     */
    int exec(const char* sql, sqlite3_callback callback, void* data) {
        if (!db_.is_open()) {
            error_ = "QueryEngine not initialized";
            return SQLITE_ERROR;
        }

        char* err_msg = nullptr;
        int rc = sqlite3_exec(db_.handle(), sql, callback, data, &err_msg);
        if (err_msg) {
            error_ = err_msg;
            sqlite3_free(err_msg);
        }
        return rc;
    }

    /**
     * Execute SQL, ignore results (for INSERT/UPDATE/DELETE)
     */
    bool execute(const char* sql) {
        return exec(sql, nullptr, nullptr) == SQLITE_OK;
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
     * Get raw SQLite handle (for advanced use)
     */
    sqlite3* handle() { return db_.handle(); }

private:
    xsql::Database db_;
    std::string error_;

    // Table registries (prevent dangling virtual table pointers)
    std::unique_ptr<entities::TableRegistry> entities_;
    std::unique_ptr<metadata::MetadataRegistry> metadata_;
    std::unique_ptr<extended::ExtendedRegistry> extended_;
    std::unique_ptr<disassembly::DisassemblyRegistry> disassembly_;
    std::unique_ptr<types::TypesRegistry> types_;
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

        functions::register_sql_functions(db_);
        search::register_search_bytes(db_);

        // Decompiler registry - register_all() handles runtime Hex-Rays detection
        decompiler_ = std::make_unique<decompiler::DecompilerRegistry>();
        decompiler_->register_all(db_);
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

    int exec(const char* sql, sqlite3_callback cb, void* data) {
        return engine_ ? engine_->exec(sql, cb, data) : SQLITE_ERROR;
    }

    bool execute(const std::string& sql) { return execute(sql.c_str()); }
    bool execute(const char* sql) {
        return engine_ ? engine_->execute(sql) : false;
    }

    std::string scalar(const std::string& sql) { return scalar(sql.c_str()); }
    std::string scalar(const char* sql) {
        return engine_ ? engine_->scalar(sql) : "";
    }

    /**
     * Get raw SQLite handle
     */
    sqlite3* handle() { return engine_ ? engine_->handle() : nullptr; }

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
 * Quick exec with callback
 */
inline int exec(const char* sql, sqlite3_callback cb, void* data) {
    return detail::global_engine().exec(sql, cb, data);
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
