// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
 * TIER 2: Session (for pre-initialized standalone tools)
 *   - Database lifecycle only: open_database + close
 *   - Caller must initialize the IDA runtime before Session::open()
 *   - Use for tools like idasql.exe after one-time init_library()
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
#include <idasql/string_utils.hpp>

#include <xsql/database.hpp>
#include <xsql/json.hpp>
#include <xsql/script.hpp>
#include <idasql/runtime_settings.hpp>
#include <idasql/fwd.hpp>
#include <string>
#include <vector>
#include <memory>

#include <idasql/platform_undef.hpp>

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
    QueryEngine();
    ~QueryEngine();

    // Moveable but not copyable
    QueryEngine(QueryEngine&&) noexcept;
    QueryEngine& operator=(QueryEngine&&) noexcept;

    QueryEngine(const QueryEngine&) = delete;
    QueryEngine& operator=(const QueryEngine&) = delete;

    /**
     * Execute SQL and return results
     */
    QueryResult query(const std::string& sql) { return query(sql.c_str()); }
    QueryResult query(const char* sql);

    /**
     * Execute SQL, ignoring rows
     */
    xsql::Status exec(const char* sql);

    /**
     * Execute SQL, ignore results (for INSERT/UPDATE/DELETE)
     */
    bool execute(const char* sql);

    /**
     * Execute multi-statement SQL script and collect statement results.
     */
    bool execute_script(const std::string& script,
                        std::vector<xsql::StatementResult>& results,
                        std::string& error);

    /**
     * Export tables to a SQL file.
     */
    bool export_tables(const std::vector<std::string>& tables,
                       const std::string& output_path,
                       std::string& error);

    /**
     * Get single value (first column of first row)
     */
    std::string scalar(const std::string& sql) { return scalar(sql.c_str()); }
    std::string scalar(const char* sql);

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
    static std::string to_lower_copy(std::string value);
    static std::string strip_optional_quotes(const std::string& s);
    static bool parse_int_value(const std::string& text, int& value);
    static bool parse_bool_value(const std::string& text, bool& value);
    static QueryResult make_pragma_result(const std::string& key, const std::string& value);
    static QueryResult make_pragma_error(const std::string& error);
    bool handle_runtime_pragma(const char* sql, QueryResult& out);
    void append_query_hints(const std::string& sql, QueryResult& result) const;

    xsql::Database db_;
    std::string error_;

    // Table registries (prevent dangling virtual table pointers)
    std::unique_ptr<entities::TableRegistry> entities_;
    std::unique_ptr<metadata::MetadataRegistry> metadata_;
    std::unique_ptr<extended::ExtendedRegistry> extended_;
    std::unique_ptr<disassembly::DisassemblyRegistry> disassembly_;
    std::unique_ptr<types::TypesRegistry> types_;
    std::unique_ptr<debugger::DebuggerRegistry> debugger_;
    std::unique_ptr<decompiler::DecompilerRegistry> decompiler_;

    void init();
};

// ============================================================================
// TIER 2: Session - Database lifecycle management
// ============================================================================

/**
 * Session - Manages THE IDA database session after runtime initialization
 *
 * Use this for standalone tools that need to open/close IDA databases
 * after calling init_library() once for the process.
 * Remember: IDA is singleton, so there's only ever ONE session.
 *
 * Example (CLI tool):
 *   if (init_library() != 0) {
 *       std::cerr << "init failed" << std::endl;
 *       return 1;
 *   }
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
    ~Session();

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
    bool open(const char* idb_path);

    /**
     * Close the session
     */
    void close();

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
    QueryResult query(const char* sql);

    xsql::Status exec(const char* sql);

    bool execute(const std::string& sql) { return execute(sql.c_str()); }
    bool execute(const char* sql);

    bool execute_script(const std::string& script,
                        std::vector<xsql::StatementResult>& results,
                        std::string& error);

    bool export_tables(const std::vector<std::string>& tables,
                       const std::string& output_path,
                       std::string& error);

    std::string scalar(const std::string& sql) { return scalar(sql.c_str()); }
    std::string scalar(const char* sql);

    /**
     * Get query engine (for advanced use)
     */
    QueryEngine* engine() { return engine_.get(); }

    /**
     * Get database info
     */
    std::string info() const;

private:
    std::unique_ptr<QueryEngine> engine_;
    bool ida_opened_ = false;
    std::string error_;
};

// ============================================================================
// TIER 3: Free Functions - Quick one-liners
// ============================================================================

namespace detail {
    QueryEngine& global_engine();
}

/**
 * Quick query - uses global engine
 */
QueryResult query(const char* sql);

/**
 * Quick exec (no result rows)
 */
xsql::Status exec(const char* sql);

/**
 * Quick execute (no results)
 */
bool execute(const char* sql);

/**
 * Quick scalar query
 */
std::string scalar(const char* sql);

// ============================================================================
// Backwards Compatibility Alias
// ============================================================================

// For existing code using idasql::Database
using Database = Session;

} // namespace idasql
