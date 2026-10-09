// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

/**
 * sql_script.hpp - idasql adapter over xsql::run_script.
 *
 * idasql callers (CLI, HTTP, MCP, plugin) all dispatch SQL through this
 * single helper. The output is xsql::ScriptResult — the canonical
 * always-array envelope — formatted via xsql::script_result_to_json
 * or xsql::script_result_to_text. No idasql-side multi-statement glue.
 */

#include <idasql/database.hpp>
#include <idasql/runtime_settings.hpp>

#include <xsql/query_script.hpp>

#include <functional>
#include <string>

namespace idasql {

using SqlExecutor = std::function<QueryResult(
    const std::string& sql, const xsql::QueryOptions& options)>;

// A request's own deadline (X-XSQL-Timeout, which libxsql parses into timeout_ms)
// wins; 0 means "not set" there, so the live query_timeout_ms applies.
inline xsql::ScriptOptions with_default_timeout(xsql::ScriptOptions options) {
    if (options.timeout_ms <= 0) options.timeout_ms = runtime_settings().query_timeout_ms();
    return options;
}

inline xsql::ScriptResult run_sql_script(const std::string& sql,
                                         const SqlExecutor& exec,
                                         const xsql::ScriptOptions& options)
{
    return xsql::run_script(sql, options,
        [&exec, &options](const std::string& stmt, xsql::ScriptStatementResult& out) {
            xsql::QueryOptions query_options;
            query_options.timeout_ms = options.timeout_ms;
            query_options.should_cancel = options.should_cancel;
            QueryResult r = exec(stmt, query_options);

            out.columns = r.columns;
            out.rows.reserve(r.rows.size());
            out.cell_null.reserve(r.rows.size());
            for (const auto& row : r.rows) {
                out.rows.push_back(row.values);
                // Thread the per-cell SQL-NULL mask so script_result_to_json emits
                // JSON `null` (and csv/tsv an empty field) for a real NULL instead
                // of rendering it as "". `row.nulls` is char-based, exactly what
                // ScriptStatementResult::cell_null wants; an empty mask falls back
                // to the legacy "NULL"-sentinel path in is_null_cell().
                out.cell_null.push_back(row.nulls);
            }
            out.elapsed_ms = static_cast<double>(r.elapsed_ms);
            out.success = r.success;
            out.error = r.error;
            // Thread the timeout/partial/warning signals so a timed-out partial
            // SELECT is distinguishable from a complete one on every machine-facing
            // surface (json/csv/tsv/MCP/-q), not just the interactive REPL.
            out.timed_out = r.timed_out;
            out.partial = r.partial;
            out.warnings = r.warnings;
        });
}

// Omitting ScriptOptions inherits the live product default even for callers
// that provide their own executor. Passing ScriptOptions explicitly remains
// exact: timeout_ms == 0 means no deadline.
inline xsql::ScriptResult run_sql_script(const std::string& sql, const SqlExecutor& exec) {
    xsql::ScriptOptions options;
    options.timeout_ms = runtime_settings().query_timeout_ms();
    return run_sql_script(sql, exec, options);
}

// Convenience for the common case: executor wraps Database::query.
inline xsql::ScriptResult run_sql_script(Database& db,
                                         const std::string& sql,
                                         const xsql::ScriptOptions& options)
{
    return run_sql_script(
        sql,
        [&db](const std::string& stmt, const xsql::QueryOptions& query_options) {
            return db.query(stmt, query_options);
        },
        options);
}

// Omitting ScriptOptions inherits the live product default. The overload above
// remains exact: an explicitly supplied timeout_ms == 0 means no deadline.
inline xsql::ScriptResult run_sql_script(Database& db, const std::string& sql) {
    xsql::ScriptOptions options;
    options.timeout_ms = runtime_settings().query_timeout_ms();
    return run_sql_script(db, sql, options);
}

// QueryEngine is the lower-level database facade used by plugins and embedded
// callers. Keep the same omitted-vs-explicit timeout contract as Session.
inline xsql::ScriptResult run_sql_script(QueryEngine& engine, const std::string& sql,
                                         const xsql::ScriptOptions& options) {
    return run_sql_script(
        sql,
        [&engine](const std::string& stmt, const xsql::QueryOptions& query_options) {
            return engine.query(stmt, query_options);
        },
        options);
}

inline xsql::ScriptResult run_sql_script(QueryEngine& engine, const std::string& sql) {
    xsql::ScriptOptions options;
    options.timeout_ms = runtime_settings().query_timeout_ms();
    return run_sql_script(engine, sql, options);
}

} // namespace idasql
