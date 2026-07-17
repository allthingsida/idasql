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

#include <xsql/query_script.hpp>

#include <functional>
#include <string>

namespace idasql {

using SqlExecutor = std::function<QueryResult(const std::string& sql)>;

inline xsql::ScriptResult run_sql_script(const std::string& sql,
                                         const SqlExecutor& exec,
                                         const xsql::ScriptOptions& options = {})
{
    return xsql::run_script(sql, options,
        [&exec](const std::string& stmt, xsql::ScriptStatementResult& out) {
            QueryResult r = exec(stmt);

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

// Convenience for the common case: executor wraps Database::query.
inline xsql::ScriptResult run_sql_script(Database& db,
                                         const std::string& sql,
                                         const xsql::ScriptOptions& options = {})
{
    return run_sql_script(
        sql,
        [&db](const std::string& stmt) { return db.query(stmt); },
        options);
}

} // namespace idasql
