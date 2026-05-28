// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
            for (const auto& row : r.rows) {
                out.rows.push_back(row.values);
            }
            out.elapsed_ms = static_cast<double>(r.elapsed_ms);
            out.success = r.success;
            out.error = r.error;
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
