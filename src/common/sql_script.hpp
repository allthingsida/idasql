// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <idasql/database.hpp>
#include <idasql/runtime_settings.hpp>

#include <xsql/query_script.hpp>

#include <functional>
#include <string>

namespace idasql {

using SqlExecutor = std::function<QueryResult(
    const std::string& sql, const xsql::QueryOptions& options)>;

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
                out.cell_null.push_back(row.nulls);
            }
            out.elapsed_ms = static_cast<double>(r.elapsed_ms);
            out.success = r.success;
            out.error = r.error;
            out.timed_out = r.timed_out;
            out.partial = r.partial;
            out.warnings = r.warnings;
        });
}

inline xsql::ScriptResult run_sql_script(const std::string& sql, const SqlExecutor& exec) {
    xsql::ScriptOptions options;
    options.timeout_ms = runtime_settings().query_timeout_ms();
    return run_sql_script(sql, exec, options);
}

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

inline xsql::ScriptResult run_sql_script(Database& db, const std::string& sql) {
    xsql::ScriptOptions options;
    options.timeout_ms = runtime_settings().query_timeout_ms();
    return run_sql_script(db, sql, options);
}

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

}
