// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

/**
 * query_script.hpp - Shared single-query vs multi-statement execution helpers.
 */

#include <idasql/database.hpp>
#include <xsql/script.hpp>

#include <functional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace idasql {

struct QueryScriptResult {
    bool success = false;
    bool multi_statement = false;
    std::vector<std::string> statements;
    std::vector<QueryResult> results;
    std::string error;
    size_t error_statement_index = 0;
};

using QueryExecutor = std::function<QueryResult(const std::string& sql)>;

inline QueryScriptResult execute_query_or_script(const std::string& sql,
                                                 const QueryExecutor& executor) {
    QueryScriptResult script_result;
    std::string collect_error;
    if (!xsql::collect_statements(sql, script_result.statements, collect_error)) {
        script_result.error = collect_error;
        return script_result;
    }

    script_result.multi_statement = script_result.statements.size() > 1;

    if (!script_result.multi_statement) {
        QueryResult result = executor(sql);
        script_result.success = result.success;
        script_result.error = result.error;
        script_result.results.push_back(std::move(result));
        return script_result;
    }

    script_result.results.reserve(script_result.statements.size());
    for (size_t i = 0; i < script_result.statements.size(); ++i) {
        QueryResult result = executor(script_result.statements[i]);
        if (!result.success) {
            script_result.error = result.error;
            script_result.error_statement_index = i;
            script_result.results.push_back(std::move(result));
            return script_result;
        }
        script_result.results.push_back(std::move(result));
    }

    script_result.success = true;
    script_result.error.clear();
    return script_result;
}

inline bool has_result_columns(const QueryResult& result) {
    return !result.columns.empty();
}

inline std::string query_script_result_to_text(const QueryScriptResult& script_result) {
    if (!script_result.success) {
        return script_result.error;
    }

    if (!script_result.multi_statement) {
        return script_result.results.empty() ? std::string() : script_result.results[0].to_string();
    }

    std::ostringstream out;
    bool wrote_result = false;
    for (const auto& result : script_result.results) {
        if (!has_result_columns(result)) {
            continue;
        }
        if (wrote_result) {
            out << "\n\n";
        }
        out << result.to_string();
        wrote_result = true;
    }

    if (!wrote_result) {
        return "(0 rows)";
    }
    return out.str();
}

} // namespace idasql
