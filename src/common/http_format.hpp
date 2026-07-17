// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// idasql HTTP ?format= response rendering.
//
// Re-renders a canonical run_script envelope (the JSON string returned by the
// main-thread query queue) into text/csv/tsv for direct terminal/pipe use, or
// passes the JSON through unchanged. json_to_script_result() is libxsql's
// inverse parser (v1.0.10); agents should consume the default JSON.
//
// Extracted from the CLI /query handler so the format logic is reusable
// without an idalib session.

#pragma once

#include <xsql/query_script.hpp>

#include <string>
#include <utility>

namespace idasql {

// True iff `format` is one this renderer understands. The CLI /query handler
// uses this to reject an unknown ?format with 400 rather than silently emitting
// JSON (mirrors libxsql's http_query_server strict-format handling).
inline bool is_valid_query_format(const std::string& format) {
    return format == "json" || format == "text" ||
           format == "csv" || format == "tsv";
}

// Returns {body, content_type} for the given canonical-envelope JSON and the
// HTTP `format` query-string value. text/csv/tsv re-render via the inverse
// parser; any other value (including the default "json") returns the envelope
// unchanged as application/json.
//
// Robustness: a request-level failure envelope ({"success":false,"error":"..."}
// with no results[]) round-trips through json_to_script_result, which surfaces
// the top-level "error" as parse_error (libxsql v1.0.11) so the delimited
// formatters emit the message rather than an empty body. Any unexpected throw
// while rendering degrades to a one-line error in the requested content-type
// instead of propagating as an httplib 500.
inline std::pair<std::string, std::string>
render_query_response(const std::string& envelope_json, const std::string& format) {
    try {
        if (format == "text")
            return { xsql::script_result_to_text(xsql::json_to_script_result(envelope_json)),
                     "text/plain" };
        if (format == "csv")
            return { xsql::script_result_to_csv(xsql::json_to_script_result(envelope_json)),
                     "text/csv" };
        if (format == "tsv")
            return { xsql::script_result_to_tsv(xsql::json_to_script_result(envelope_json)),
                     "text/tab-separated-values" };
    } catch (const std::exception& e) {
        const std::string msg = std::string("error rendering ?format=") + format + ": " + e.what();
        if (format == "csv")  return { "error\n\"" + msg + "\"\n", "text/csv" };
        if (format == "tsv")  return { "error\n" + msg + "\n", "text/tab-separated-values" };
        return { msg + "\n", "text/plain" };
    }
    return { envelope_json, "application/json" };
}

} // namespace idasql
