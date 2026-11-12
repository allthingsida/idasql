// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <xsql/query_script.hpp>

#include <string>
#include <utility>

namespace idasql {

inline bool is_valid_query_format(const std::string& format) {
    return format == "json" || format == "text" ||
           format == "csv" || format == "tsv";
}

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

}
