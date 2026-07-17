// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0

#include "address_resolution.hpp"

#include <idasql/string_utils.hpp>

#include <sqlite3.h>

#include <cerrno>
#include <cstdlib>
#include <limits>

namespace idasql {

bool parse_numeric_ea_text(const std::string& text, ea_t& out_ea) {
    const std::string token = trim_copy(text);
    if (token.empty()) {
        return false;
    }
    // strtoull silently WRAPS a leading '-' (e.g. "-1" -> 0xFFFF...FFFF) without
    // setting ERANGE, which would masquerade as a valid high address. A negative
    // address is never valid — reject it up front.
    if (token[0] == '-') {
        return false;
    }

    errno = 0;
    char* end_ptr = nullptr;
    const unsigned long long value = strtoull(token.c_str(), &end_ptr, 0);
    if (errno == ERANGE || end_ptr == token.c_str() || end_ptr == nullptr || *end_ptr != '\0') {
        return false;
    }
    const unsigned long long max_ea = static_cast<unsigned long long>((std::numeric_limits<ea_t>::max)());
    if (value > max_ea) {
        return false;
    }

    out_ea = static_cast<ea_t>(value);
    return true;
}

bool resolve_address_value(
        xsql::FunctionArg arg,
        const char* arg_name,
        ea_t& out_ea,
        std::string* error) {
    out_ea = BADADDR;
    const char* name = (arg_name && *arg_name) ? arg_name : "addr";
    const int sqlite_type = arg.type();

    auto set_error = [error](std::string message) {
        if (error) {
            *error = std::move(message);
        }
    };

    if (sqlite_type == SQLITE_INTEGER) {
        out_ea = static_cast<ea_t>(arg.as_int64());
        return true;
    }

    if (sqlite_type == SQLITE_FLOAT) {
        set_error(std::string(name) + " must be an integer, numeric string, or symbol name");
        return false;
    }

    if (sqlite_type == SQLITE_TEXT) {
        const std::string raw = arg.as_text();
        const std::string text = trim_copy(raw);
        if (text.empty()) {
            set_error(std::string(name) + " must not be empty");
            return false;
        }

        ea_t parsed = BADADDR;
        if (parse_numeric_ea_text(text, parsed)) {
            out_ea = parsed;
            return true;
        }

        const ea_t resolved = get_name_ea(BADADDR, text.c_str());
        if (resolved != BADADDR) {
            out_ea = resolved;
            return true;
        }

        set_error("Could not resolve name to address: " + text);
        return false;
    }

    if (sqlite_type == SQLITE_NULL) {
        set_error(std::string(name) + " must not be NULL");
        return false;
    }

    set_error(std::string(name) + " must be an integer, numeric string, or symbol name");
    return false;
}

bool resolve_address_arg(
        xsql::FunctionContext& ctx,
        xsql::FunctionArg* argv,
        int arg_index,
        const char* arg_name,
        ea_t& out_ea) {
    if (arg_index < 0) {
        ctx.result_error("Internal error: invalid address argument index");
        out_ea = BADADDR;
        return false;
    }

    std::string error;
    if (!resolve_address_value(argv[arg_index], arg_name, out_ea, &error)) {
        ctx.result_error(error);
        return false;
    }
    return true;
}

} // namespace idasql
