// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0

#include "address_resolution.hpp"

#include <idasql/string_utils.hpp>
#include <xsql/vtable.hpp>

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

bool resolve_address_key(
        xsql::FunctionArg arg,
        const char* arg_name,
        std::optional<ea_t>& out_ea,
        std::string* error) {
    out_ea.reset();
    if (const std::optional<int64_t> key = xsql::exact_int64(arg)) {
        out_ea = static_cast<ea_t>(static_cast<uint64_t>(*key));
        return true;
    }
    if (arg.type() != SQLITE_TEXT) {
        return true;  // NULL, a blob or a non-integral real equals no address
    }
    ea_t ea = BADADDR;
    if (!resolve_address_value(arg, arg_name, ea, error)) {
        return false;
    }
    out_ea = ea;
    return true;
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

std::optional<int64_t> resolve_int_value(
        xsql::FunctionArg arg,
        const char* arg_name,
        int64_t lo,
        int64_t hi,
        std::string* error) {
    const std::string name = (arg_name && *arg_name) ? arg_name : "value";
    auto fail = [&](const std::string& why) -> std::optional<int64_t> {
        if (error) *error = name + ": " + why;
        return std::nullopt;
    };
    if (arg.is_null()) return fail("must not be NULL");
    std::optional<int64_t> v;
    if (arg.type() != SQLITE_BLOB) v = xsql::exact_int64(arg);
    if (!v) {
        return fail(std::string("expected an integer (e.g. 16 or 0x10), got ") +
                    (arg.type() == SQLITE_BLOB    ? "a blob"
                     : arg.type() == SQLITE_FLOAT ? "a non-integral or out-of-range real"
                                                  : "non-integer text"));
    }
    if (*v < lo || *v > hi) {
        return fail("out of range (" + std::to_string(lo) + ".." + std::to_string(hi) +
                    "): " + std::to_string(*v));
    }
    return v;
}

bool resolve_int_arg(
        xsql::FunctionContext& ctx,
        xsql::FunctionArg* argv,
        int arg_index,
        const char* arg_name,
        int64_t lo,
        int64_t hi,
        int64_t& out) {
    std::string error;
    const std::optional<int64_t> v = resolve_int_value(argv[arg_index], arg_name, lo, hi, &error);
    if (!v) {
        ctx.result_error(error);
        return false;
    }
    out = *v;
    return true;
}

bool write_address(xsql::FunctionArg arg, const char* table, const char* column, ea_t& out_ea) {
    const std::string name = std::string(table) + "." + column;
    std::string error;
    if (!resolve_address_value(arg, name.c_str(), out_ea, &error)) {
        // resolve_address_value names the column in most messages, not all.
        xsql::set_vtab_error(error.rfind(name, 0) == 0 ? error : name + ": " + error);
        return false;
    }
    return true;
}

std::optional<int64_t> write_int(
        xsql::FunctionArg arg,
        const char* table,
        const char* column,
        int64_t lo,
        int64_t hi) {
    std::string error;
    const std::optional<int64_t> v =
        resolve_int_value(arg, (std::string(table) + "." + column).c_str(), lo, hi, &error);
    if (!v) xsql::set_vtab_error(error);
    return v;
}

} // namespace idasql
