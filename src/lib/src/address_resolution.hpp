// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0

#pragma once

#include <idasql/platform.hpp>

#include <xsql/functions.hpp>

#include "ida_headers.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace idasql {

// Private SQL-address coercion shared by scalar functions and writable tables.
// Accepts integer EAs, numeric strings, and IDA symbol names where appropriate.
bool parse_numeric_ea_text(const std::string& text, ea_t& out_ea);

bool resolve_address_value(
    xsql::FunctionArg arg,
    const char* arg_name,
    ea_t& out_ea,
    std::string* error = nullptr);

// An address-key constraint value on a table whose key also takes the
// documented spellings (numeric strings, '0x...' hex, symbol names), e.g.
// applied_types.addr. The plan is omit=1, so a value no address can equal is
// "no match" (out empty, returns true), never a silent truncation: NULL, a
// blob, a non-integral real. An integer, an integral real, or text SQLite's
// INTEGER affinity makes an integer ('4198400', ' 4198400 ', '4198400.0')
// is that address; other text is parsed as a hex/numeric string or resolved
// as a symbol name, and an unresolvable name is an error (returns false).
bool resolve_address_key(
    xsql::FunctionArg arg,
    const char* arg_name,
    std::optional<ea_t>& out_ea,
    std::string* error = nullptr);

bool resolve_address_arg(
    xsql::FunctionContext& ctx,
    xsql::FunctionArg* argv,
    int arg_index,
    const char* arg_name,
    ea_t& out_ea);

// An integer value, exact like a native INTEGER comparison (xsql::exact_int64:
// 144, '144' and 144.0 are 144; '0x90', 144.5, NULL and a blob are refused,
// never truncated to 0 or saturated), within [lo, hi]. On failure *error says why.
std::optional<int64_t> resolve_int_value(
    xsql::FunctionArg arg,
    const char* arg_name,
    int64_t lo,
    int64_t hi,
    std::string* error = nullptr);

// resolve_int_value for a scalar function argument; reports the error on ctx.
bool resolve_int_arg(
    xsql::FunctionContext& ctx,
    xsql::FunctionArg* argv,
    int arg_index,
    const char* arg_name,
    int64_t lo,
    int64_t hi,
    int64_t& out);

// Table writes (INSERT/UPDATE values): resolve_address_value / resolve_int_value
// that set the vtab error "<table>.<column>: <reason>" on failure.
bool write_address(xsql::FunctionArg arg, const char* table, const char* column, ea_t& out_ea);
std::optional<int64_t> write_int(
    xsql::FunctionArg arg,
    const char* table,
    const char* column,
    int64_t lo,
    int64_t hi);

} // namespace idasql
