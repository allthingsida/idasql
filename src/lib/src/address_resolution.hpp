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

bool parse_numeric_ea_text(const std::string& text, ea_t& out_ea);

bool resolve_address_value(
    xsql::FunctionArg arg,
    const char* arg_name,
    ea_t& out_ea,
    std::string* error = nullptr);

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

std::optional<int64_t> resolve_int_value(
    xsql::FunctionArg arg,
    const char* arg_name,
    int64_t lo,
    int64_t hi,
    std::string* error = nullptr);

bool resolve_int_arg(
    xsql::FunctionContext& ctx,
    xsql::FunctionArg* argv,
    int arg_index,
    const char* arg_name,
    int64_t lo,
    int64_t hi,
    int64_t& out);

bool write_address(xsql::FunctionArg arg, const char* table, const char* column, ea_t& out_ea);
std::optional<int64_t> write_int(
    xsql::FunctionArg arg,
    const char* table,
    const char* column,
    int64_t lo,
    int64_t hi);

}
