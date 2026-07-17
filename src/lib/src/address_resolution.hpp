// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0

#pragma once

#include <idasql/platform.hpp>

#include <xsql/functions.hpp>

#include "ida_headers.hpp"

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

bool resolve_address_arg(
    xsql::FunctionContext& ctx,
    xsql::FunctionArg* argv,
    int arg_index,
    const char* arg_name,
    ea_t& out_ea);

} // namespace idasql
