// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_dbg.hpp - Debugger-related IDA entities as virtual tables
 *
 * Tables: breakpoints
 */

#pragma once

#include <idasql/platform.hpp>

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include "ida_headers.hpp"

namespace idasql {
namespace debugger {

const char* bpt_type_name(bpttype_t type);
const char* bpt_loc_type_name(int loc_type);
std::string safe_bpt_group(const bpt_t& bpt);
std::string safe_bpt_loc_path(const bpt_t& bpt);
std::string safe_bpt_loc_symbol(const bpt_t& bpt);

VTableDef define_breakpoints();

struct DebuggerRegistry {
    VTableDef breakpoints;

    DebuggerRegistry();
    void register_all(xsql::Database& db);
};

} // namespace debugger
} // namespace idasql
