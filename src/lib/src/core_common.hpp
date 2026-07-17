// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_common.hpp - Shared declarations for the idasql::entities tables.
 *
 * Common includes, safe accessors, function-type helpers, and parsing
 * utilities used across the per-table entity definition units
 * (entities_funcs.cpp, entities_names.cpp, ...). Each per-table header
 * includes this one.
 */

#pragma once

#include <idasql/platform.hpp>

#include <idasql/string_utils.hpp>
#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "dirtree_utils.hpp"
#include "ida_headers.hpp"

namespace idasql {
namespace core {

// ============================================================================
// Safe accessors (never throw; return empty/fallback on failure)
// ============================================================================

std::string safe_func_name(ea_t ea);
std::string safe_func_prototype(ea_t ea);
std::string safe_func_comment(ea_t ea, bool repeatable);
std::string safe_segm_name(segment_t *seg);
std::string safe_segm_class(segment_t *seg);
std::string safe_name(ea_t ea);
std::string safe_entry_name(size_t idx);
std::string name_or_fallback(ea_t ea);

// ============================================================================
// Function-type helpers
// ============================================================================

bool get_func_tinfo(ea_t ea, tinfo_t &tif);
bool get_func_type_details(ea_t ea, func_type_data_t &fi);
const char *get_cc_name(callcnv_t cc);

// ============================================================================
// Parsing helpers (trim_copy is in <idasql/string_utils.hpp>)
// ============================================================================

using idasql::trim_copy;

// Convert a SQL int64 address value to ea_t (wrap-around cast).
ea_t normalize_sql_ea(int64_t value);

bool starts_with_ci(const std::string &text, const char *prefix);
bool equals_ci(const std::string &text, const char *token);
bool parse_int64(const std::string &text, int64_t &out_value);
bool resolve_named_type_tid(const std::string &name, tid_t &out_tid,
                            tinfo_t *out_tif = nullptr);
std::string tid_name_or_fallback(tid_t tid);

} // namespace core
} // namespace idasql
