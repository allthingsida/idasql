// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * code_switch_tables.hpp - `switch_tables` (summary, one row per switch) and
 * `switch_cases` (detail, one row per case value -> target).
 * switch_tables schema (ghidra reference): func_addr, instr_addr, table_addr,
 * min_case, max_case, case_count, default_addr.
 * switch_cases schema: func_addr, switch_instr_addr, case_index, case_value,
 * target_addr, is_default.
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace code {

// One reconstructed switch/jump table. BADADDR addresses and unavailable case
// bounds are surfaced as SQL NULL.
struct SwitchTableInfo {
  ea_t func_ea = BADADDR;
  ea_t instr_addr = BADADDR;   // the indirect-jump (switch) instruction
  ea_t table_addr = BADADDR;   // jump-table start address (switch_info_t::jumps)
  int64_t min_case = 0;
  int64_t max_case = 0;
  int64_t case_count = 0;
  ea_t default_addr = BADADDR;
  bool has_cases = false;
  bool has_default = false;
};

GeneratorTableDef<SwitchTableInfo> define_switch_tables();

// One (case value -> target) mapping within a switch, from calc_switch_cases().
// `case_value` is NULL for the default row (is_default=1); `case_index` is 0-based
// within the switch. `switch_instr_addr` joins `switch_tables.instr_addr`.
struct SwitchCaseInfo {
  ea_t func_ea = BADADDR;
  ea_t switch_instr_addr = BADADDR;
  int64_t case_index = 0;
  int64_t case_value = 0;
  ea_t target_addr = BADADDR;
  bool is_default = false;
};

GeneratorTableDef<SwitchCaseInfo> define_switch_cases();

} // namespace code
} // namespace idasql
