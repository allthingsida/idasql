// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace code {

struct SwitchTableInfo {
  ea_t func_ea = BADADDR;
  ea_t instr_addr = BADADDR;
  ea_t table_addr = BADADDR;
  int64_t min_case = 0;
  int64_t max_case = 0;
  int64_t case_count = 0;
  ea_t default_addr = BADADDR;
  bool has_cases = false;
  bool has_default = false;
};

GeneratorTableDef<SwitchTableInfo> define_switch_tables();

struct SwitchCaseInfo {
  ea_t func_ea = BADADDR;
  ea_t switch_instr_addr = BADADDR;
  int64_t case_index = 0;
  int64_t case_value = 0;
  ea_t target_addr = BADADDR;
  bool is_default = false;
};

GeneratorTableDef<SwitchCaseInfo> define_switch_cases();

}
}
