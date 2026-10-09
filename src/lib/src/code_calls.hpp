// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * code_calls.hpp - `disasm_calls` table (call sites within functions).
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace code {

// A call instruction and the function it is reported under. A call in a tail
// shared by several functions is one row per owner; owner is BADADDR (and
// func_addr 0) for a call outside every function.
struct DisasmCallInfo {
  ea_t func_addr;
  ea_t ea;
  ea_t callee_addr;
  std::string callee_name;
  ea_t owner = BADADDR;
};

GeneratorTableDef<DisasmCallInfo> define_disasm_calls();

} // namespace code
} // namespace idasql
