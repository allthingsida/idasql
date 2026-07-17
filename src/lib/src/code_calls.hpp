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

struct DisasmCallInfo {
  ea_t func_addr;
  ea_t ea;
  ea_t callee_addr;
  std::string callee_name;
};

GeneratorTableDef<DisasmCallInfo> define_disasm_calls();

} // namespace code
} // namespace idasql
