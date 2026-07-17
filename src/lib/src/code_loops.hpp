// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * code_loops.hpp - `disasm_loops` table (natural loops per function).
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace code {

struct LoopInfo {
  ea_t func_addr;
  int loop_id;
  ea_t header_ea;
  ea_t header_end_ea;
  ea_t back_edge_block_ea;
  ea_t back_edge_block_end;
};

void collect_loops_for_func(std::vector<LoopInfo> &loops, func_t *pfn);

GeneratorTableDef<LoopInfo> define_disasm_loops();

} // namespace code
} // namespace idasql
