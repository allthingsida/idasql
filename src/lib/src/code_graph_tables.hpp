// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * code_graph_tables.hpp - canonical cross-tool CFG-graph tables,
 * matching the ghidrasql reference shapes:
 *   dominators      (func_addr, node_addr, idom_addr, depth, is_entry)
 *   post_dominators (func_addr, node_addr, ipdom_addr, depth, is_exit)
 *   loops           (func_addr, header_addr, latch_addr, start_addr, end_addr,
 *                    depth, loop_kind, block_count)
 *
 * Each maps a function's flow-chart basic blocks onto opaque node ids and runs the
 * generic, RE-agnostic xsql::graph module — the CFG knowledge stays entirely here;
 * libxsql stays a stock graph library. Filter by func_addr for a single function.
 */

#pragma once

#include "core_common.hpp"

#include <xsql/graph.hpp>

#include <vector>

namespace idasql {
namespace code {

struct DominatorRow {
  ea_t func_ea = BADADDR;
  ea_t node_addr = BADADDR;
  ea_t idom_addr = BADADDR;
  bool has_idom = false;   // false for the entry block -> idom_addr NULL
  int64_t depth = 0;       // depth in the dominator tree (entry = 0)
  bool is_entry = false;
};

struct PostDominatorRow {
  ea_t func_ea = BADADDR;
  ea_t node_addr = BADADDR;
  ea_t ipdom_addr = BADADDR;
  bool has_ipdom = false;  // false when the node post-dominates straight to exit
  int64_t depth = 0;       // depth in the post-dominator tree (exit side = 0)
  bool is_exit = false;    // block has no CFG successors (a function sink)
};

struct LoopRow {
  ea_t func_ea = BADADDR;
  ea_t header_addr = BADADDR;
  ea_t latch_addr = BADADDR;
  ea_t start_addr = BADADDR;   // min body-block start
  ea_t end_addr = BADADDR;     // max body-block end
  int64_t depth = 0;           // loop-nesting depth (outermost = 1)
  std::string loop_kind;       // "natural"
  int64_t block_count = 0;
};

GeneratorTableDef<DominatorRow> define_dominators();
GeneratorTableDef<PostDominatorRow> define_post_dominators();
GeneratorTableDef<LoopRow> define_loops();

// The block-level CFG of the function whose entry is `func_ea` (shared by the
// graph tables and disasm_loops): block ids in flow-chart order, with each block's
// start and end address and the entry block's id. False for a non-entry address
// or an interrupted query.
bool build_func_graph(ea_t func_ea, xsql::graph::DirectedGraph &g_out,
                      std::vector<ea_t> &addr, std::vector<ea_t> &end_ea,
                      size_t &entry);

} // namespace code
} // namespace idasql
