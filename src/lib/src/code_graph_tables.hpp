// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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
  bool has_idom = false;
  int64_t depth = 0;
  bool is_entry = false;
};

struct PostDominatorRow {
  ea_t func_ea = BADADDR;
  ea_t node_addr = BADADDR;
  ea_t ipdom_addr = BADADDR;
  bool has_ipdom = false;
  int64_t depth = 0;
  bool is_exit = false;
};

struct LoopRow {
  ea_t func_ea = BADADDR;
  ea_t header_addr = BADADDR;
  ea_t latch_addr = BADADDR;
  ea_t start_addr = BADADDR;
  ea_t end_addr = BADADDR;
  int64_t depth = 0;
  std::string loop_kind;
  int64_t block_count = 0;
};

GeneratorTableDef<DominatorRow> define_dominators();
GeneratorTableDef<PostDominatorRow> define_post_dominators();
GeneratorTableDef<LoopRow> define_loops();

bool build_func_graph(ea_t func_ea, xsql::graph::DirectedGraph &g_out,
                      std::vector<ea_t> &addr, std::vector<ea_t> &end_ea,
                      size_t &entry);

}
}
