// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * code_graph.hpp - `call_graph` and `shortest_path` tables (function call-graph
 * BFS traversal).
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace code {

// call_graph virtual table row
struct CallGraphRow {
  ea_t func_addr = BADADDR;
  std::string func_name;
  int depth = 0;
  ea_t parent_addr = BADADDR;
};

// shortest_path virtual table row
struct ShortestPathRow {
  int step = 0;
  ea_t func_addr = BADADDR;
  std::string func_name;
};

// Get callees of a function (used by call_graph BFS)
void get_function_callees(ea_t func_addr, std::vector<ea_t> &callees);
// Get callers of a function (used by call_graph reverse BFS)
void get_function_callers(ea_t func_addr, std::vector<ea_t> &callers);

GeneratorTableDef<CallGraphRow> define_call_graph();
GeneratorTableDef<ShortestPathRow> define_shortest_path();

} // namespace code
} // namespace idasql
