// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * disassembly.hpp - Disassembly-level SQL tables
 *
 * Tables: disasm_calls, disasm_loops, call_graph, shortest_path, cfg_edges
 */

#pragma once

#include <idasql/platform.hpp>

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include "ida_headers.hpp"

#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <queue>

namespace idasql {
namespace disassembly {

std::string safe_name(ea_t ea);

struct DisasmCallInfo {
    ea_t func_addr;
    ea_t ea;
    ea_t callee_addr;
    std::string callee_name;
};

struct LoopInfo {
    ea_t func_addr;
    int loop_id;
    ea_t header_ea;
    ea_t header_end_ea;
    ea_t back_edge_block_ea;
    ea_t back_edge_block_end;
};

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

// cfg_edges table row
struct CfgEdgeInfo {
    ea_t func_ea;
    ea_t from_block;
    ea_t to_block;
    std::string edge_type;  // "normal", "true", "false"
};

void collect_loops_for_func(std::vector<LoopInfo>& loops, func_t* pfn);

// Get callees of a function (used by call_graph BFS)
void get_function_callees(ea_t func_addr, std::vector<ea_t>& callees);
// Get callers of a function (used by call_graph reverse BFS)
void get_function_callers(ea_t func_addr, std::vector<ea_t>& callers);

GeneratorTableDef<DisasmCallInfo> define_disasm_calls();
GeneratorTableDef<LoopInfo> define_disasm_loops();
GeneratorTableDef<CallGraphRow> define_call_graph();
GeneratorTableDef<ShortestPathRow> define_shortest_path();
GeneratorTableDef<CfgEdgeInfo> define_cfg_edges();
bool register_disasm_views(xsql::Database& db);

struct DisassemblyRegistry {
    GeneratorTableDef<DisasmCallInfo> disasm_calls;
    GeneratorTableDef<LoopInfo> disasm_loops;
    GeneratorTableDef<CallGraphRow> call_graph;
    GeneratorTableDef<ShortestPathRow> shortest_path;
    GeneratorTableDef<CfgEdgeInfo> cfg_edges;

    DisassemblyRegistry();
    void register_all(xsql::Database& db);
};

} // namespace disassembly
} // namespace idasql
