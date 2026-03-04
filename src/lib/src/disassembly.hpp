// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * disassembly.hpp - Disassembly-level SQL tables
 *
 * Tables: disasm_calls, disasm_loops
 */

#pragma once

#include <idasql/platform.hpp>

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include "ida_headers.hpp"

#include <vector>
#include <string>

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

void collect_loops_for_func(std::vector<LoopInfo>& loops, func_t* pfn);

GeneratorTableDef<DisasmCallInfo> define_disasm_calls();
GeneratorTableDef<LoopInfo> define_disasm_loops();
bool register_disasm_views(xsql::Database& db);

struct DisassemblyRegistry {
    GeneratorTableDef<DisasmCallInfo> disasm_calls;
    GeneratorTableDef<LoopInfo> disasm_loops;

    DisassemblyRegistry();
    void register_all(xsql::Database& db);
};

} // namespace disassembly
} // namespace idasql
