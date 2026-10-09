// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * code_cfg.hpp - `cfg_edges` table (intra-function control-flow edges) and the
 * disassembly convenience views.
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace code {

// cfg_edges table row. Canonical edge token: from_addr/to_addr (block start
// addresses); func_addr is the owning function. (Was from_block/to_block; renamed
// to the ratified from_addr/to_addr edge token — cross-tool convergence.)
struct CfgEdgeInfo {
  ea_t func_ea;
  ea_t from_addr;
  ea_t to_addr;
  std::string edge_type; // "normal", "true", "false"
};

GeneratorTableDef<CfgEdgeInfo> define_cfg_edges();

// Registers disassembly convenience views (calls_in_loops, funcs_with_loops, ...)
bool register_disasm_views(xsql::Database &db);

} // namespace code
} // namespace idasql
