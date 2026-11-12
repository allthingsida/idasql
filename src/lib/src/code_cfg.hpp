// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace code {

struct CfgEdgeInfo {
  ea_t func_ea;
  ea_t from_addr;
  ea_t to_addr;
  std::string edge_type;
};

GeneratorTableDef<CfgEdgeInfo> define_cfg_edges();

bool register_disasm_views(xsql::Database &db);

}
}
