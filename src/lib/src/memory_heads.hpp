// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_heads.hpp - `heads` generator table (defined items) + helpers.
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace memory {

struct HeadRow {
  ea_t ea = BADADDR;
};

void collect_head_rows(std::vector<HeadRow> &rows);
const char *get_item_type_str(ea_t ea);

GeneratorTableDef<HeadRow> define_heads();

} // namespace memory
} // namespace idasql
