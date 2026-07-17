// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_names.hpp - `names` and `entries` tables (named addresses, entry
 * points).
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace symbols {

struct NameRow {
  ea_t ea = BADADDR;
  std::string name;
  int is_public = 0;
  int is_weak = 0;
  std::string folder_path;
  std::string full_path;
};

void collect_name_rows(std::vector<NameRow> &rows);

CachedTableDef<NameRow> define_names();
VTableDef define_entries();

} // namespace symbols
} // namespace idasql
