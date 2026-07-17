// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_bookmarks.hpp - `bookmarks` table (marked locations + descriptions).
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace symbols {

struct BookmarkRow {
  uint32_t index = 0;
  ea_t ea = BADADDR;
  std::string desc;
  uint64_t inode = 0;
  std::string folder_path;
  std::string full_path;
};

void collect_bookmark_rows(std::vector<BookmarkRow> &rows);

CachedTableDef<BookmarkRow> define_bookmarks();

} // namespace symbols
} // namespace idasql
