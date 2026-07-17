// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * types_bookmarks.hpp - `local_type_bookmarks` table (bookmarks anchored at
 * local-type ordinals).
 */

#pragma once

#include "types_common.hpp"

namespace idasql {
namespace types {

struct LocalTypeBookmarkRow {
  uint32_t index = 0;
  uint32_t ordinal = 0;
  std::string type_name;
  std::string desc;
  uint64_t inode = 0;
  std::string folder_path;
  std::string full_path;
};

CachedTableDef<LocalTypeBookmarkRow> define_local_type_bookmarks();
void reset_local_type_bookmark_place_cache();

} // namespace types
} // namespace idasql
