// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_imports.hpp - `imports` table (imported symbols + module).
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace symbols {

struct ImportInfo {
  int module_idx;
  ea_t ea;
  std::string name;
  uval_t ord;
  std::string folder_path;
  std::string full_path;
};

struct ImportEnumContext {
  std::vector<ImportInfo> *cache;
  const std::unordered_map<uint64_t, dirtrees::DirtreePathInfo> *folder_paths;
  int module_idx;
};

std::string get_import_module_name_safe(int idx);

CachedTableDef<ImportInfo> define_imports();

} // namespace symbols
} // namespace idasql
