// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "types_common.hpp"

namespace idasql {
namespace types {

struct TypeEntry {
  uint32_t ordinal;
  std::string name;
  std::string kind;
  int64_t size;
  int alignment;
  bool is_struct;
  bool is_union;
  bool is_enum;
  bool is_typedef;
  bool is_func;
  bool is_ptr;
  bool is_array;
  std::string definition;
  std::string resolved;
  std::string folder_path;
  std::string full_path;
  bool is_fixed;
  bool is_bitmask;
};

void collect_types(std::vector<TypeEntry> &rows);

CachedTableDef<TypeEntry> define_types();

}
}
