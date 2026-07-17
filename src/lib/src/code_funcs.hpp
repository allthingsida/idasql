// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_funcs.hpp - `funcs` table (functions: address, name, prototype,
 * comment, type details, folder path).
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace code {

struct FuncRow {
  ea_t start_ea = BADADDR;
  std::string original_name;
  std::string original_prototype;
  std::string original_comment;
  std::string original_rpt_comment;
  std::string folder_path;
  std::string full_path;

  // Lazy-computed type details
  mutable func_type_data_t fi;
  mutable bool fi_valid = false;
  mutable bool fi_computed = false;

  // Defined after get_func_type_details declaration below
  inline bool ensure_fi() const;
};

inline bool FuncRow::ensure_fi() const {
  if (!fi_computed) {
    fi_computed = true;
    fi_valid = core::get_func_type_details(start_ea, fi);
  }
  return fi_valid;
}

CachedTableDef<FuncRow> define_funcs();

} // namespace code
} // namespace idasql
