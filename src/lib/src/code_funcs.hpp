// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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

  mutable func_type_data_t fi;
  mutable bool fi_valid = false;
  mutable bool fi_computed = false;

  inline bool ensure_fi() const;
};

inline bool FuncRow::ensure_fi() const {
  if (!fi_computed) {
    fi_computed = true;
    fi_valid = core::get_func_type_details(start_ea, fi);
  }
  return fi_valid;
}

struct FuncAtRow {
  ea_t func_ea = BADADDR;
  ea_t addr = BADADDR;
  ea_t chunk_start = BADADDR;
  ea_t chunk_end = BADADDR;
  bool is_tail = false;
};

CachedTableDef<FuncRow> define_funcs();

GeneratorTableDef<FuncAtRow> define_func_at();

}
}
