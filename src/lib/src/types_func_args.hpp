// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * types_func_args.hpp - `types_func_args` table (function prototype arguments),
 * the argument-type classification helpers it relies on, and the per-function
 * argument iterator.
 */

#pragma once

#include "types_common.hpp"

namespace idasql {
namespace types {

struct TypeClassification {
  // Surface-level classification (literal type as written)
  bool is_ptr = false;
  bool is_int = false;      // Exactly int type
  bool is_integral = false; // Int-like family (int, long, short, char, bool)
  bool is_float = false;
  bool is_void = false;
  bool is_struct = false;
  bool is_array = false;
  int ptr_depth = 0;
  std::string base_type; // Type name with pointers stripped

  // Resolved classification (after typedef resolution)
  bool is_ptr_resolved = false;
  bool is_int_resolved = false;
  bool is_integral_resolved = false;
  bool is_float_resolved = false;
  bool is_void_resolved = false;
  int ptr_depth_resolved = 0;
  std::string base_type_resolved;
};

int get_ptr_depth(tinfo_t tif);
std::string get_base_type_name(tinfo_t tif);

void classify_tinfo(const tinfo_t &tif, bool &is_ptr, bool &is_int,
                    bool &is_integral, bool &is_float, bool &is_void,
                    bool &is_struct, bool &is_array, int &ptr_depth,
                    std::string &base_type);

bool is_surface_typedef(const tinfo_t &tif);

void classify_surface(const tinfo_t &tif, bool &is_ptr, bool &is_int,
                      bool &is_integral, bool &is_float, bool &is_void,
                      bool &is_struct, bool &is_array, int &ptr_depth,
                      std::string &base_type);

TypeClassification classify_arg_type(const tinfo_t &tif);

struct FuncArgEntry {
  uint32_t type_ordinal;
  std::string type_name;
  int arg_index; // -1 for return type
  std::string arg_name;
  std::string arg_type;
  std::string calling_conv; // Only set on arg_index=-1 row

  // Type classification
  TypeClassification tc;
};

const char *get_calling_convention_name(cm_t cc);

void collect_func_args(std::vector<FuncArgEntry> &rows);

/**
 * Iterator for function args of a specific function type.
 * Used when query has: WHERE type_ordinal = X
 */
class FuncArgsInTypeIterator : public xsql::RowIterator {
  uint32_t type_ordinal_;
  std::string type_name_;
  func_type_data_t fi_;
  int idx_ = -2; // Start at -2, first next() moves to -1 (return type)
  bool valid_ = false;
  bool has_data_ = false;

public:
  explicit FuncArgsInTypeIterator(uint32_t ordinal);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

CachedTableDef<FuncArgEntry> define_types_func_args();

} // namespace types
} // namespace idasql
