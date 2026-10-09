// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * xrefs.hpp - `xrefs` and `data_refs` tables, plus constraint-pushdown
 * iterators (xrefs to/from an address, xrefs from a function).
 */

#pragma once

#include "core_common.hpp"

#include <string>

namespace idasql {

// The readable `kind` of a cross-reference, shared by every table that reports
// xrefs (`xrefs.kind`, `data_refs.kind`, `struct_member_xrefs.xref_kind`) so the
// same IDA xref type always gets the same label. Code: call, jump, flow, code.
// Data: offset, write, read, text, info, data (dr_U and dr_S are "data").
// `type` is an xrefblk_t::type (or a stored copy of one); the XREF_* flag bits are
// masked off before the cref_t / dref_t value is mapped.
inline std::string xref_kind_str(bool iscode, uchar type) {
  const uchar t = static_cast<uchar>(type & XREF_MASK);
  if (iscode) {
    switch (t) {
      case fl_CF: case fl_CN: return "call";
      case fl_JF: case fl_JN: return "jump";
      case fl_F:              return "flow";
      default:                return "code";
    }
  }
  switch (t) {
    case dr_O: return "offset";
    case dr_W: return "write";
    case dr_R: return "read";
    case dr_T: return "text";
    case dr_I: return "info";
    default:   return "data";
  }
}

namespace xrefs {

// One cross-reference as reported under one function. An xref whose source
// lies in a tail shared by several functions is one row per owner (from_func);
// from_func is BADADDR (SQL NULL) for a source outside every function.
struct XrefInfo {
  ea_t from_ea = BADADDR;
  ea_t to_ea = BADADDR;
  ea_t from_func = BADADDR;
  uint8_t type = 0;
  bool is_code = false;
  uint32_t ordinal = 0; // position among the non-flow xrefs from from_ea
};

struct DataRefInfo {
  ea_t from_ea = BADADDR;
  ea_t to_ea = BADADDR;
  ea_t from_func = BADADDR;
  uint8_t type = 0;
};

/**
 * Base for the xref pushdown iterators: each one collects its rows up front
 * (one per owning function of the source) and reports them with the same
 * columns and rowid as the full scan.
 */
class XrefRowsIterator : public xsql::RowIterator {
protected:
  std::vector<XrefInfo> rows_;
  size_t idx_ = 0;
  bool started_ = false;

public:
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

/**
 * Iterator for xrefs TO a specific address.
 * Used when query has: WHERE to_addr = X
 * Uses xrefblk_t::first_to/next_to for O(refs_to_X) instead of O(all_xrefs)
 */
class XrefsToIterator : public XrefRowsIterator {
public:
  explicit XrefsToIterator(ea_t target);
};

/**
 * Iterator for xrefs FROM a specific address.
 * Used when query has: WHERE from_addr = X
 * Uses xrefblk_t::first_from/next_from for O(refs_from_X) instead of
 * O(all_xrefs)
 */
class XrefsFromIterator : public XrefRowsIterator {
public:
  explicit XrefsFromIterator(ea_t source);
};

/**
 * Iterator for xrefs originating from within a specific function.
 * Used when query has: WHERE from_func = X
 * Walks every head of every chunk of the function and enumerates its outgoing
 * xrefs.
 */
class XrefsFromFuncIterator : public XrefRowsIterator {
public:
  explicit XrefsFromFuncIterator(ea_t func_ea);
};

CachedTableDef<XrefInfo> define_xrefs();
CachedTableDef<DataRefInfo> define_data_refs();

} // namespace xrefs
} // namespace idasql
