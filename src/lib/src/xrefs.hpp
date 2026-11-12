// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

#include <string>

namespace idasql {

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

struct XrefInfo {
  ea_t from_ea = BADADDR;
  ea_t to_ea = BADADDR;
  ea_t from_func = BADADDR;
  uint8_t type = 0;
  bool is_code = false;
  uint32_t ordinal = 0;
};

struct DataRefInfo {
  ea_t from_ea = BADADDR;
  ea_t to_ea = BADADDR;
  ea_t from_func = BADADDR;
  uint8_t type = 0;
};

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

class XrefsToIterator : public XrefRowsIterator {
public:
  explicit XrefsToIterator(ea_t target);
};

class XrefsFromIterator : public XrefRowsIterator {
public:
  explicit XrefsFromIterator(ea_t source);
};

class XrefsFromFuncIterator : public XrefRowsIterator {
public:
  explicit XrefsFromFuncIterator(ea_t func_ea);
};

CachedTableDef<XrefInfo> define_xrefs();
CachedTableDef<DataRefInfo> define_data_refs();

}
}
