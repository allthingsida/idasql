// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// `data_items` — enumerate defined data items (data heads). Canonical cross-tool
// surface, matching ghidrasql:
//   addr, name, data_type, size, value_repr, segment_name, is_string, is_initialized.

#include "code_data_items.hpp"

#include <bytes.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>

using namespace idasql::core;

namespace idasql {
namespace code {

namespace {

// A data head is a defined item whose class is data (not code/tail/unknown).
inline bool is_data_head(ea_t ea) {
  if (ea == BADADDR)
    return false;
  flags64_t f = get_flags(ea);
  return is_head(f) && is_data(f);
}

// Best-effort type descriptor: prefer an applied tinfo, else the flag class.
std::string data_type_str(ea_t ea) {
  flags64_t f = get_flags(ea);
  tinfo_t tif;
  if (get_tinfo(&tif, ea)) {
    qstring s;
    if (tif.print(&s) && !s.empty())
      return s.c_str();
  }
  if (is_strlit(f))
    return "string";
  if (is_struct(f))
    return "struct";
  switch (get_item_size(ea)) {
  case 1: return "byte";
  case 2: return "word";
  case 4: return "dword";
  case 8: return "qword";
  default: return "data";
  }
}

// Best-effort value rendering: string contents for strlits, small scalars as hex.
std::string value_repr_str(ea_t ea) {
  flags64_t f = get_flags(ea);
  if (is_strlit(f)) {
    qstring s;
    if (get_strlit_contents(&s, ea, -1, get_str_type(ea)) > 0)
      return s.c_str();
    return "";
  }
  if (!is_loaded(ea))
    return "";
  asize_t sz = get_item_size(ea);
  uint64_t v = 0;
  switch (sz) {
  case 1: v = get_byte(ea); break;
  case 2: v = get_word(ea); break;
  case 4: v = get_dword(ea); break;
  case 8: v = get_qword(ea); break;
  default: return "";
  }
  char buf[32];
  qsnprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
  return buf;
}

std::string segment_name_str(ea_t ea) {
  qstring s;
  if (idasql_segment_name(&s, ea) > 0)
    return s.c_str();
  return "";
}

// WHERE addr = X pushdown: a single data head (or nothing) at X.
class DataItemAtIterator : public xsql::RowIterator {
  ea_t ea_ = BADADDR;
  bool started_ = false;
  bool valid_ = false;

public:
  explicit DataItemAtIterator(ea_t ea) : ea_(ea), valid_(is_data_head(ea)) {}

  bool next() override {
    if (!started_) {
      started_ = true;
      return valid_;
    }
    valid_ = false;
    return false;
  }

  bool eof() const override { return started_ && !valid_; }

  void column(xsql::FunctionContext &ctx, int col) override {
    if (!valid_) { ctx.result_null(); return; }
    switch (col) {
    case 0: ctx.result_int64(static_cast<int64_t>(ea_)); break;
    case 1: ctx.result_text(get_ea_name(ea_).c_str()); break;
    case 2: ctx.result_text(data_type_str(ea_).c_str()); break;
    case 3: ctx.result_int64(static_cast<int64_t>(get_item_size(ea_))); break;
    case 4: ctx.result_text(value_repr_str(ea_).c_str()); break;
    case 5: ctx.result_text(segment_name_str(ea_).c_str()); break;
    case 6: ctx.result_int64(is_strlit(get_flags(ea_)) ? 1 : 0); break;
    case 7: ctx.result_int64(is_loaded(ea_) ? 1 : 0); break;
    default: ctx.result_null(); break;
    }
  }

  int64_t rowid() const override { return static_cast<int64_t>(ea_); }

private:
  static std::string get_ea_name(ea_t ea) {
    qstring s;
    if (get_name(&s, ea) > 0)
      return s.c_str();
    return "";
  }
};

// Full-scan generator: walk every head, keep the data ones.
class DataItemsGenerator : public xsql::Generator<DataItemRow> {
  ea_t max_ea_ = inf_get_max_ea();
  bool started_ = false;
  mutable size_t scanned_ = 0;
  mutable DataItemRow row_{BADADDR};

  ea_t advance_to_data(ea_t ea) const {
    while (ea != BADADDR && ea < max_ea_) {
      if (((scanned_++) & 1023u) == 0 && xsql::vtab_interrupted()) {
        xsql::set_vtab_error("query interrupted while scanning data_items");
        return BADADDR;
      }
      if (is_data_head(ea))
        return ea;
      ea = next_head(ea, max_ea_);
    }
    return BADADDR;
  }

public:
  bool next() override {
    ea_t ea;
    if (!started_) {
      started_ = true;
      ea = advance_to_data(inf_get_min_ea());
    } else {
      ea = advance_to_data(next_head(row_.ea, max_ea_));
    }
    if (ea == BADADDR)
      return false;
    row_.ea = ea;
    return true;
  }

  const DataItemRow &current() const override { return row_; }

  int64_t rowid() const override { return static_cast<int64_t>(row_.ea); }
};

std::string ea_name_str(ea_t ea) {
  qstring s;
  if (get_name(&s, ea) > 0)
    return s.c_str();
  return "";
}

}  // namespace

GeneratorTableDef<DataItemRow> define_data_items() {
  return xsql::generator_table<DataItemRow>("data_items")
      .generator([]() -> std::unique_ptr<xsql::Generator<DataItemRow>> {
        return std::make_unique<DataItemsGenerator>();
      })
      .column_int64("addr",
                    [](const DataItemRow &r) -> int64_t {
                      return static_cast<int64_t>(r.ea);
                    })
      .column_text("name",
                   [](const DataItemRow &r) -> std::string {
                     return ea_name_str(r.ea);
                   })
      .column_text("data_type",
                   [](const DataItemRow &r) -> std::string {
                     return data_type_str(r.ea);
                   })
      .column_int64("size",
                    [](const DataItemRow &r) -> int64_t {
                      return static_cast<int64_t>(get_item_size(r.ea));
                    })
      .column_text("value_repr",
                   [](const DataItemRow &r) -> std::string {
                     return value_repr_str(r.ea);
                   })
      .column_text("segment_name",
                   [](const DataItemRow &r) -> std::string {
                     return segment_name_str(r.ea);
                   })
      .column_int64("is_string",
                    [](const DataItemRow &r) -> int64_t {
                      return is_strlit(get_flags(r.ea)) ? 1 : 0;
                    })
      .column_int64("is_initialized",
                    [](const DataItemRow &r) -> int64_t {
                      return is_loaded(r.ea) ? 1 : 0;
                    })
      .filter_eq(
          "addr",
          [](int64_t addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<DataItemAtIterator>(
                static_cast<ea_t>(addr));
          },
          1.0, 1.0)
      .build();
}

} // namespace code
} // namespace idasql
