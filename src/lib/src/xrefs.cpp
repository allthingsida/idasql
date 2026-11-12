// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "xrefs.hpp"

#include "function_rowid.hpp"

using namespace idasql::core;

namespace idasql {
namespace xrefs {

static inline bool is_flow_xref(const xrefblk_t &xb) {
  return xb.iscode && xb.type == fl_F;
}

static std::vector<ea_t> source_owners(ea_t from) {
  std::vector<ea_t> owners;
  idasql_for_each_owner_of(from, [&](ea_t owner) { owners.push_back(owner); });
  if (owners.empty())
    owners.push_back(BADADDR);
  return owners;
}

template <typename Callback>
static void for_each_xref_from(ea_t from, Callback &&cb) {
  xrefblk_t xb;
  uint32_t ordinal = 0;
  for (bool ok = xb.first_from(from, XREF_ALL); ok; ok = xb.next_from()) {
    if (is_flow_xref(xb))
      continue;
    const uint32_t k = ordinal++;
    if (xb.to == BADADDR)
      continue;
    cb(xb, k);
  }
}

static void append_xref_rows(const xrefblk_t &xb, uint32_t ordinal,
                             const std::vector<ea_t> &owners,
                             std::vector<XrefInfo> &out) {
  for (ea_t owner : owners) {
    XrefInfo xi;
    xi.from_ea = xb.from;
    xi.to_ea = xb.to;
    xi.from_func = owner;
    xi.type = xb.type;
    xi.is_code = xb.iscode;
    xi.ordinal = ordinal;
    out.push_back(xi);
  }
}

static uint64_t splitmix64(uint64_t x) {
  x += 0x9E3779B97F4A7C15ull;
  x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
  x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
  return x ^ (x >> 31);
}

static int64_t xref_rowid(const XrefInfo &row) {
  if (row.from_func != BADADDR && row.ordinal < (1u << 16)) {
    const int func_index = get_func_num(row.from_func);
    uint64_t pos = 0;
    if (func_index >= 0 && func_index < (1 << 23) &&
        idasql::detail::function_position(row.from_func, row.from_ea, pos) &&
        pos < (uint64_t{1} << 24)) {
      return static_cast<int64_t>(
          (static_cast<uint64_t>(func_index) << 40) | (pos << 16) |
          static_cast<uint64_t>(row.ordinal));
    }
  }
  uint64_t h = splitmix64(static_cast<uint64_t>(row.from_func));
  h = splitmix64(h ^ static_cast<uint64_t>(row.from_ea));
  h = splitmix64(h ^ static_cast<uint64_t>(row.to_ea));
  h = splitmix64(h ^ static_cast<uint64_t>(row.ordinal));
  return static_cast<int64_t>(h | (uint64_t{1} << 63));
}

static void xref_column(xsql::FunctionContext &ctx, const XrefInfo &r,
                        int col) {
  switch (col) {
  case 0:
    ctx.result_int64(static_cast<int64_t>(r.from_ea));
    break;
  case 1:
    ctx.result_int64(static_cast<int64_t>(r.to_ea));
    break;
  case 2:
    if (r.from_func == BADADDR)
      ctx.result_null();
    else
      ctx.result_int64(static_cast<int64_t>(r.from_func));
    break;
  case 3:
    ctx.result_int(r.type);
    break;
  case 4:
    ctx.result_int(r.is_code ? 1 : 0);
    break;
  case 5:
    ctx.result_text(xref_kind_str(r.is_code, r.type));
    break;
  default:
    ctx.result_null();
    break;
  }
}

bool XrefRowsIterator::next() {
  if (!started_)
    started_ = true;
  else if (idx_ < rows_.size())
    ++idx_;
  return idx_ < rows_.size();
}

bool XrefRowsIterator::eof() const { return started_ && idx_ >= rows_.size(); }

void XrefRowsIterator::column(xsql::FunctionContext &ctx, int col) {
  if (idx_ >= rows_.size()) {
    ctx.result_null();
    return;
  }
  xref_column(ctx, rows_[idx_], col);
}

int64_t XrefRowsIterator::rowid() const {
  return idx_ < rows_.size() ? xref_rowid(rows_[idx_]) : 0;
}

XrefsToIterator::XrefsToIterator(ea_t target) {
  xrefblk_t xb;
  for (bool ok = xb.first_to(target, XREF_ALL); ok; ok = xb.next_to()) {
    if (is_flow_xref(xb))
      continue;
    uint32_t ordinal = 0;
    bool found = false;
    for_each_xref_from(xb.from, [&](const xrefblk_t &from_xb, uint32_t k) {
      if (!found && from_xb.to == target && from_xb.iscode == xb.iscode &&
          from_xb.type == xb.type) {
        ordinal = k;
        found = true;
      }
    });
    if (!found)
      continue;
    append_xref_rows(xb, ordinal, source_owners(xb.from), rows_);
  }
}

XrefsFromIterator::XrefsFromIterator(ea_t source) {
  std::vector<ea_t> owners;
  for_each_xref_from(source, [&](const xrefblk_t &xb, uint32_t k) {
    if (owners.empty())
      owners = source_owners(source);
    append_xref_rows(xb, k, owners, rows_);
  });
}

XrefsFromFuncIterator::XrefsFromFuncIterator(ea_t func_ea) {
  if (!idasql_is_func_start(func_ea))
    return;
  const std::vector<ea_t> owner{func_ea};
  idasql_func_item_iterator fii;
  for (bool ok = fii.set(func_ea); ok; ok = fii.next_head()) {
    for_each_xref_from(fii.current(), [&](const xrefblk_t &xb, uint32_t k) {
      append_xref_rows(xb, k, owner, rows_);
    });
  }
}

CachedTableDef<XrefInfo> define_xrefs() {
  return cached_table<XrefInfo>("xrefs")
      .no_shared_cache()
      .estimate_rows([]() -> size_t {
        return get_func_qty() * 10;
      })
      .cache_builder([](std::vector<XrefInfo> &cache) {
        const ea_t max_ea = inf_get_max_ea();
        uint64_t scanned = 0;
        for (ea_t ea = inf_get_min_ea(); ea != BADADDR && ea < max_ea;
             ea = next_head(ea, max_ea)) {
          if (((++scanned) & 4095u) == 0 && xsql::vtab_interrupted()) {
            xsql::set_vtab_error("query interrupted: timeout while building xrefs");
            return;
          }
          std::vector<ea_t> owners;
          for_each_xref_from(ea, [&](const xrefblk_t &xb, uint32_t k) {
            if (owners.empty())
              owners = source_owners(ea);
            append_xref_rows(xb, k, owners, cache);
          });
        }
      })
      .rowid([](const XrefInfo &r) -> int64_t { return xref_rowid(r); })
      .column_int64("from_addr",
                    [](const XrefInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.from_ea);
                    })
      .column_int64("to_addr",
                    [](const XrefInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.to_ea);
                    })
      .column("from_func", xsql::ColumnType::Integer,
              [](xsql::FunctionContext &ctx, const XrefInfo &r) {
                if (r.from_func == BADADDR)
                  ctx.result_null();
                else
                  ctx.result_int64(static_cast<int64_t>(r.from_func));
              })
      .column_int(
          "type",
          [](const XrefInfo &r) -> int { return static_cast<int>(r.type); })
      .column_int("is_code",
                  [](const XrefInfo &r) -> int { return r.is_code ? 1 : 0; })
      .column_text("kind",
                   [](const XrefInfo &r) -> std::string {
                     return xref_kind_str(r.is_code, r.type);
                   })
      .filter_eq(
          "to_addr",
          [](int64_t target) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<XrefsToIterator>(static_cast<ea_t>(target));
          },
          0.5, 5.0)
      .filter_eq(
          "from_addr",
          [](int64_t source) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<XrefsFromIterator>(
                static_cast<ea_t>(source));
          },
          0.5, 5.0)
      .filter_eq(
          "from_func",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<XrefsFromFuncIterator>(
                static_cast<ea_t>(func_addr));
          },
          1.0, 10.0)
      .build();
}

CachedTableDef<DataRefInfo> define_data_refs() {
  return cached_table<DataRefInfo>("data_refs")
      .no_shared_cache()
      .estimate_rows([]() -> size_t { return get_func_qty() * 4; })
      .cache_builder([](std::vector<DataRefInfo> &cache) {
        size_t func_qty = get_func_qty();
        for (size_t i = 0; i < func_qty; i++) {
          const ea_t func_ea = idasql_func_ea_by_num(i);
          if (func_ea == BADADDR)
            continue;

          idasql_func_item_iterator fii;
          if (!fii.set(func_ea))
            continue;

          auto collect_item_refs = [&](ea_t item_ea) {
            xrefblk_t xb;
            for (bool ok = xb.first_from(item_ea, XREF_ALL); ok;
                 ok = xb.next_from()) {
              if (xb.iscode || xb.to == BADADDR)
                continue;

              DataRefInfo row;
              row.from_ea = xb.from;
              row.to_ea = xb.to;
              row.from_func = func_ea;
              row.type = xb.type;
              cache.push_back(row);
            }
          };

          collect_item_refs(fii.current());
          while (fii.next_head()) {
            collect_item_refs(fii.current());
          }
        }
      })
      .column_int64("from_addr",
                    [](const DataRefInfo &row) -> int64_t {
                      return static_cast<int64_t>(row.from_ea);
                    })
      .column_int64("to_addr",
                    [](const DataRefInfo &row) -> int64_t {
                      return static_cast<int64_t>(row.to_ea);
                    })
      .column_int64("from_func_addr",
                    [](const DataRefInfo &row) -> int64_t {
                      return row.from_func != BADADDR
                                 ? static_cast<int64_t>(row.from_func)
                                 : 0;
                    })
      .column_text("from_func_name",
                   [](const DataRefInfo &row) -> std::string {
                     return row.from_func != BADADDR
                                ? name_or_fallback(row.from_func)
                                : "";
                   })
      .column_int("ref_type",
                  [](const DataRefInfo &row) -> int {
                    return static_cast<int>(row.type);
                  })
      .column_text("kind",
                   [](const DataRefInfo &row) -> std::string {
                     return xref_kind_str(false, row.type);
                   })
      .build();
}

}
}
