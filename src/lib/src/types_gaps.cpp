// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_gaps.hpp"

#include "types_members.hpp" // get_type_ordinal_by_name

#include <algorithm>
#include <utility>

namespace idasql {
namespace types {

// Free ranges are derived from the coverage of *non-gap* members: a gap member
// (TAFLD_GAP) is placeholder space, so it counts as free, not occupied. This is
// robust regardless of whether get_udt_details materializes implicit holes as
// gap members -- both explicit gap members and implicit holes (and trailing
// space up to total_size) surface as free ranges a field can be inserted into.
std::vector<GapRow> compute_type_gaps(uint32_t ordinal) {
  std::vector<GapRow> gaps;
  til_t *ti = get_idati();
  if (!ti) return gaps;
  const char *name = get_numbered_type_name(ti, ordinal);
  if (!name) return gaps;
  tinfo_t tif;
  if (!tif.get_numbered_type(ti, ordinal)) return gaps;
  if (!tif.is_struct()) return gaps; // unions overlay at offset 0 -- no gaps

  udt_type_data_t udt;
  if (!tif.get_udt_details(&udt)) return gaps;

  const size_t total_bytes = tif.get_size();
  if (total_bytes == 0 || total_bytes == BADSIZE) return gaps;
  const int64_t total = static_cast<int64_t>(total_bytes);

  std::vector<std::pair<int64_t, int64_t>> occ; // [start, end) in bytes
  for (const udm_t &m : udt) {
    if (m.is_gap()) continue; // gap members are free space
    const int64_t start = static_cast<int64_t>(m.offset / 8);
    const int64_t end = static_cast<int64_t>((m.offset + m.size + 7) / 8);
    if (end > start) occ.emplace_back(start, end);
  }
  std::sort(occ.begin(), occ.end());

  auto emit = [&](int64_t s, int64_t e) {
    if (e <= s) return;
    GapRow g;
    g.type_ordinal = ordinal;
    g.type_name = name;
    g.gap_offset = s;
    g.gap_size = e - s;
    gaps.push_back(std::move(g));
  };

  int64_t cur = 0;
  for (const auto &iv : occ) {
    if (iv.first > cur) emit(cur, iv.first);
    cur = std::max(cur, iv.second);
  }
  if (cur < total) emit(cur, total);
  return gaps;
}

bool range_overlaps_member(uint32_t ordinal, uint64_t start_bit, uint64_t end_bit) {
  if (end_bit <= start_bit) return false;
  til_t *ti = get_idati();
  if (!ti) return false;
  tinfo_t tif;
  if (!tif.get_numbered_type(ti, ordinal)) return false;
  if (!tif.is_struct()) return false; // unions overlay at 0 -- no fixed gaps
  udt_type_data_t udt;
  if (!tif.get_udt_details(&udt)) return false;

  // Compare in bits: udm_t.offset / .size are bit quantities, so a byte-rounded
  // check could miss an overlap when the new member starts mid-byte.
  for (const udm_t &m : udt) {
    if (m.is_gap()) continue; // gap members are free space, not real members
    const uint64_t s = m.offset;
    const uint64_t e = m.offset + m.size;
    if (e <= s) continue;
    if (start_bit < e && s < end_bit) return true; // half-open overlap
  }
  return false;
}

GapsIterator::GapsIterator(std::vector<GapRow> rows) : rows_(std::move(rows)) {}

bool GapsIterator::next() {
  ++idx_;
  return idx_ >= 0 && static_cast<size_t>(idx_) < rows_.size();
}

bool GapsIterator::eof() const {
  return idx_ < 0 || static_cast<size_t>(idx_) >= rows_.size();
}

void GapsIterator::column(xsql::FunctionContext &ctx, int col) {
  if (idx_ < 0 || static_cast<size_t>(idx_) >= rows_.size()) {
    ctx.result_null();
    return;
  }
  const GapRow &g = rows_[idx_];
  switch (col) {
    case 0: ctx.result_int(static_cast<int>(g.type_ordinal)); break;
    case 1: ctx.result_text(g.type_name.c_str()); break;
    case 2: ctx.result_int64(g.gap_offset); break;
    case 3: ctx.result_int64(g.gap_size); break;
    default: ctx.result_null(); break;
  }
}

int64_t GapsIterator::rowid() const {
  if (idx_ < 0 || static_cast<size_t>(idx_) >= rows_.size()) return 0;
  // Stable and collision-free: ordinal in the high 32 bits, gap byte offset in
  // the low 32. A multiply-by-100000 scheme collided once a gap offset reached
  // 100000 (structs > ~100 KB) with the next ordinal's rowid space.
  return (static_cast<int64_t>(rows_[idx_].type_ordinal) << 32)
       | (static_cast<int64_t>(rows_[idx_].gap_offset) & 0xFFFFFFFF);
}

CachedTableDef<GapRow> define_type_gaps() {
  return cached_table<GapRow>("type_gaps")
      .no_shared_cache()
      .estimate_rows([]() -> size_t { return 16; })
      // Unfiltered scan would compute gaps for every type -- require a filter.
      .cache_builder([](std::vector<GapRow> &) {
        xsql::set_vtab_error(
            "type_gaps requires a filter on type_ordinal or type_name "
            "(e.g. WHERE type_name = 'MyStruct').");
      })
      .column_int("type_ordinal", [](const GapRow &r) { return static_cast<int>(r.type_ordinal); })
      .column_text("type_name", [](const GapRow &r) { return r.type_name; })
      .column_int64("gap_offset", [](const GapRow &r) { return r.gap_offset; })
      .column_int64("gap_size", [](const GapRow &r) { return r.gap_size; })
      .filter_eq(
          "type_ordinal",
          [](int64_t ord) -> std::unique_ptr<xsql::RowIterator> {
            // Type ordinals are uint32; reject anything out of range rather than
            // truncating (e.g. 4294967297 -> 1 would return ordinal-1's gaps).
            if (ord <= 0 || ord > static_cast<int64_t>(UINT32_MAX))
              return std::make_unique<GapsIterator>(std::vector<GapRow>{});
            return std::make_unique<GapsIterator>(compute_type_gaps(static_cast<uint32_t>(ord)));
          },
          1.0, 8.0)
      .filter_eq_text(
          "type_name",
          [](const char *name) -> std::unique_ptr<xsql::RowIterator> {
            til_t *ti = get_idati();
            const int ord = get_type_ordinal_by_name(ti, name ? name : "");
            return std::make_unique<GapsIterator>(
                ord > 0 ? compute_type_gaps(static_cast<uint32_t>(ord)) : std::vector<GapRow>{});
          },
          1.0, 8.0)
      .build();
}

} // namespace types
} // namespace idasql
