// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "memory_bytes.hpp"

using namespace idasql::core;

namespace idasql {
namespace memory {

// ============================================================================
// BYTES Table - Raw mapped bytes with patch support
// ============================================================================

namespace {

enum class ByteOrder { Asc, Desc };

struct ByteBounds {
  bool has_lower = false;
  ea_t lower = 0;
  bool lower_inclusive = true;
  bool has_upper = false;
  ea_t upper = 0;
  bool upper_inclusive = true;
};

void tighten_byte_lower_bound(ByteBounds &bounds, ea_t ea, bool inclusive) {
  if (!bounds.has_lower || ea > bounds.lower ||
      (ea == bounds.lower && !inclusive && bounds.lower_inclusive)) {
    bounds.has_lower = true;
    bounds.lower = ea;
    bounds.lower_inclusive = inclusive;
  }
}

void tighten_byte_upper_bound(ByteBounds &bounds, ea_t ea, bool inclusive) {
  if (!bounds.has_upper || ea < bounds.upper ||
      (ea == bounds.upper && !inclusive && bounds.upper_inclusive)) {
    bounds.has_upper = true;
    bounds.upper = ea;
    bounds.upper_inclusive = inclusive;
  }
}

bool byte_beyond_upper(ea_t ea, const ByteBounds &bounds) {
  return bounds.has_upper &&
         (ea > bounds.upper || (ea == bounds.upper && !bounds.upper_inclusive));
}

bool byte_below_lower(ea_t ea, const ByteBounds &bounds) {
  return bounds.has_lower &&
         (ea < bounds.lower || (ea == bounds.lower && !bounds.lower_inclusive));
}

bool byte_within_bounds(ea_t ea, const ByteBounds &bounds) {
  if (ea == BADADDR)
    return false;
  return !byte_below_lower(ea, bounds) && !byte_beyond_upper(ea, bounds);
}

bool is_mapped_byte_address(ea_t ea) {
  return ea != BADADDR && is_mapped(ea);
}

size_t estimate_mapped_byte_rows() {
  uint64 total = 0;
  for (int i = 0; i < get_segm_qty(); ++i) {
    segment_t *seg = getnseg(i);
    if (!seg || seg->end_ea <= seg->start_ea)
      continue;
    total += static_cast<uint64>(seg->end_ea - seg->start_ea);
    if (total > static_cast<uint64>(std::numeric_limits<size_t>::max()))
      return std::numeric_limits<size_t>::max();
  }
  return static_cast<size_t>(total);
}

class BytesGenerator : public xsql::Generator<ByteRow> {
  ByteOrder order_;
  ByteBounds bounds_;
  bool started_ = false;
  ea_t current_ea_ = BADADDR;
  mutable ByteRow row_{BADADDR};

  ea_t first_ascending() const {
    ea_t start = bounds_.has_lower ? bounds_.lower : inf_get_min_ea();
    if (start == BADADDR)
      return BADADDR;
    if (bounds_.has_lower && !bounds_.lower_inclusive) {
      if (start == BADADDR - 1)
        return BADADDR;
      ++start;
    }
    return next_mapped_at_or_after(start);
  }

  ea_t first_descending() const {
    if (get_segm_qty() <= 0)
      return BADADDR;

    ea_t start = BADADDR;
    if (bounds_.has_upper) {
      start = bounds_.upper;
      if (!bounds_.upper_inclusive) {
        if (start == 0)
          return BADADDR;
        --start;
      }
    } else {
      segment_t *seg = get_last_seg();
      if (!seg || seg->end_ea <= seg->start_ea)
        return BADADDR;
      start = seg->end_ea - 1;
    }
    return prev_mapped_at_or_before(start);
  }

  ea_t next_mapped_at_or_after(ea_t start) const {
    segment_t *seg = getseg(start);
    if (!seg)
      seg = get_next_seg(start);

    while (seg) {
      ea_t ea = start > seg->start_ea ? start : seg->start_ea;
      while (ea < seg->end_ea) {
        if (byte_beyond_upper(ea, bounds_))
          return BADADDR;
        if (byte_within_bounds(ea, bounds_) && is_mapped_byte_address(ea))
          return ea;
        if (ea == BADADDR - 1)
          return BADADDR;
        ++ea;
      }

      seg = get_next_seg(seg->start_ea);
      if (seg)
        start = seg->start_ea;
    }
    return BADADDR;
  }

  ea_t prev_mapped_at_or_before(ea_t start) const {
    segment_t *seg = getseg(start);
    if (!seg)
      seg = get_prev_seg(start);

    while (seg) {
      if (seg->end_ea <= seg->start_ea) {
        seg = get_prev_seg(seg->start_ea);
        continue;
      }

      ea_t ea = start < seg->end_ea ? start : seg->end_ea - 1;
      while (true) {
        if (byte_below_lower(ea, bounds_))
          return BADADDR;
        if (byte_within_bounds(ea, bounds_) && is_mapped_byte_address(ea))
          return ea;
        if (ea == seg->start_ea || ea == 0)
          break;
        --ea;
      }

      if (seg->start_ea == 0)
        return BADADDR;
      seg = get_prev_seg(seg->start_ea);
      if (seg && seg->end_ea > seg->start_ea)
        start = seg->end_ea - 1;
    }
    return BADADDR;
  }

public:
  BytesGenerator(ByteOrder order, ByteBounds bounds)
      : order_(order), bounds_(bounds) {}

  bool next() override {
    ea_t next_ea = BADADDR;
    if (!started_) {
      started_ = true;
      next_ea =
          order_ == ByteOrder::Asc ? first_ascending() : first_descending();
    } else if (order_ == ByteOrder::Asc) {
      if (current_ea_ == BADADDR - 1)
        return false;
      next_ea = next_mapped_at_or_after(current_ea_ + 1);
    } else {
      if (current_ea_ == 0)
        return false;
      next_ea = prev_mapped_at_or_before(current_ea_ - 1);
    }

    if (!byte_within_bounds(next_ea, bounds_)) {
      current_ea_ = BADADDR;
      return false;
    }

    current_ea_ = next_ea;
    row_.ea = current_ea_;
    return true;
  }

  const ByteRow &current() const override { return row_; }

  int64_t rowid() const override { return static_cast<int64_t>(current_ea_); }
};

void apply_byte_constraint(ByteBounds &bounds,
                           const xsql::GeneratorConstraintArg &arg) {
  switch (arg.op) {
  case xsql::ConstraintOp::Eq:
  {
    const ea_t ea = normalize_sql_ea(arg.value.as_int64());
    tighten_byte_lower_bound(bounds, ea, true);
    tighten_byte_upper_bound(bounds, ea, true);
    break;
  }
  case xsql::ConstraintOp::Gt:
  {
    const ea_t ea = normalize_sql_ea(arg.value.as_int64());
    tighten_byte_lower_bound(bounds, ea, false);
    break;
  }
  case xsql::ConstraintOp::Ge:
  {
    const ea_t ea = normalize_sql_ea(arg.value.as_int64());
    tighten_byte_lower_bound(bounds, ea, true);
    break;
  }
  case xsql::ConstraintOp::Lt:
  {
    const ea_t ea = normalize_sql_ea(arg.value.as_int64());
    tighten_byte_upper_bound(bounds, ea, false);
    break;
  }
  case xsql::ConstraintOp::Le:
  {
    const ea_t ea = normalize_sql_ea(arg.value.as_int64());
    tighten_byte_upper_bound(bounds, ea, true);
    break;
  }
  case xsql::ConstraintOp::Like:
    xsql::set_vtab_error(
        "bytes: internal error: LIKE constraint routed to numeric addr bounds");
    break;
  }
}

std::unique_ptr<xsql::Generator<ByteRow>>
make_bytes_generator(ByteOrder order,
                     const std::vector<xsql::GeneratorConstraintArg> &args) {
  ByteBounds bounds;
  for (const auto &arg : args) {
    apply_byte_constraint(bounds, arg);
  }
  return std::make_unique<BytesGenerator>(order, bounds);
}

bool byte_is_patched(ea_t ea) {
  return get_byte(ea) != static_cast<uchar>(get_original_byte(ea));
}

// idaapi callback for visit_patched_bytes: collect patched addresses.
int idaapi collect_patched_ea(ea_t ea, qoff64_t, uint64, uint64, void *ud) {
  auto *vec = static_cast<std::vector<ea_t> *>(ud);
  vec->push_back(ea);
  return 0; // continue
}

// Generator backing `bytes WHERE is_patched = <v>`. For v == 1 it enumerates
// only patched locations via visit_patched_bytes() (O(#patches)); for v == 0 it
// scans mapped bytes yielding the unpatched ones; any other value yields none.
// The query planner omits the is_patched constraint (omit=1), so this generator
// must return exactly the matching rows.
class IsPatchedGenerator : public xsql::Generator<ByteRow> {
  int want_;
  std::vector<ea_t> patched_;
  size_t pidx_ = 0;
  BytesGenerator scan_{ByteOrder::Asc, ByteBounds{}};
  mutable ByteRow row_{BADADDR};

public:
  explicit IsPatchedGenerator(int want) : want_(want) {
    if (want_ == 1) {
      visit_patched_bytes(0, BADADDR, collect_patched_ea, &patched_);
    }
  }

  bool next() override {
    if (want_ == 1) {
      while (pidx_ < patched_.size()) {
        const ea_t ea = patched_[pidx_++];
        if (is_mapped_byte_address(ea) && byte_is_patched(ea)) {
          row_.ea = ea;
          return true;
        }
      }
      return false;
    }
    if (want_ == 0) {
      while (scan_.next()) {
        const ea_t ea = scan_.current().ea;
        if (!byte_is_patched(ea)) {
          row_.ea = ea;
          return true;
        }
      }
      return false;
    }
    return false;
  }

  const ByteRow &current() const override { return row_; }
  int64_t rowid() const override { return static_cast<int64_t>(row_.ea); }
};

// Column indices for the bytes table — used by constraint filters that
// dispatch on column_index. Keep in sync with define_bytes() column order.
enum BytesColumn {
  kBytesEa = 0,
  kBytesValue = 1,
  kBytesWord = 2,
  kBytesDword = 3,
  kBytesQword = 4,
  kBytesOriginalValue = 5,
  kBytesIsPatched = 6,
  kBytesFpos = 7,
  kBytesStartEa = 8,
  kBytesN = 9,
};

// Generator backing `bytes WHERE start_addr = X AND n = N`. Yields exactly N
// consecutive ea values starting at X in ascending order. Does not skip
// unmapped addresses; the `value` column delegates to get_byte(), which
// returns whatever the SDK yields at unmapped positions. Stops early if
// address arithmetic would overflow.
class BytesNGenerator : public xsql::Generator<ByteRow> {
  ea_t start_ea_;
  int64_t remaining_;
  bool started_ = false;
  ea_t current_ea_ = BADADDR;
  mutable ByteRow row_{BADADDR};

public:
  BytesNGenerator(ea_t start, int64_t n)
      : start_ea_(start), remaining_(n < 0 ? 0 : n) {}

  bool next() override {
    if (remaining_ <= 0)
      return false;

    if (!started_) {
      started_ = true;
      current_ea_ = start_ea_;
    } else {
      if (current_ea_ == BADADDR || current_ea_ >= BADADDR - 1)
        return false;
      ++current_ea_;
    }

    --remaining_;
    row_.ea = current_ea_;
    return true;
  }

  const ByteRow &current() const override { return row_; }
  int64_t rowid() const override { return static_cast<int64_t>(current_ea_); }
};

std::unique_ptr<xsql::Generator<ByteRow>>
make_bytes_n_generator(const std::vector<xsql::GeneratorConstraintArg> &args) {
  ea_t start = BADADDR;
  int64_t n = 0;
  for (const auto &arg : args) {
    if (arg.op != xsql::ConstraintOp::Eq)
      continue;
    if (arg.column_index == kBytesStartEa) {
      start = normalize_sql_ea(arg.value.as_int64());
    } else if (arg.column_index == kBytesN) {
      n = arg.value.as_int64();
    }
  }
  return std::make_unique<BytesNGenerator>(start, n);
}

} // namespace

GeneratorTableDef<ByteRow> define_bytes() {
  return generator_table<ByteRow>("bytes")
      .estimate_rows([]() -> size_t { return estimate_mapped_byte_rows(); })
      .generator([]() -> std::unique_ptr<xsql::Generator<ByteRow>> {
        return std::make_unique<BytesGenerator>(ByteOrder::Asc, ByteBounds{});
      })
      .column_int64("addr",
                    [](const ByteRow &row) -> int64_t {
                      return static_cast<int64_t>(row.ea);
                    })
      .column_int_rw(
          "value", [](const ByteRow &row) -> int { return get_byte(row.ea); },
          [](ByteRow &row, int val) -> bool {
            if (!is_mapped_byte_address(row.ea)) {
              xsql::set_vtab_error("bytes: address is not mapped: " +
                                   idasql::format_ea_hex(row.ea));
              return false;
            }
            if (val < 0 || val > 0xFF) {
              xsql::set_vtab_error("bytes.value: out of range (0..0xFF): " +
                                   std::to_string(val));
              return false;
            }
            // patch_byte returns false when the byte already holds this value;
            // treat "already equal" as success so re-runs / bulk NOP-outs don't
            // abort mid-range.
            if (get_byte(row.ea) == static_cast<uchar>(val))
              return true;
            bool ok = patch_byte(row.ea, static_cast<uint64>(val));
            if (!ok)
              xsql::set_vtab_error("bytes: failed to patch byte at " +
                                   idasql::format_ea_hex(row.ea));
            return ok;
          })
      .column_int_rw(
          "word", [](const ByteRow &row) -> int { return get_word(row.ea); },
          [](ByteRow &row, int val) -> bool {
            if (!is_mapped_byte_address(row.ea)) {
              xsql::set_vtab_error("bytes: address is not mapped: " +
                                   idasql::format_ea_hex(row.ea));
              return false;
            }
            if (val < 0 || val > 0xFFFF) {
              xsql::set_vtab_error("bytes.word: out of range (0..0xFFFF): " +
                                   std::to_string(val));
              return false;
            }
            // patch_word returns false when the word already holds this value;
            // treat "already equal" as success (idempotent re-runs).
            if (get_word(row.ea) == static_cast<ushort>(val))
              return true;
            bool ok = patch_word(row.ea, static_cast<uint64>(val));
            if (!ok)
              xsql::set_vtab_error("bytes: failed to patch word at " +
                                   idasql::format_ea_hex(row.ea));
            return ok;
          })
      .column_int64_rw(
          "dword",
          [](const ByteRow &row) -> int64_t {
            return static_cast<int64_t>(get_dword(row.ea));
          },
          [](ByteRow &row, int64_t val) -> bool {
            if (!is_mapped_byte_address(row.ea)) {
              xsql::set_vtab_error("bytes: address is not mapped: " +
                                   idasql::format_ea_hex(row.ea));
              return false;
            }
            if (val < 0 || val > 0xFFFFFFFFLL) {
              xsql::set_vtab_error(
                  "bytes.dword: out of range (0..0xFFFFFFFF): " +
                  std::to_string(val));
              return false;
            }
            // patch_dword returns false when the dword already holds this value;
            // treat "already equal" as success (idempotent re-runs).
            if (get_dword(row.ea) == static_cast<uint32>(val))
              return true;
            bool ok = patch_dword(row.ea, static_cast<uint64>(val));
            if (!ok)
              xsql::set_vtab_error("bytes: failed to patch dword at " +
                                   idasql::format_ea_hex(row.ea));
            return ok;
          })
      .column_int64_rw(
          "qword",
          [](const ByteRow &row) -> int64_t {
            return static_cast<int64_t>(get_qword(row.ea));
          },
          [](ByteRow &row, int64_t val) -> bool {
            if (!is_mapped_byte_address(row.ea)) {
              xsql::set_vtab_error("bytes: address is not mapped: " +
                                   idasql::format_ea_hex(row.ea));
              return false;
            }
            // qword spans the full 64-bit column width, so any int64 bit
            // pattern is in range. patch_qword returns false when the qword
            // already holds this value; treat "already equal" as success
            // (idempotent re-runs).
            if (get_qword(row.ea) == static_cast<uint64>(val))
              return true;
            bool ok = patch_qword(row.ea, static_cast<uint64>(val));
            if (!ok)
              xsql::set_vtab_error("bytes: failed to patch qword at " +
                                   idasql::format_ea_hex(row.ea));
            return ok;
          })
      .column_int("original_value",
                  [](const ByteRow &row) -> int {
                    return static_cast<int>(get_original_byte(row.ea));
                  })
      .column_int("is_patched",
                  [](const ByteRow &row) -> int {
                    return (get_byte(row.ea) !=
                            static_cast<uchar>(get_original_byte(row.ea)))
                               ? 1
                               : 0;
                  })
      .column("fpos", xsql::ColumnType::Integer,
              [](xsql::FunctionContext &ctx, const ByteRow &row) {
                const qoff64_t fpos = get_fileregion_offset(row.ea);
                if (fpos < 0)
                  ctx.result_null();
                else
                  ctx.result_int64(static_cast<int64_t>(fpos));
      })
      // Hidden input columns for the bounded read: `WHERE start_addr = X AND
      // n = N` requests exactly N consecutive bytes beginning at X. Both
      // columns are HIDDEN (input-only, not in `SELECT *`). Using a dedicated
      // `start_ea` rather than consuming the visible `ea` keeps any user
      // predicate on `ea` enforceable by SQLite, so joins like
      // `ON b.ea = t.target AND b.start_ea = t.target AND b.n = 4` stay
      // correct.
      .hidden_column_int64("start_addr")
      .hidden_column_int("n")
      .row_lookup([](ByteRow &row, int64_t ea_val) -> bool {
        const ea_t ea = normalize_sql_ea(ea_val);
        if (!is_mapped_byte_address(ea))
          return false;
        row.ea = ea;
        return true;
      })
      // Bounded read: `WHERE start_addr = X AND n = N` yields N consecutive
      // bytes starting at X. The generator yields in ascending ea order, so
      // ORDER BY ea is free.
      .constraint_filter(
          {xsql::required_eq("start_addr", ""), xsql::required_eq("n", "")},
          make_bytes_n_generator,
          1.0, 1.0)
      .order_by_consumed("addr")
      .constraint_filter(
          {xsql::required_eq("addr", "")},
          [](const std::vector<xsql::GeneratorConstraintArg> &args)
              -> std::unique_ptr<xsql::Generator<ByteRow>> {
            return make_bytes_generator(ByteOrder::Asc, args);
          },
          1.0, 1.0)
      .constraint_filter(
          {xsql::optional_ge("addr"), xsql::optional_gt("addr"),
           xsql::optional_lt("addr"), xsql::optional_le("addr")},
          [](const std::vector<xsql::GeneratorConstraintArg> &args)
              -> std::unique_ptr<xsql::Generator<ByteRow>> {
            return make_bytes_generator(ByteOrder::Asc, args);
          },
          10.0, 100.0)
      .order_by_consumed("addr")
      .constraint_filter(
          {xsql::optional_ge("addr"), xsql::optional_gt("addr"),
           xsql::optional_lt("addr"), xsql::optional_le("addr")},
          [](const std::vector<xsql::GeneratorConstraintArg> &args)
              -> std::unique_ptr<xsql::Generator<ByteRow>> {
            return make_bytes_generator(ByteOrder::Desc, args);
          },
          10.0, 100.0)
      .order_by_consumed("addr", true)
      // Fast patch enumeration: `WHERE is_patched = 1` walks the patch list via
      // visit_patched_bytes() (O(#patches)) instead of scanning every mapped
      // byte. Replaces the former standalone patched_bytes table.
      .constraint_filter(
          {xsql::required_eq("is_patched", "")},
          [](const std::vector<xsql::GeneratorConstraintArg> &args)
              -> std::unique_ptr<xsql::Generator<ByteRow>> {
            int want = 1;
            if (!args.empty())
              want = static_cast<int>(args.front().value.as_int64());
            return std::make_unique<IsPatchedGenerator>(want);
          },
          1.0, 64.0)
      // DELETE reverts a patch (revert_byte). Deleting an unpatched byte is a
      // harmless no-op. `DELETE FROM bytes WHERE is_patched = 1` reverts all.
      .deletable([](ByteRow &row) -> bool {
        if (!is_mapped_byte_address(row.ea)) {
          xsql::set_vtab_error("bytes: address is not mapped: " +
                               idasql::format_ea_hex(row.ea));
          return false;
        }
        if (!byte_is_patched(row.ea))
          return true; // nothing to revert
        bool ok = revert_byte(row.ea);
        if (!ok)
          xsql::set_vtab_error("bytes: failed to revert byte at " +
                               idasql::format_ea_hex(row.ea));
        return ok;
      })
      .build();
}

} // namespace memory
} // namespace idasql
