// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "memory_bytes.hpp"

#include <netnode.hpp>
#include <sqlite3.h>

#include <algorithm>
#include <cstring>
#include <optional>

using namespace idasql::core;

namespace idasql {
namespace memory {

// ============================================================================
// BYTES Table - Raw mapped bytes with patch support
// ============================================================================

namespace {

enum class ByteOrder { Asc, Desc };

bool is_mapped_byte_address(ea_t ea) {
  return ea != BADADDR && is_mapped(ea);
}

bool is_mapped_byte_range(ea_t ea, size_t width) {
  if (width == 0 || ea == BADADDR || ea > BADADDR - static_cast<ea_t>(width))
    return false;
  for (size_t i = 0; i < width; ++i) {
    if (!is_mapped_byte_address(ea + static_cast<ea_t>(i)))
      return false;
  }
  return true;
}

bool is_loaded_byte_range(ea_t ea, size_t width) {
  if (!is_mapped_byte_range(ea, width))
    return false;
  for (size_t i = 0; i < width; ++i) {
    if (!is_loaded(ea + static_cast<ea_t>(i)))
      return false;
  }
  return true;
}

// IDA's revert_byte() restores the saved original byte value, but a patch made
// against an unloaded byte has no initialized value to restore. Persist that
// extra bit of state in the IDB so DELETE can faithfully return BSS (and other
// sparse mapped bytes) to SQL NULL even after saving and reopening the
// database.
constexpr const char *kUnloadedPatchNode = "$ idasql bytes originally unloaded";

netnode unloaded_patch_node(bool create) {
  return netnode(kUnloadedPatchNode, 0, create);
}

void forget_unloaded_patch(ea_t ea) {
  netnode node = unloaded_patch_node(false);
  if (node != BADNODE)
    node.altdel_ea(ea);
}

bool was_unloaded_before_patch(ea_t ea) {
  netnode node = unloaded_patch_node(false);
  return node != BADNODE && node.altval_ea(ea) != 0;
}

bool remember_unloaded_before_patch(ea_t ea, size_t width) {
  netnode node;
  bool opened = false;
  for (size_t i = 0; i < width; ++i) {
    const ea_t byte_ea = ea + static_cast<ea_t>(i);
    if (is_loaded(byte_ea))
      continue;
    if (!opened) {
      node = unloaded_patch_node(true);
      opened = true;
      if (node == BADNODE) {
        xsql::set_vtab_error(
            "bytes: failed to record unloaded-byte patch state");
        return false;
      }
    }
    if (!node.altset_ea(byte_ea, 1)) {
      xsql::set_vtab_error(
          "bytes: failed to record unloaded-byte patch state at " +
          idasql::format_ea_hex(byte_ea));
      for (size_t rollback = 0; rollback <= i; ++rollback) {
        const ea_t rollback_ea = ea + static_cast<ea_t>(rollback);
        if (!is_loaded(rollback_ea))
          forget_unloaded_patch(rollback_ea);
      }
      return false;
    }
  }
  return true;
}

void forget_markers_for_still_unloaded_bytes(ea_t ea, size_t width) {
  for (size_t i = 0; i < width; ++i) {
    const ea_t byte_ea = ea + static_cast<ea_t>(i);
    if (!is_loaded(byte_ea))
      forget_unloaded_patch(byte_ea);
  }
}

// The integer a bytes setter writes, or nullopt with the vtab error set. Exact like a
// native INTEGER comparison (xsql::exact_int64): text, a real or a blob that is not
// exactly an integer is refused instead of truncating to 0 or saturating.
std::optional<int64_t> setter_int64(xsql::FunctionArg arg, const char *column,
                                    const char *noun) {
  if (arg.is_null()) {
    xsql::set_vtab_error(std::string("bytes.") + column + ": NULL is not a " +
                         noun + " value");
    return std::nullopt;
  }
  if (arg.type() != SQLITE_BLOB) {
    if (const auto v = xsql::exact_int64(arg))
      return v;
  }
  const char *got = arg.type() == SQLITE_BLOB    ? "a blob"
                    : arg.type() == SQLITE_FLOAT ? "a non-integral or out-of-range real"
                                                 : "non-integer text";
  xsql::set_vtab_error(
      std::string("bytes.") + column +
      ": expected an integer (e.g. 144 or 0x90), got " + got +
      (std::strcmp(column, "qword") == 0
           ? "; write qwords above 0x7FFFFFFFFFFFFFFF as hex "
             "(0xFFFFFFFFFFFFFFFF) or signed (-1)"
           : ""));
  return std::nullopt;
}

size_t estimate_mapped_byte_rows() {
  uint64 total = 0;
  for (int i = 0; i < get_segm_qty(); ++i) {
    idasql_segment_info_t seg;
    if (!idasql_segment_info(idasql_segment_ea_by_num(i), &seg)
        || seg.end_ea <= seg.start_ea)
      continue;
    total += static_cast<uint64>(seg.end_ea - seg.start_ea);
    if (total > static_cast<uint64>(std::numeric_limits<size_t>::max()))
      return std::numeric_limits<size_t>::max();
  }
  return static_cast<size_t>(total);
}

// Yields the mapped bytes of an addr window in SQL order: the window is walked
// as its unsigned spans (xsql::Int64KeyRange::unsigned_spans), because an
// address >= 2^63 is a negative INTEGER and sorts first. Within a span the walk
// is segment-driven, upward (Asc) or downward (Desc). The unconstrained scan
// walks every address the same way.
class BytesGenerator : public xsql::Generator<ByteRow> {
  ByteOrder order_;
  std::vector<xsql::U64Span> spans_;
  size_t span_ = 0;
  bool in_span_ = false;
  ea_t current_ea_ = BADADDR;
  mutable ByteRow row_{BADADDR};

  // The first mapped byte at or after `start` and at or below `hi`.
  static ea_t next_mapped_at_or_after(ea_t start, ea_t hi) {
    idasql_segment_info_t seg;
    bool have_seg = idasql_segment_info(start, &seg)
                    || idasql_segment_info(idasql_next_segment_ea(start), &seg);

    while (have_seg) {
      if (seg.start_ea > hi)
        return BADADDR;
      for (ea_t ea = start > seg.start_ea ? start : seg.start_ea;
           ea < seg.end_ea; ++ea) {
        if (ea > hi)
          return BADADDR;
        if (is_mapped_byte_address(ea))
          return ea;
      }
      have_seg = idasql_segment_info(idasql_next_segment_ea(seg.start_ea), &seg);
    }
    return BADADDR;
  }

  // The last mapped byte at or before `start` and at or above `lo`. `start`
  // may be BADADDR: the segment before BADADDR is the last segment.
  static ea_t prev_mapped_at_or_before(ea_t start, ea_t lo) {
    idasql_segment_info_t seg;
    bool have_seg = idasql_segment_info(start, &seg)
                    || idasql_segment_info(idasql_prev_segment_ea(start), &seg);

    while (have_seg) {
      if (seg.end_ea > seg.start_ea) {
        if (seg.end_ea - 1 < lo)
          return BADADDR;
        ea_t ea = start < seg.end_ea ? start : seg.end_ea - 1;
        while (true) {
          if (ea < lo)
            return BADADDR;
          if (is_mapped_byte_address(ea))
            return ea;
          if (ea == seg.start_ea)
            break;
          --ea;
        }
      }
      if (seg.start_ea == 0)
        return BADADDR;
      have_seg = idasql_segment_info(idasql_prev_segment_ea(seg.start_ea), &seg);
    }
    return BADADDR;
  }

  ea_t step(const xsql::U64Span &span) const {
    const ea_t lo = static_cast<ea_t>(span.lo);
    const ea_t hi = static_cast<ea_t>(span.hi);
    if (order_ == ByteOrder::Asc) {
      if (!in_span_)
        return next_mapped_at_or_after(lo, hi);
      return current_ea_ >= hi ? BADADDR
                               : next_mapped_at_or_after(current_ea_ + 1, hi);
    }
    if (!in_span_)
      return prev_mapped_at_or_before(hi, lo);
    return current_ea_ <= lo ? BADADDR
                             : prev_mapped_at_or_before(current_ea_ - 1, lo);
  }

public:
  BytesGenerator(ByteOrder order, const xsql::Int64KeyRange &range)
      : order_(order), spans_(range.unsigned_spans(order == ByteOrder::Desc)) {}

  bool next() override {
    while (span_ < spans_.size()) {
      const ea_t ea = step(spans_[span_]);
      in_span_ = true;
      if (ea != BADADDR) {
        current_ea_ = ea;
        row_.ea = ea;
        return true;
      }
      ++span_;
      in_span_ = false;
    }
    current_ea_ = BADADDR;
    return false;
  }

  const ByteRow &current() const override { return row_; }

  int64_t rowid() const override { return static_cast<int64_t>(current_ea_); }
};

// The addr constraints are omit=1, so they are compared the way SQLite
// compares the INTEGER addr column (xsql::Int64KeyRange): `addr = 4096.5` and
// `addr = NULL` match nothing, `addr >= 4095.5` starts at 4096.
std::unique_ptr<xsql::Generator<ByteRow>>
make_bytes_generator(ByteOrder order,
                     const std::vector<xsql::GeneratorConstraintArg> &args) {
  xsql::Int64KeyRange range;
  for (const auto &arg : args) {
    if (arg.op == xsql::ConstraintOp::Like) {
      xsql::set_vtab_error(
          "bytes: internal error: LIKE constraint routed to numeric addr bounds");
      return nullptr;
    }
    range.constrain(arg.op, arg.value);
  }
  if (range.empty())
    return nullptr;
  return std::make_unique<BytesGenerator>(order, range);
}

bool byte_is_patched(ea_t ea) {
  // A zero written into an originally-unloaded byte has the same numeric value
  // as IDA's synthetic original zero, but it is still a real patch: it changes
  // the byte from SQL NULL/uninitialized to an initialized zero. Preserve that
  // semantic distinction through the marker recorded by the setter -- while the
  // byte is still loaded: a patch reverted outside idasql (IDA's Patched bytes
  // window, revert_byte) leaves the byte unloaded and the marker stale.
  if (was_unloaded_before_patch(ea))
    return is_loaded(ea);
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
  BytesGenerator scan_{ByteOrder::Asc, xsql::Int64KeyRange{}};
  mutable ByteRow row_{BADADDR};

public:
  explicit IsPatchedGenerator(int want) : want_(want) {
    if (want_ == 1) {
      visit_patched_bytes(0, BADADDR, collect_patched_ea, &patched_);
      // A zero written into an unloaded byte equals its synthetic original, so
      // IDA may not list it as patched; the setter's marker does. (Markers are
      // stored ea-mapped, hence node2ea.)
      netnode node = unloaded_patch_node(false);
      if (node != BADNODE) {
        for (nodeidx_t idx = node.altfirst(); idx != BADNODE; idx = node.altnext(idx))
          patched_.push_back(node2ea(idx));
      }
      std::sort(patched_.begin(), patched_.end());
      patched_.erase(std::unique(patched_.begin(), patched_.end()), patched_.end());
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
  kBytesIsInitialized = 7,
  kBytesFpos = 8,
  kBytesStartEa = 9,
  kBytesN = 10,
};

// Generator backing `bytes WHERE start_addr = X AND n = N`: the N consecutive
// addresses X, X+1, ... (unsigned), stopping before BADADDR, which is never an
// address. Does not skip unmapped addresses; `value` is NULL wherever the SDK
// reports the byte as uninitialized. The plan claims ORDER BY addr, so the rows
// come out in SQL order: when the run crosses 2^63 (0x7FFF...FFFF ->
// 0x8000...0000), the part at or above 2^63 -- negative INTEGERs -- comes first.
class BytesNGenerator : public xsql::Generator<ByteRow> {
  // At most two runs, each inclusive, walked upward in this order.
  std::vector<std::pair<ea_t, ea_t>> runs_;
  size_t run_ = 0;
  bool in_run_ = false;
  ea_t current_ea_ = BADADDR;
  mutable ByteRow row_{BADADDR};

public:
  BytesNGenerator(ea_t start, int64_t n) {
    if (n <= 0 || start == BADADDR)
      return;
    // The last address the run reaches, saturated below BADADDR.
    const ea_t room = (BADADDR - 1) - start;
    const ea_t last = static_cast<uint64_t>(n - 1) > static_cast<uint64_t>(room)
                          ? BADADDR - 1
                          : start + static_cast<ea_t>(n - 1);
    const ea_t seam = static_cast<ea_t>(uint64_t{1} << 63);
    if (start < seam && last >= seam) {
      runs_.emplace_back(seam, last);
      runs_.emplace_back(start, seam - 1);
    } else {
      runs_.emplace_back(start, last);
    }
  }

  bool next() override {
    while (run_ < runs_.size()) {
      const auto &[first, last] = runs_[run_];
      if (!in_run_) {
        in_run_ = true;
        current_ea_ = first;
      } else if (current_ea_ < last) {
        ++current_ea_;
      } else {
        ++run_;
        in_run_ = false;
        continue;
      }
      row_.ea = current_ea_;
      return true;
    }
    return false;
  }

  const ByteRow &current() const override { return row_; }
  int64_t rowid() const override { return static_cast<int64_t>(current_ea_); }
};

std::unique_ptr<xsql::Generator<ByteRow>>
make_bytes_n_generator(const std::vector<xsql::GeneratorConstraintArg> &args) {
  // Both inputs are omit=1: a value no integer equals (NULL, 4096.5, 'a')
  // requests nothing, as a native INTEGER column would match nothing.
  ea_t start = BADADDR;
  int64_t n = 0;
  for (const auto &arg : args) {
    if (arg.op != xsql::ConstraintOp::Eq)
      continue;
    const std::optional<int64_t> value = xsql::exact_int64(arg.value);
    if (!value)
      return nullptr;
    if (arg.column_index == kBytesStartEa) {
      start = normalize_sql_ea(*value);
    } else if (arg.column_index == kBytesN) {
      n = *value;
    }
  }
  return std::make_unique<BytesNGenerator>(start, n);
}

} // namespace

GeneratorTableDef<ByteRow> define_bytes() {
  return generator_table<ByteRow>("bytes")
      .estimate_rows([]() -> size_t { return estimate_mapped_byte_rows(); })
      .generator([]() -> std::unique_ptr<xsql::Generator<ByteRow>> {
        return std::make_unique<BytesGenerator>(ByteOrder::Asc,
                                                xsql::Int64KeyRange{});
      })
      .column_int64("addr",
                    [](const ByteRow &row) -> int64_t {
                      return static_cast<int64_t>(row.ea);
                    })
      // Canonical byte surface: value is NULL for a mapped-but-uninitialized byte
      // (e.g. BSS), preserving the "unknown" vs "real 0" distinction (the ratified
      // cross-tool decision; matches ghidrasql/bnsql, with is_initialized carrying
      // the 0/1 flag). The byte-patch setter still writes any mapped byte.
      .column_rw(
          "value", xsql::ColumnType::Integer,
          [](xsql::FunctionContext &ctx, const ByteRow &row) {
            if (is_loaded(row.ea))
              ctx.result_int64(static_cast<int64_t>(get_byte(row.ea)));
            else
              ctx.result_null();
          },
          [](ByteRow &row, xsql::FunctionArg arg) -> bool {
            const auto exact = setter_int64(arg, "value", "byte");
            if (!exact)
              return false;
            const int64_t value = *exact;
            if (!is_mapped_byte_address(row.ea)) {
              xsql::set_vtab_error("bytes: address is not mapped: " +
                                   idasql::format_ea_hex(row.ea));
              return false;
            }
            if (value < 0 || value > 0xFF) {
              xsql::set_vtab_error("bytes.value: out of range (0..0xFF): " +
                                   std::to_string(value));
              return false;
            }
            const auto val = static_cast<uchar>(value);
            // patch_byte returns false when the byte already holds this value;
            // treat "already equal" as success so re-runs / bulk NOP-outs don't
            // abort mid-range. An unloaded byte that reads as zero is NOT
            // already equal: writing it must initialize the byte.
            if (is_loaded(row.ea) && get_byte(row.ea) == val)
              return true;
            if (!remember_unloaded_before_patch(row.ea, 1))
              return false;
            bool ok = patch_byte(row.ea, static_cast<uint64>(value));
            if (!ok) {
              forget_markers_for_still_unloaded_bytes(row.ea, 1);
              xsql::set_vtab_error("bytes: failed to patch byte at " +
                                   idasql::format_ea_hex(row.ea));
            }
            return ok;
          })
      .column_int_rw(
          "word", [](const ByteRow &row) -> int { return get_word(row.ea); },
          [](ByteRow &row, xsql::FunctionArg arg) -> bool {
            const auto exact = setter_int64(arg, "word", "word");
            if (!exact)
              return false;
            const int64_t value = *exact;
            if (!is_mapped_byte_range(row.ea, 2)) {
              xsql::set_vtab_error("bytes: word range is not mapped at " +
                                   idasql::format_ea_hex(row.ea));
              return false;
            }
            if (value < 0 || value > 0xFFFF) {
              xsql::set_vtab_error("bytes.word: out of range (0..0xFFFF): " +
                                   std::to_string(value));
              return false;
            }
            // patch_word returns false when the word already holds this value;
            // treat "already equal" as success (idempotent re-runs).
            if (is_loaded_byte_range(row.ea, 2) &&
                get_word(row.ea) == static_cast<ushort>(value))
              return true;
            if (!remember_unloaded_before_patch(row.ea, 2))
              return false;
            bool ok = patch_word(row.ea, static_cast<uint64>(value));
            if (!ok) {
              forget_markers_for_still_unloaded_bytes(row.ea, 2);
              xsql::set_vtab_error("bytes: failed to patch word at " +
                                   idasql::format_ea_hex(row.ea));
            }
            return ok;
          })
      .column_int64_rw(
          "dword",
          [](const ByteRow &row) -> int64_t {
            return static_cast<int64_t>(get_dword(row.ea));
          },
          [](ByteRow &row, xsql::FunctionArg arg) -> bool {
            const auto exact = setter_int64(arg, "dword", "dword");
            if (!exact)
              return false;
            const int64_t value = *exact;
            if (!is_mapped_byte_range(row.ea, 4)) {
              xsql::set_vtab_error("bytes: dword range is not mapped at " +
                                   idasql::format_ea_hex(row.ea));
              return false;
            }
            if (value < 0 || value > 0xFFFFFFFFLL) {
              xsql::set_vtab_error(
                  "bytes.dword: out of range (0..0xFFFFFFFF): " +
                  std::to_string(value));
              return false;
            }
            // patch_dword returns false when the dword already holds this value;
            // treat "already equal" as success (idempotent re-runs).
            if (is_loaded_byte_range(row.ea, 4) &&
                get_dword(row.ea) == static_cast<uint32>(value))
              return true;
            if (!remember_unloaded_before_patch(row.ea, 4))
              return false;
            bool ok = patch_dword(row.ea, static_cast<uint64>(value));
            if (!ok) {
              forget_markers_for_still_unloaded_bytes(row.ea, 4);
              xsql::set_vtab_error("bytes: failed to patch dword at " +
                                   idasql::format_ea_hex(row.ea));
            }
            return ok;
          })
      .column_int64_rw(
          "qword",
          [](const ByteRow &row) -> int64_t {
            return static_cast<int64_t>(get_qword(row.ea));
          },
          [](ByteRow &row, xsql::FunctionArg arg) -> bool {
            const auto exact = setter_int64(arg, "qword", "qword");
            if (!exact)
              return false;
            const int64_t value = *exact;
            if (!is_mapped_byte_range(row.ea, 8)) {
              xsql::set_vtab_error("bytes: qword range is not mapped at " +
                                   idasql::format_ea_hex(row.ea));
              return false;
            }
            // qword spans the full 64-bit column width, so any int64 bit
            // pattern is in range (-1 is 0xFFFFFFFFFFFFFFFF). patch_qword returns false when the qword
            // already holds this value; treat "already equal" as success
            // (idempotent re-runs).
            if (is_loaded_byte_range(row.ea, 8) &&
                get_qword(row.ea) == static_cast<uint64>(value))
              return true;
            if (!remember_unloaded_before_patch(row.ea, 8))
              return false;
            bool ok = patch_qword(row.ea, static_cast<uint64>(value));
            if (!ok) {
              forget_markers_for_still_unloaded_bytes(row.ea, 8);
              xsql::set_vtab_error("bytes: failed to patch qword at " +
                                   idasql::format_ea_hex(row.ea));
            }
            return ok;
          })
      .column_int("original_value",
                  [](const ByteRow &row) -> int {
                    return static_cast<int>(get_original_byte(row.ea));
                  })
      .column_int("is_patched",
                  [](const ByteRow &row) -> int {
                    return byte_is_patched(row.ea) ? 1 : 0;
                  })
      // Canonical byte-surface flag: 1 when the byte is initialized (loaded from
      // the image), 0 for a mapped-but-uninitialized byte (e.g. BSS). Matches
      // ghidrasql's is_initialized so the cross-tool byte surface is portable.
      .column_int("is_initialized",
                  [](const ByteRow &row) -> int {
                    return is_loaded(row.ea) ? 1 : 0;
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
      // bytes starting at X. The generator yields them in SQL order (the part
      // at or above 2^63 first when the run crosses it), so ORDER BY addr is
      // free.
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
            // omit=1: `is_patched = 1.5` or `= NULL` matches no byte (a
            // truncating read turned them into 1 and 0).
            const std::optional<int64_t> want =
                args.empty() ? std::optional<int64_t>(1)
                             : xsql::exact_int64(args.front().value);
            if (!want || (*want != 0 && *want != 1))
              return nullptr;
            return std::make_unique<IsPatchedGenerator>(static_cast<int>(*want));
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
        if (was_unloaded_before_patch(row.ea)) {
          // A marker can outlive an out-of-band revert. Either way, remove any
          // patch record, drop the synthetic value, and clear our metadata.
          (void)revert_byte(row.ea);
          del_value(row.ea);
          forget_unloaded_patch(row.ea);
          return true;
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
