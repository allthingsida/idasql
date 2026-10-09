// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "memory_segments.hpp"

#include "address_resolution.hpp"

#include <optional>

using namespace idasql::core;

namespace idasql {
namespace memory {

// ============================================================================
// SEGMENTS Table
// ============================================================================

namespace {

// Multi-column UPDATE hazard guard for the `segments` table.
//
// The `start_addr` setter rebases a segment (move_segment), which re-sorts the
// segment array by start address and can therefore change a segment's ordinal
// index. libxsql's xUpdate applies each column setter in column order against
// the *same* row index, and `start_addr` is column 0 — so in a single statement
// like `UPDATE segments SET start_addr = X, end_addr = Y WHERE ...` the
// `start_addr` rebase can shift the array out from under the later `end_addr`/
// `name`/`class`/`perm` setters, which would otherwise resolve the wrong segment
// by ordinal. We record the rebase and let subsequent setters re-resolve
// the moved segment by its new start address. The guard is reset once per row by
// the table's on_modify hook (fired at the top of each xUpdate).
struct SegRebaseGuard {
  bool   active = false;
  size_t orig_index = 0;
  ea_t   new_start_ea = BADADDR;
};
thread_local SegRebaseGuard g_seg_rebase;

// Multi-ROW rebase guard for the `segments` table.
//
// `segments` is a LIVE table (VTableDef): its scan rowid is the positional
// segment ordinal `i`. A multi-row DELETE needs nothing here: libxsql hands
// delete_row the segment's current ordinal (the scanned ordinal less the rows
// the statement already deleted), which is exactly how del_segm() compacts the
// array. A multi-row rebase UPDATE is different: a move re-sorts the array
// by start address, so a later row's ordinal `i` — captured against the
// pristine scan-time array — can point at a DIFFERENT segment. The setters
// therefore resolve through a snapshot of the pristine ordered list of segment
// start_eas, taken ONCE per statement (lazily, at the first setter, while the
// array is still pristine — SQLite completes the whole scan before issuing any
// VUpdate), by stable start_ea instead of the shifting ordinal `i`. The
// snapshot is invalidated at the top of every scan via the table's .count()
// callback (xFilter → row_count), which is the statement boundary.
struct SegRowSnapshot {
  bool               valid = false;
  std::vector<ea_t>  start_eas;  // start_eas[i] = pristine start_ea of ordinal i
};
thread_local SegRowSnapshot g_seg_rows;

// Invalidate the per-statement snapshot. Called from .count() (once per scan).
inline void reset_segment_row_snapshot() { g_seg_rows.valid = false; }

// Build the snapshot from the current (pristine) segment array on first use.
inline void ensure_segment_row_snapshot() {
  if (g_seg_rows.valid)
    return;
  g_seg_rows.start_eas.clear();
  const int qty = get_segm_qty();
  g_seg_rows.start_eas.reserve(static_cast<size_t>(qty > 0 ? qty : 0));
  for (int k = 0; k < qty; ++k)
    g_seg_rows.start_eas.push_back(idasql_segment_ea_by_num(k));
  g_seg_rows.valid = true;
}

// Resolve the stable start_ea for scan-ordinal `index` from the pristine
// snapshot, so a mutation targets the row identified at scan time even after
// earlier rows in the same statement shifted the live array. BADADDR = unknown.
inline ea_t stable_start_ea_for_index(size_t index) {
  ensure_segment_row_snapshot();
  if (index < g_seg_rows.start_eas.size())
    return g_seg_rows.start_eas[index];
  return BADADDR;
}

// Resolve the start of the segment a setter should act on. First honor a
// same-statement, same-row rebase (start_addr moved this exact ordinal);
// otherwise resolve by the stable scan-time start_ea (position-independent
// across multi-row edits). BADADDR when there is no such segment.
inline ea_t resolve_segment(size_t index) {
  idasql_segment_info_t si;
  if (g_seg_rebase.active && g_seg_rebase.orig_index == index) {
    if (idasql_segment_info(g_seg_rebase.new_start_ea, &si))
      return si.start_ea;
  }
  const ea_t stable_ea = stable_start_ea_for_index(index);
  if (stable_ea != BADADDR && idasql_segment_info(stable_ea, &si))
    return si.start_ea;
  return idasql_segment_ea_by_num(static_cast<int>(index));
}

// Segment number `i` (0..get_segm_qty()-1); false for a bad `i`.
inline bool segment_by_num(size_t i, idasql_segment_info_t *out) {
  return idasql_segment_info(idasql_segment_ea_by_num(static_cast<int>(i)), out);
}

}  // namespace

VTableDef define_segments() {
  return table("segments")
      .row_count([]() {
        // xFilter calls row_count() at the top of every scan -- the statement
        // boundary. Drop any stale per-statement snapshot here so the next
        // multi-row DELETE/UPDATE rebuilds it from the fresh, pristine array.
        reset_segment_row_snapshot();
        return static_cast<size_t>(get_segm_qty());
      })
      // Reset the per-row rebase guard at the top of every modification so a
      // stale rebase from a previous statement can never leak into this one.
      .on_modify([](const std::string &) { g_seg_rebase = SegRebaseGuard{}; })
      // Canonical address columns (writable). `start_addr` rebases the
      // segment (move_segment); `end_addr` resizes it (set_segm_end).
      .column_int64_rw(
          "start_addr",
          // Getter
          [](size_t i) -> int64_t {
            const ea_t start = idasql_segment_ea_by_num(static_cast<int>(i));
            return start != BADADDR ? static_cast<int64_t>(start) : 0;
          },
          // Setter - rebase: move the segment to a new start address.
          [](size_t i, int64_t new_start) -> bool {
            idasql_auto_wait();
            // Resolve by the stable scan-time start_ea so a multi-row rebase
            // targets the correct segment even after an earlier row's move
            // re-sorted the array (ordinal i would drift).
            const ea_t seg_start = resolve_segment(i);
            if (seg_start == BADADDR) {
              xsql::set_vtab_error("segments: segment not found at index " + std::to_string(i));
              return false;
            }
            ea_t to = static_cast<ea_t>(new_start);
            if (to == BADADDR) {
              xsql::set_vtab_error("segments: invalid start_addr");
              return false;
            }
            move_segm_code_t rc = idasql_move_segment(seg_start, to, MSF_SILENT);
            bool ok = rc == MOVE_SEGM_OK;
            if (!ok) {
              xsql::set_vtab_error(std::string("segments: rebase failed: ") +
                                   move_segm_strerror(rc));
            } else {
              // Record the rebase so later column setters in the same statement
              // re-resolve this segment by its new start (the move may have
              // reordered the segment array — see SegRebaseGuard above).
              g_seg_rebase = SegRebaseGuard{true, i, to};
            }
            idasql_auto_wait();
            return ok;
          })
      .column_int64_rw(
          "end_addr",
          // Getter
          [](size_t i) -> int64_t {
            idasql_segment_info_t s;
            return segment_by_num(i, &s) ? static_cast<int64_t>(s.end_ea) : 0;
          },
          // Setter - resize the segment end address.
          [](size_t i, int64_t new_end) -> bool {
            idasql_auto_wait();
            const ea_t seg_start = resolve_segment(i);
            if (seg_start == BADADDR) {
              xsql::set_vtab_error("segments: segment not found at index " + std::to_string(i));
              return false;
            }
            ea_t end = static_cast<ea_t>(new_end);
            if (end == BADADDR) {
              // IDA would accept it and silently make a 1-byte segment.
              xsql::set_vtab_error(
                  "segments: end_addr -1 (BADADDR) is not an address; the "
                  "highest segment end is 0xFFFFFFFFFFFFFFFE");
              return false;
            }
            if (end <= seg_start) {
              xsql::set_vtab_error("segments: end_addr must be > start_addr");
              return false;
            }
            bool ok = set_segm_end(seg_start, end, SEGMOD_SILENT | SEGMOD_KEEP);
            if (!ok)
              xsql::set_vtab_error("segments: failed to resize segment " +
                                   idasql::format_ea_hex(seg_start));
            idasql_auto_wait();
            return ok;
          })
      .column_text_rw(
          "name",
          // Getter
          [](size_t i) -> std::string {
            return safe_segm_name(idasql_segment_ea_by_num(static_cast<int>(i)));
          },
          // Setter - rename segment
          [](size_t i, const char *new_name) -> bool {
            idasql_auto_wait();
            const ea_t seg_start = resolve_segment(i);
            if (seg_start == BADADDR) {
              xsql::set_vtab_error("segments: segment not found at index " + std::to_string(i));
              return false;
            }
            bool ok = idasql_set_segment_name(seg_start, new_name);
            if (!ok)
              xsql::set_vtab_error("segments: failed to rename segment " +
                                   idasql::format_ea_hex(seg_start));
            idasql_auto_wait();
            return ok;
          })
      .column_text_rw(
          "class",
          // Getter
          [](size_t i) -> std::string {
            return safe_segm_class(idasql_segment_ea_by_num(static_cast<int>(i)));
          },
          // Setter - change segment class
          [](size_t i, const char *new_class) -> bool {
            idasql_auto_wait();
            const ea_t seg_start = resolve_segment(i);
            if (seg_start == BADADDR) {
              xsql::set_vtab_error("segments: segment not found at index " + std::to_string(i));
              return false;
            }
            bool ok = idasql_set_segment_class(seg_start, new_class);
            if (!ok)
              xsql::set_vtab_error("segments: failed to set class on segment " +
                                   idasql::format_ea_hex(seg_start));
            idasql_auto_wait();
            return ok;
          })
      .column_int_rw(
          "perm",
          // Getter
          [](size_t i) -> int {
            idasql_segment_info_t s;
            return segment_by_num(i, &s) ? s.perm : 0;
          },
          // Setter - change segment permissions
          [](size_t i, int new_perm) -> bool {
            idasql_auto_wait();
            const ea_t seg_start = resolve_segment(i);
            if (seg_start == BADADDR) {
              xsql::set_vtab_error("segments: segment not found at index " + std::to_string(i));
              return false;
            }
            if (new_perm < 0 || new_perm > 7) {
              xsql::set_vtab_error("segments.perm: out of range (0..7): " +
                                   std::to_string(new_perm));
              return false;
            }
            bool ok = idasql_set_segment_perm(seg_start, static_cast<uchar>(new_perm));
            if (!ok)
              xsql::set_vtab_error("segments: failed to update permissions on segment " +
                                   idasql::format_ea_hex(seg_start));
            idasql_auto_wait();
            return ok;
          })
      // Addressing width in bits (16, 32, 64). Read-only: changing it would delete
      // the segment's instructions; INSERT may set it.
      .column_int("bitness",
                  [](size_t i) -> int {
                    idasql_segment_info_t s;
                    return segment_by_num(i, &s) ? (16 << s.bitness) : 0;
                  })
      .deletable([](size_t i) -> bool {
        idasql_auto_wait();
        // `i` is the segment's current ordinal: libxsql already adjusted the
        // scanned ordinal for the segments this statement deleted before it.
        const ea_t seg_start = idasql_segment_ea_by_num(static_cast<int>(i));
        if (seg_start == BADADDR) {
          xsql::set_vtab_error("segments: segment not found at index " +
                               std::to_string(i));
          idasql_auto_wait();
          return false;
        }
        bool ok = del_segm(seg_start, SEGMOD_KILL) != 0;
        if (!ok)
          xsql::set_vtab_error("segments: failed to delete segment " +
                               idasql::format_ea_hex(seg_start));
        idasql_auto_wait();
        return ok;
      })
      .insertable([](int argc, xsql::FunctionArg *argv) -> bool {
        // Columns: 0 start_addr, 1 end_addr, 2 name, 3 class, 4 perm, 5 bitness.
        if (argc < 2 || argv[0].is_null() || argv[1].is_null()) {
          xsql::set_vtab_error("segments: INSERT requires start_addr and end_addr");
          return false;
        }

        ea_t start = BADADDR;
        ea_t end = BADADDR;
        std::string err;
        if (!resolve_address_value(argv[0], "start_addr", start, &err) ||
            !resolve_address_value(argv[1], "end_addr", end, &err)) {
          xsql::set_vtab_error("segments: " + err);
          return false;
        }
        if (start == BADADDR || end == BADADDR) {
          // IDA's add_segm accepts end = BADADDR and silently creates a 1-byte
          // segment; the top of the address space is 0xFFFFFFFFFFFFFFFE.
          xsql::set_vtab_error(
              "segments: -1 (BADADDR) is not an address; the highest segment "
              "end is 0xFFFFFFFFFFFFFFFE");
          return false;
        }
        if (end <= start) {
          xsql::set_vtab_error("segments: end_addr must be > start_addr");
          return false;
        }

        int perm = -1;
        if (argc > 4 && !argv[4].is_null()) {
          const std::optional<int64_t> p = xsql::exact_int64(argv[4]);
          if (!p || *p < 0 || *p > 7) {
            xsql::set_vtab_error("segments.perm: out of range (0..7): " +
                                 (p ? std::to_string(*p) : std::string(argv[4].as_c_str())));
            return false;
          }
          perm = static_cast<int>(*p);
        }

        // The database's own addressing unless the INSERT names one.
        uchar bitness = idasql_default_segment_bitness();
        if (argc > 5 && !argv[5].is_null()) {
          const std::optional<int64_t> b = xsql::exact_int64(argv[5]);
          if (!b || (*b != 16 && *b != 32 && *b != 64)) {
            xsql::set_vtab_error("segments.bitness: must be 16, 32 or 64");
            return false;
          }
          bitness = *b == 16 ? 0 : (*b == 32 ? 1 : 2);
        }

        // Avoid destructive overlap behavior from add_segm().
        const int seg_qty = get_segm_qty();
        for (int seg_idx = 0; seg_idx < seg_qty; ++seg_idx) {
          idasql_segment_info_t seg;
          if (!segment_by_num(static_cast<size_t>(seg_idx), &seg))
            continue;
          if (start < seg.end_ea && end > seg.start_ea) {
            xsql::set_vtab_error("segments: [" + idasql::format_ea_hex(start) + ", " +
                                 idasql::format_ea_hex(end) + ") overlaps segment " +
                                 safe_segm_name(seg.start_ea) + " [" +
                                 idasql::format_ea_hex(seg.start_ea) + ", " +
                                 idasql::format_ea_hex(seg.end_ea) + ")");
            return false;
          }
        }

        const char *seg_name = nullptr;
        if (argc > 2 && !argv[2].is_null()) {
          seg_name = argv[2].as_c_str();
          if (seg_name && seg_name[0] == '\0')
            seg_name = nullptr;
        }

        const char *seg_class = nullptr;
        if (argc > 3 && !argv[3].is_null()) {
          seg_class = argv[3].as_c_str();
          if (seg_class && seg_class[0] == '\0')
            seg_class = nullptr;
        }

        idasql_auto_wait();
        const bool ok = idasql_add_segment(start, end, seg_name, seg_class, bitness, perm);
        if (!ok)
          xsql::set_vtab_error("segments: IDA refused to create [" + idasql::format_ea_hex(start) +
                               ", " + idasql::format_ea_hex(end) + ")");
        idasql_auto_wait();
        return ok;
      })
      .build();
}

} // namespace memory
} // namespace idasql
