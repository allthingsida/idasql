// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "memory_segments.hpp"

using namespace idasql::core;

namespace idasql {
namespace memory {

// ============================================================================
// SEGMENTS Table
// ============================================================================

namespace {

// Multi-column UPDATE hazard guard for the `segments` table.
//
// The `start_addr` setter rebases a segment via move_segm(), which re-sorts the
// segment array by start address and can therefore change a segment's ordinal
// index. libxsql's xUpdate applies each column setter in column order against
// the *same* row index, and `start_addr` is column 0 — so in a single statement
// like `UPDATE segments SET start_addr = X, end_addr = Y WHERE ...` the
// `start_addr` rebase can shift the array out from under the later `end_addr`/
// `name`/`class`/`perm` setters, which would otherwise resolve the wrong segment
// via getnseg(index). We record the rebase and let subsequent setters re-resolve
// the moved segment by its new start address. The guard is reset once per row by
// the table's on_modify hook (fired at the top of each xUpdate).
struct SegRebaseGuard {
  bool   active = false;
  size_t orig_index = 0;
  ea_t   new_start_ea = BADADDR;
};
thread_local SegRebaseGuard g_seg_rebase;

// Multi-ROW mutation guard for the `segments` table.
//
// `segments` is a LIVE table (VTableDef): its scan rowid is the positional
// segment ordinal `i`, and the DELETE/UPDATE handlers get that same `i`. But a
// del_segm() (multi-row DELETE) or a move_segm() (multi-row rebase UPDATE)
// compacts/re-sorts the segment array, so a later row's ordinal `i` — captured
// against the pristine scan-time array — now points at a DIFFERENT segment. To
// stay position-independent we snapshot the pristine ordered list of segment
// start_eas ONCE per statement (built lazily on the first mutation, while the
// array is still pristine — SQLite completes the whole scan before issuing any
// VUpdate) and resolve each mutation by its stable start_ea (getseg) instead of
// the shifting getnseg(i). The snapshot is invalidated at the top of every scan
// via the table's .count() callback (xFilter → row_count), which is the
// statement boundary; it is NOT touched between the buffered per-row deletes of
// one statement.
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
  for (int k = 0; k < qty; ++k) {
    segment_t *s = getnseg(k);
    g_seg_rows.start_eas.push_back(s ? s->start_ea : BADADDR);
  }
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

// Resolve the segment a setter should act on. First honor a same-statement,
// same-row rebase (start_addr moved this exact ordinal); otherwise resolve by
// the stable scan-time start_ea (position-independent across multi-row edits).
inline segment_t *resolve_segment(size_t index) {
  if (g_seg_rebase.active && g_seg_rebase.orig_index == index) {
    if (segment_t *moved = getseg(g_seg_rebase.new_start_ea))
      return moved;
  }
  const ea_t stable_ea = stable_start_ea_for_index(index);
  if (stable_ea != BADADDR) {
    if (segment_t *s = getseg(stable_ea))
      return s;
  }
  return getnseg(static_cast<int>(index));
}

}  // namespace

VTableDef define_segments() {
  return table("segments")
      .count([]() {
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
      // segment (move_segm); `end_addr` resizes it (set_segm_end).
      .column_int64_rw(
          "start_addr",
          // Getter
          [](size_t i) -> int64_t {
            segment_t *s = getnseg(static_cast<int>(i));
            return s ? static_cast<int64_t>(s->start_ea) : 0;
          },
          // Setter - rebase: move the segment to a new start address.
          [](size_t i, int64_t new_start) -> bool {
            idasql_auto_wait();
            // Resolve by the stable scan-time start_ea so a multi-row rebase
            // targets the correct segment even after an earlier row's move_segm
            // re-sorted the array (getnseg(i) would drift).
            segment_t *s = resolve_segment(i);
            if (!s) {
              xsql::set_vtab_error("segments: segment not found at index " + std::to_string(i));
              return false;
            }
            ea_t to = static_cast<ea_t>(new_start);
            if (to == BADADDR) {
              xsql::set_vtab_error("segments: invalid start_addr");
              return false;
            }
            move_segm_code_t rc = move_segm(s, to, MSF_SILENT);
            bool ok = rc == MOVE_SEGM_OK;
            if (!ok) {
              xsql::set_vtab_error(std::string("segments: rebase failed: ") +
                                   move_segm_strerror(rc));
            } else {
              // Record the rebase so later column setters in the same statement
              // re-resolve this segment by its new start (move_segm may have
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
            segment_t *s = getnseg(static_cast<int>(i));
            return s ? static_cast<int64_t>(s->end_ea) : 0;
          },
          // Setter - resize the segment end address.
          [](size_t i, int64_t new_end) -> bool {
            idasql_auto_wait();
            segment_t *s = resolve_segment(i);
            if (!s) {
              xsql::set_vtab_error("segments: segment not found at index " + std::to_string(i));
              return false;
            }
            ea_t end = static_cast<ea_t>(new_end);
            if (end == BADADDR || end <= s->start_ea) {
              xsql::set_vtab_error("segments: end_addr must be > start_addr");
              return false;
            }
            bool ok = set_segm_end(s->start_ea, end, SEGMOD_SILENT | SEGMOD_KEEP);
            if (!ok)
              xsql::set_vtab_error("segments: failed to resize segment " +
                                   idasql::format_ea_hex(s->start_ea));
            idasql_auto_wait();
            return ok;
          })
      .column_text_rw(
          "name",
          // Getter
          [](size_t i) -> std::string {
            segment_t *s = getnseg(static_cast<int>(i));
            return safe_segm_name(s);
          },
          // Setter - rename segment
          [](size_t i, const char *new_name) -> bool {
            idasql_auto_wait();
            segment_t *s = resolve_segment(i);
            if (!s) {
              xsql::set_vtab_error("segments: segment not found at index " + std::to_string(i));
              return false;
            }
            bool ok = set_segm_name(s, new_name) != 0;
            if (!ok)
              xsql::set_vtab_error("segments: failed to rename segment " +
                                   idasql::format_ea_hex(s->start_ea));
            idasql_auto_wait();
            return ok;
          })
      .column_text_rw(
          "class",
          // Getter
          [](size_t i) -> std::string {
            segment_t *s = getnseg(static_cast<int>(i));
            return safe_segm_class(s);
          },
          // Setter - change segment class
          [](size_t i, const char *new_class) -> bool {
            idasql_auto_wait();
            segment_t *s = resolve_segment(i);
            if (!s) {
              xsql::set_vtab_error("segments: segment not found at index " + std::to_string(i));
              return false;
            }
            bool ok = set_segm_class(s, new_class) != 0;
            if (!ok)
              xsql::set_vtab_error("segments: failed to set class on segment " +
                                   idasql::format_ea_hex(s->start_ea));
            idasql_auto_wait();
            return ok;
          })
      .column_int_rw(
          "perm",
          // Getter
          [](size_t i) -> int {
            segment_t *s = getnseg(static_cast<int>(i));
            return s ? s->perm : 0;
          },
          // Setter - change segment permissions
          [](size_t i, int new_perm) -> bool {
            idasql_auto_wait();
            segment_t *s = resolve_segment(i);
            if (!s) {
              xsql::set_vtab_error("segments: segment not found at index " + std::to_string(i));
              return false;
            }
            if (new_perm < 0 || new_perm > 7) {
              xsql::set_vtab_error("segments.perm: out of range (0..7): " +
                                   std::to_string(new_perm));
              return false;
            }
            s->perm = static_cast<uchar>(new_perm);
            bool ok = s->update();
            if (!ok)
              xsql::set_vtab_error("segments: failed to update permissions on segment " +
                                   idasql::format_ea_hex(s->start_ea));
            idasql_auto_wait();
            return ok;
          })
      .deletable([](size_t i) -> bool {
        idasql_auto_wait();
        // Resolve the target by its stable scan-time start_ea, not the live
        // ordinal `i`: a prior del_segm in this multi-row statement compacts the
        // array, so getnseg(i) would delete the wrong (shifted) segment.
        segment_t *s = resolve_segment(i);
        if (!s) {
          xsql::set_vtab_error("segments: segment not found at index " +
                               std::to_string(i));
          idasql_auto_wait();
          return false;
        }
        bool ok = del_segm(s->start_ea, SEGMOD_KILL) != 0;
        if (!ok)
          xsql::set_vtab_error("segments: failed to delete segment " +
                               idasql::format_ea_hex(s->start_ea));
        idasql_auto_wait();
        return ok;
      })
      .insertable([](int argc, xsql::FunctionArg *argv) -> bool {
        // Columns: 0 start_addr, 1 end_addr, 2 name, 3 class, 4 perm.
        if (argc < 2 || argv[0].is_null() || argv[1].is_null())
          return false;

        ea_t start = static_cast<ea_t>(argv[0].as_int64());
        ea_t end = static_cast<ea_t>(argv[1].as_int64());
        if (start == BADADDR || end == BADADDR || end <= start)
          return false;

        int perm = 0;
        bool has_perm = false;
        if (argc > 4 && !argv[4].is_null()) {
          perm = argv[4].as_int();
          if (perm < 0 || perm > 7)
            return false;
          has_perm = true;
        }

        // Avoid destructive overlap behavior from add_segm().
        const int seg_qty = get_segm_qty();
        for (int seg_idx = 0; seg_idx < seg_qty; ++seg_idx) {
          segment_t *seg = getnseg(seg_idx);
          if (!seg)
            continue;
          if (start < seg->end_ea && end > seg->start_ea) {
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

        const ea_t para = start >> 4;

        idasql_auto_wait();
        bool ok = add_segm(para, start, end, seg_name, seg_class,
                           ADDSEG_QUIET | ADDSEG_NOAA);
        if (ok && has_perm) {
          segment_t *created = getseg(start);
          if (created == nullptr) {
            ok = false;
          } else {
            created->perm = static_cast<uchar>(perm);
            ok = created->update();
          }
        }
        idasql_auto_wait();
        return ok;
      })
      .build();
}

} // namespace memory
} // namespace idasql
