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

namespace {

struct SegRebaseGuard {
  bool   active = false;
  size_t orig_index = 0;
  ea_t   new_start_ea = BADADDR;
};
thread_local SegRebaseGuard g_seg_rebase;

struct SegRowSnapshot {
  bool               valid = false;
  std::vector<ea_t>  start_eas;
};
thread_local SegRowSnapshot g_seg_rows;

inline void reset_segment_row_snapshot() { g_seg_rows.valid = false; }

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

inline ea_t stable_start_ea_for_index(size_t index) {
  ensure_segment_row_snapshot();
  if (index < g_seg_rows.start_eas.size())
    return g_seg_rows.start_eas[index];
  return BADADDR;
}

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

inline bool segment_by_num(size_t i, idasql_segment_info_t *out) {
  return idasql_segment_info(idasql_segment_ea_by_num(static_cast<int>(i)), out);
}

}

VTableDef define_segments() {
  return table("segments")
      .row_count([]() {
        reset_segment_row_snapshot();
        return static_cast<size_t>(get_segm_qty());
      })
      .on_modify([](const std::string &) { g_seg_rebase = SegRebaseGuard{}; })
      .column_int64_rw(
          "start_addr",
          [](size_t i) -> int64_t {
            const ea_t start = idasql_segment_ea_by_num(static_cast<int>(i));
            return start != BADADDR ? static_cast<int64_t>(start) : 0;
          },
          [](size_t i, int64_t new_start) -> bool {
            idasql_auto_wait();
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
              g_seg_rebase = SegRebaseGuard{true, i, to};
            }
            idasql_auto_wait();
            return ok;
          })
      .column_int64_rw(
          "end_addr",
          [](size_t i) -> int64_t {
            idasql_segment_info_t s;
            return segment_by_num(i, &s) ? static_cast<int64_t>(s.end_ea) : 0;
          },
          [](size_t i, int64_t new_end) -> bool {
            idasql_auto_wait();
            const ea_t seg_start = resolve_segment(i);
            if (seg_start == BADADDR) {
              xsql::set_vtab_error("segments: segment not found at index " + std::to_string(i));
              return false;
            }
            ea_t end = static_cast<ea_t>(new_end);
            if (end == BADADDR) {
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
          [](size_t i) -> std::string {
            return safe_segm_name(idasql_segment_ea_by_num(static_cast<int>(i)));
          },
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
          [](size_t i) -> std::string {
            return safe_segm_class(idasql_segment_ea_by_num(static_cast<int>(i)));
          },
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
          [](size_t i) -> int {
            idasql_segment_info_t s;
            return segment_by_num(i, &s) ? s.perm : 0;
          },
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
      .column_int("bitness",
                  [](size_t i) -> int {
                    idasql_segment_info_t s;
                    return segment_by_num(i, &s) ? (16 << s.bitness) : 0;
                  })
      .deletable([](size_t i) -> bool {
        idasql_auto_wait();
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

        uchar bitness = idasql_default_segment_bitness();
        if (argc > 5 && !argv[5].is_null()) {
          const std::optional<int64_t> b = xsql::exact_int64(argv[5]);
          if (!b || (*b != 16 && *b != 32 && *b != 64)) {
            xsql::set_vtab_error("segments.bitness: must be 16, 32 or 64");
            return false;
          }
          bitness = *b == 16 ? 0 : (*b == 32 ? 1 : 2);
        }

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

}
}
