// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_funcs.hpp"

#include "decompiler.hpp"

using namespace idasql::core;

namespace idasql {
namespace code {

bool update_function_comment(FuncRow &row, xsql::FunctionArg val,
                             bool repeatable) {
  if (val.is_nochange()) {
    return true;
  }

  func_t *f = get_func(row.start_ea);
  if (!f)
    return false;

  const char *new_comment = val.is_null() ? nullptr : val.as_c_str();
  const std::string requested_comment = new_comment ? new_comment : "";
  std::string &original_comment =
      repeatable ? row.original_rpt_comment : row.original_comment;

  // no_shared_cache() can replay the pre-update value during unrelated
  // column updates; treat that exact replay as a no-op.
  if (requested_comment == original_comment) {
    return true;
  }

  idasql_auto_wait();
  const bool ok = set_func_cmt(f, requested_comment.c_str(), repeatable);
  if (ok) {
    original_comment = requested_comment;
    decompiler::invalidate_decompiler_cache(row.start_ea);
  }
  idasql_auto_wait();
  return ok;
}

// Invalidate the decompiler cache of every function that references `callee` via a
// code xref (call/jump). A name or prototype change on `callee` changes how those
// CALLERS render the call site, but invalidate_decompiler_cache(callee) only
// refreshes the callee itself; a caller decompiled earlier in the session would keep
// stale pseudocode (the same latent class the callee_type INTERR fix addressed, one
// hop up). Cheap (marks dirty), safe when Hex-Rays is absent.
static void invalidate_callers(ea_t callee) {
  if (callee == BADADDR) {
    return;
  }
  xrefblk_t xb;
  for (bool ok = xb.first_to(callee, XREF_ALL); ok; ok = xb.next_to()) {
    if (!xb.iscode) {
      continue;
    }
    func_t *caller = get_func(xb.from);
    if (caller != nullptr && caller->start_ea != callee) {
      decompiler::invalidate_decompiler_cache(caller->start_ea);
    }
  }
}

// ============================================================================
// FUNCS Table (with UPDATE/DELETE support)
// ============================================================================

CachedTableDef<FuncRow> define_funcs() {
  return cached_table<FuncRow>("funcs")
      .no_shared_cache()
      .estimate_rows([]() -> size_t { return get_func_qty(); })
      .count([]() -> size_t { return get_func_qty(); })
      .cache_builder([](std::vector<FuncRow> &rows) {
        rows.clear();
        const size_t n = get_func_qty();
        rows.reserve(n);
        auto folder_paths = dirtrees::collect_inode_paths(DIRTREE_FUNCS);
        for (size_t i = 0; i < n; ++i) {
          func_t *f = getn_func(i);
          if (f) {
            FuncRow row;
            row.start_ea = f->start_ea;
            auto it = folder_paths.find(static_cast<uint64_t>(f->start_ea));
            if (it != folder_paths.end()) {
              row.folder_path = it->second.folder_path;
              row.full_path = it->second.full_path;
            }
            rows.push_back(std::move(row));
          }
        }
      })
      // Stable rowid = the function's start_ea, matching the `addr` column. This
      // makes full-scan and index cursors report a positional-independent rowid
      // so a multi-row UPDATE/DELETE resolves each row by its own address --
      // deleting one func never shifts another's rowid. row_lookup below resolves
      // that rowid back to the live function by ea (get_func), NOT by ordinal.
      .rowid([](const FuncRow &row) -> int64_t {
        return static_cast<int64_t>(row.start_ea);
      })
      .row_lookup([](FuncRow &row, int64_t rowid) -> bool {
        // rowid is a start_ea (see .rowid above): resolve the function by its
        // stable address, and require it to actually START there (get_func also
        // succeeds for interior addresses / chunks -- a func whose start_ea is
        // not `rowid` is a different function and must not be mutated).
        func_t *f = get_func(static_cast<ea_t>(rowid));
        if (!f || f->start_ea != static_cast<ea_t>(rowid))
          return false;
        row.start_ea = f->start_ea;
        row.original_name = safe_func_name(row.start_ea);
        row.original_prototype = safe_func_prototype(row.start_ea);
        row.original_comment = safe_func_comment(row.start_ea, false);
        row.original_rpt_comment = safe_func_comment(row.start_ea, true);
        auto path = dirtrees::find_inode_path(DIRTREE_FUNCS,
                                              static_cast<uint64_t>(row.start_ea));
        if (path) {
          row.folder_path = path->folder_path;
          row.full_path = path->full_path;
        }
        return true;
      })
      .column_int64("addr",
                    [](const FuncRow &row) -> int64_t {
                      return static_cast<int64_t>(row.start_ea);
                    })
      // Per-cursor address index: JOINs probing funcs.addr (e.g. string_refs'
      // func_name leg) reuse one cache per cursor instead of rebuilding the whole
      // funcs cache on every probe (~49ms/probe at 22k funcs; a string_refs scan
      // cost ~61s on a 22k-function database before this registration).
      .index_on("addr",
                [](const FuncRow &row) -> int64_t {
                  return static_cast<int64_t>(row.start_ea);
                })
      .column_text_rw(
          "name",
          [](const FuncRow &row) -> std::string {
            return safe_func_name(row.start_ea);
          },
          [](FuncRow &row, const char *new_name) -> bool {
            const std::string requested_name = new_name ? new_name : "";
            if (requested_name == row.original_name) {
              return true;
            }
            idasql_auto_wait();
            bool ok =
                set_name(row.start_ea, requested_name.c_str(), SN_CHECK) != 0;
            if (ok) {
              decompiler::invalidate_decompiler_cache(row.start_ea);
              invalidate_callers(row.start_ea);
            }
            idasql_auto_wait();
            return ok;
          })
      .column_text_rw(
          "prototype",
          [](const FuncRow &row) -> std::string {
            return safe_func_prototype(row.start_ea);
          },
          [](FuncRow &row, xsql::FunctionArg val) -> bool {
            if (val.is_nochange()) {
              return true;
            }
            const char *new_decl = val.is_null() ? nullptr : val.as_c_str();
            const std::string requested_decl = new_decl ? new_decl : "";
            // no_shared_cache() can replay the pre-update declaration during
            // rename-only updates; treat that exact replay as a no-op.
            if (requested_decl == row.original_prototype) {
              return true;
            }
            idasql_auto_wait();
            bool ok = false;
            if (new_decl == nullptr || new_decl[0] == '\0') {
              del_tinfo(row.start_ea);
              ok = true;
            } else {
              ok = apply_cdecl(nullptr, row.start_ea, new_decl, 0);
            }
            if (ok) {
              decompiler::invalidate_decompiler_cache(row.start_ea);
              invalidate_callers(row.start_ea);
            }
            idasql_auto_wait();
            return ok;
          })
      .column_text_rw(
          "comment",
          [](const FuncRow &row) -> std::string {
            return safe_func_comment(row.start_ea, false);
          },
          [](FuncRow &row, xsql::FunctionArg val) -> bool {
            return update_function_comment(row, val, false);
          })
      .column_text_rw(
          "rpt_comment",
          [](const FuncRow &row) -> std::string {
            return safe_func_comment(row.start_ea, true);
          },
          [](FuncRow &row, xsql::FunctionArg val) -> bool {
            return update_function_comment(row, val, true);
          })
      .column_int64("size",
                    [](const FuncRow &row) -> int64_t {
                      func_t *f = get_func(row.start_ea);
                      return f ? static_cast<int64_t>(f->size()) : 0;
                    })
      .column_int64("end_addr",
                    [](const FuncRow &row) -> int64_t {
                      func_t *f = get_func(row.start_ea);
                      return f ? static_cast<int64_t>(f->end_ea) : 0;
                    })
      .column_int64_rw(
          "flags",
          [](const FuncRow &row) -> int64_t {
            func_t *f = get_func(row.start_ea);
            return f ? static_cast<int64_t>(f->flags) : 0;
          },
          [](FuncRow &row, int64_t new_flags) -> bool {
            func_t *f = get_func(row.start_ea);
            if (!f)
              return false;
            // Only a whitelisted subset of func_t::flags (a uint64) is safe to
            // write; every other bit is preserved from the current value. In
            // particular FUNC_TAIL and FUNC_RESERVED are structural and must
            // never be set through this column.
            static constexpr uint64 WRITABLE_MASK =
                FUNC_NORET | FUNC_LIB | FUNC_STATICDEF | FUNC_FRAME |
                FUNC_HIDDEN | FUNC_THUNK | FUNC_BOTTOMBP;
            const uint64 requested = static_cast<uint64>(new_flags);
            // Refuse if the write would change ANY non-writable bit (set or
            // clear); all such bits are preserved from the current value.
            if (((f->flags ^ requested) & ~WRITABLE_MASK) != 0) {
              xsql::set_vtab_error(
                  "funcs.flags: attempt to modify a non-writable bit at " +
                  idasql::format_ea_hex(row.start_ea));
              return false;
            }
            idasql_auto_wait();
            f->flags = (f->flags & ~WRITABLE_MASK) | (requested & WRITABLE_MASK);
            bool ok = update_func(f);
            if (ok)
              decompiler::invalidate_decompiler_cache(row.start_ea);
            idasql_auto_wait();
            return ok;
          })
      // Prototype columns - return type (lazy-computed, cached per row)
      .column_text("return_type",
                   [](const FuncRow &row) -> std::string {
                     if (!row.ensure_fi())
                       return "";
                     qstring ret_str;
                     row.fi.rettype.print(&ret_str);
                     return ret_str.c_str();
                   })
      .column_int("return_is_ptr",
                  [](const FuncRow &row) -> int {
                    return row.ensure_fi() && row.fi.rettype.is_ptr() ? 1 : 0;
                  })
      .column_int("return_is_int",
                  [](const FuncRow &row) -> int {
                    return row.ensure_fi() && row.fi.rettype.is_int() ? 1 : 0;
                  })
      .column_int("return_is_integral",
                  [](const FuncRow &row) -> int {
                    return row.ensure_fi() && row.fi.rettype.is_integral() ? 1
                                                                           : 0;
                  })
      .column_int("return_is_void",
                  [](const FuncRow &row) -> int {
                    return row.ensure_fi() && row.fi.rettype.is_void() ? 1 : 0;
                  })
      // Prototype columns - arguments
      .column_int("arg_count",
                  [](const FuncRow &row) -> int {
                    if (!row.ensure_fi())
                      return 0;
                    return static_cast<int>(row.fi.size());
                  })
      .column_text("calling_conv",
                   [](const FuncRow &row) -> std::string {
                     if (!row.ensure_fi())
                       return "";
                     return get_cc_name(row.fi.get_cc());
                   })
      .column_text_nullable_rw(
          "folder_path",
          [](const FuncRow &row) -> std::optional<std::string> {
            if (row.folder_path.empty())
              return std::nullopt;
            return row.folder_path;
          },
          [](FuncRow &row, xsql::FunctionArg val) -> bool {
            const bool ok = dirtrees::move_inode_to_folder(
                DIRTREE_FUNCS, static_cast<uint64_t>(row.start_ea),
                safe_func_name(row.start_ea), val, "funcs.folder_path");
            if (ok) {
              auto path = dirtrees::find_inode_path(
                  DIRTREE_FUNCS, static_cast<uint64_t>(row.start_ea));
              if (path) {
                row.folder_path = path->folder_path;
                row.full_path = path->full_path;
              }
              decompiler::invalidate_decompiler_cache(row.start_ea);
            }
            return ok;
          })
      .column_text("full_path", [](const FuncRow &row) -> std::string {
        return row.full_path;
      })
      .deletable([](FuncRow &row) -> bool {
        idasql_auto_wait();
        bool ok = del_func(row.start_ea);
        idasql_auto_wait();
        return ok;
      })
      .insertable([](int argc, xsql::FunctionArg *argv) -> bool {
        // address (col 0) is required
        if (argc < 1 || argv[0].is_null())
          return false;

        ea_t ea = static_cast<ea_t>(argv[0].as_int64());

        // Check if function already exists at this address
        if (get_func(ea) != nullptr)
          return false;

        idasql_auto_wait();
        // Columns: 0 addr, 1 name, 2 prototype, 3 comment, 4 rpt_comment,
        // 5 size, 6 end_addr, 7 flags.
        // end_ea from col 6 if provided, else BADADDR (IDA auto-detects).
        ea_t end = BADADDR;
        if (argc > 6 && !argv[6].is_null())
          end = static_cast<ea_t>(argv[6].as_int64());

        bool ok = add_func(ea, end);
        idasql_auto_wait();

        if (!ok)
          return false;

        // Optional: set name (col 1) after creation
        if (argc > 1 && !argv[1].is_null()) {
          const char *name = argv[1].as_c_str();
          if (name && name[0])
            set_name(ea, name, SN_CHECK);
        }

        // Optional: apply prototype (col 2)
        if (argc > 2 && !argv[2].is_null()) {
          const char *decl = argv[2].as_c_str();
          if (decl && decl[0])
            apply_cdecl(nullptr, ea, decl, 0);
        }

        func_t *f = get_func(ea);
        // Optional: regular comment (col 3) and repeatable comment (col 4)
        if (f && argc > 3 && !argv[3].is_null()) {
          const char *cmt = argv[3].as_c_str();
          if (cmt)
            set_func_cmt(f, cmt, false);
        }
        if (f && argc > 4 && !argv[4].is_null()) {
          const char *rpt = argv[4].as_c_str();
          if (rpt)
            set_func_cmt(f, rpt, true);
        }

        // Optional: writable flags (col 7). Only the whitelisted, non-structural
        // subset may be OR'd in; everything else is left as IDA analyzed it.
        if (f && argc > 7 && !argv[7].is_null()) {
          static constexpr uint64 WRITABLE_MASK =
              FUNC_NORET | FUNC_LIB | FUNC_STATICDEF | FUNC_FRAME | FUNC_HIDDEN |
              FUNC_THUNK | FUNC_BOTTOMBP;
          const uint64 requested = static_cast<uint64>(argv[7].as_int64());
          f->flags = (f->flags & ~WRITABLE_MASK) | (requested & WRITABLE_MASK);
          update_func(f);
        }

        idasql_auto_wait();
        return true;
      })
      .build();
}

} // namespace code
} // namespace idasql
