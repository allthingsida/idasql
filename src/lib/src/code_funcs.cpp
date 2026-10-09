// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_funcs.hpp"

#include "address_resolution.hpp"
#include "decompiler.hpp"
#include "function_rowid.hpp"

using namespace idasql::core;

namespace idasql {
namespace code {

bool update_function_comment(FuncRow &row, xsql::FunctionArg val,
                             bool repeatable) {
  if (val.is_nochange()) {
    return true;
  }

  if (idasql_func_start(row.start_ea) == BADADDR)
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
  const bool ok =
      idasql_set_func_cmt(row.start_ea, requested_comment.c_str(), repeatable);
  if (ok) {
    original_comment = requested_comment;
    decompiler::invalidate_decompiler_cache(row.start_ea);
  }
  idasql_auto_wait();
  return ok;
}

// Invalidate the decompiler cache of every function that references `callee`: its
// callers (code xrefs) and the functions that take its address (data xrefs, e.g.
// `&sub_X` in a callback table), every owner of a shared tail included. A name,
// prototype or no-return change on `callee` changes how they render it, but
// invalidate_decompiler_cache(callee) only refreshes the callee itself; a referrer
// decompiled earlier in the session would keep stale pseudocode. Cheap (marks
// dirty), safe when Hex-Rays is absent.
static void invalidate_callers(ea_t callee) {
  if (callee == BADADDR) {
    return;
  }
  xrefblk_t xb;
  for (bool ok = xb.first_to(callee, XREF_ALL); ok; ok = xb.next_to()) {
    idasql_for_each_owner_of(xb.from, [&](ea_t owner) {
      if (owner != callee)
        decompiler::invalidate_decompiler_cache(owner);
    });
  }
}

// ============================================================================
// FUNCS Table (with UPDATE/DELETE support)
// ============================================================================

CachedTableDef<FuncRow> define_funcs() {
  return cached_table<FuncRow>("funcs")
      .no_shared_cache()
      .estimate_rows([]() -> size_t { return get_func_qty(); })
      .row_count([]() -> size_t { return get_func_qty(); })
      .cache_builder([](std::vector<FuncRow> &rows) {
        rows.clear();
        const size_t n = get_func_qty();
        rows.reserve(n);
        auto folder_paths = dirtrees::collect_inode_paths(DIRTREE_FUNCS);
        for (size_t i = 0; i < n; ++i) {
          const ea_t f_start = idasql_func_ea_by_num(i);
          if (f_start != BADADDR) {
            FuncRow row;
            row.start_ea = f_start;
            auto it = folder_paths.find(static_cast<uint64_t>(f_start));
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
      // that rowid back to the live function by ea, NOT by ordinal.
      .rowid([](const FuncRow &row) -> int64_t {
        return static_cast<int64_t>(row.start_ea);
      })
      .row_lookup([](FuncRow &row, int64_t rowid) -> bool {
        // rowid is a start_ea (see .rowid above): resolve the function by its
        // stable address, and require it to actually START there (a lookup also
        // succeeds for interior addresses / chunks -- a func whose start_ea is
        // not `rowid` is a different function and must not be mutated).
        if (!idasql_is_func_start(static_cast<ea_t>(rowid)))
          return false;
        row.start_ea = static_cast<ea_t>(rowid);
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
      // funcs cache on every probe. Without this registration a string_refs scan
      // on a large database rebuilt the cache per probe and took roughly a
      // minute; with it the probe cost is negligible.
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
            // rename-only updates; treat that exact replay as a no-op -- but only
            // when the type is already the user's. A guessed type (from a PDB or
            // auto-analysis) prints the same text yet is not pinned: Hex-Rays
            // may rewrite it on the next decompile (IDA 9.4 SP1 widens an `int`
            // return to `__int64`). Writing that text is how a user pins it, so
            // it must reach apply_cdecl, which always applies TINFO_DEFINITE.
            if (requested_decl == row.original_prototype &&
                (requested_decl.empty() || is_userti(row.start_ea))) {
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
      // size = total bytes across ALL chunks (entry + tails). end_addr below is
      // the end of the ENTRY chunk only; a chunked function is not contiguous.
      .column_int64("size",
                    [](const FuncRow &row) -> int64_t {
                      return static_cast<int64_t>(
                          idasql_func_total_size(row.start_ea));
                    })
      .column_int64("end_addr",
                    [](const FuncRow &row) -> int64_t {
                      idasql_func_info_t fi;
                      return idasql_func_info(row.start_ea, &fi)
                                 ? static_cast<int64_t>(fi.end_ea)
                                 : 0;
                    })
      .column_int64_rw(
          "flags",
          [](const FuncRow &row) -> int64_t {
            return static_cast<int64_t>(idasql_func_flags(row.start_ea));
          },
          [](FuncRow &row, int64_t new_flags) -> bool {
            if (idasql_func_start(row.start_ea) == BADADDR)
              return false;
            const uint64 current = idasql_func_flags(row.start_ea);
            // Only a whitelisted subset of the FUNC_* flags (a uint64) is safe to
            // write; every other bit is preserved from the current value. In
            // particular FUNC_TAIL and FUNC_RESERVED are structural and must
            // never be set through this column.
            static constexpr uint64 WRITABLE_MASK =
                FUNC_NORET | FUNC_LIB | FUNC_STATICDEF | FUNC_FRAME |
                FUNC_HIDDEN | FUNC_THUNK | FUNC_BOTTOMBP;
            const uint64 requested = static_cast<uint64>(new_flags);
            // Refuse if the write would change ANY non-writable bit (set or
            // clear); all such bits are preserved from the current value.
            if (((current ^ requested) & ~WRITABLE_MASK) != 0) {
              xsql::set_vtab_error(
                  "funcs.flags: attempt to modify a non-writable bit at " +
                  idasql::format_ea_hex(row.start_ea));
              return false;
            }
            idasql_auto_wait();
            bool ok = idasql_set_func_flags(
                row.start_ea,
                (current & ~WRITABLE_MASK) | (requested & WRITABLE_MASK));
            if (ok) {
              decompiler::invalidate_decompiler_cache(row.start_ea);
              // A no-return change alters every caller (code after the call).
              if (((current ^ requested) & FUNC_NORET) != 0)
                invalidate_callers(row.start_ea);
            }
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
      // Appended last on purpose: INSERT reads columns 0-7 by position.
      .column_int64("chunk_count",
                    [](const FuncRow &row) -> int64_t {
                      return static_cast<int64_t>(
                          idasql_func_chunk_count(row.start_ea));
                    })
      .deletable([](FuncRow &row) -> bool {
        idasql_auto_wait();
        bool ok = del_func(row.start_ea);
        idasql_auto_wait();
        return ok;
      })
      .insertable([](int argc, xsql::FunctionArg *argv) -> bool {
        // address (col 0) is required
        if (argc < 1 || argv[0].is_null()) {
          xsql::set_vtab_error("funcs: INSERT needs addr");
          return false;
        }

        ea_t ea = BADADDR;
        if (!idasql::write_address(argv[0], "funcs", "addr", ea))
          return false;

        // An address already inside a function (its entry or any chunk).
        const ea_t owner = idasql_func_start(ea);
        if (owner != BADADDR) {
          xsql::set_vtab_error(
              owner == ea ? "funcs: a function already starts at " + idasql::format_ea_hex(ea)
                          : "funcs: " + idasql::format_ea_hex(ea) +
                                " is inside the function at " + idasql::format_ea_hex(owner));
          return false;
        }

        idasql_auto_wait();
        // Columns: 0 addr, 1 name, 2 prototype, 3 comment, 4 rpt_comment,
        // 5 size, 6 end_addr, 7 flags.
        // end_ea from col 6 if provided, else BADADDR (IDA auto-detects).
        ea_t end = BADADDR;
        if (argc > 6 && !argv[6].is_null() &&
            !idasql::write_address(argv[6], "funcs", "end_addr", end))
          return false;
        std::optional<int64_t> flags;
        if (argc > 7 && !argv[7].is_null()) {
          flags = idasql::write_int(argv[7], "funcs", "flags", INT64_MIN, INT64_MAX);
          if (!flags)
            return false;
        }

        bool ok = add_func(ea, end);
        idasql_auto_wait();

        if (!ok) {
          xsql::set_vtab_error("funcs: IDA could not create a function at " +
                               idasql::format_ea_hex(ea) +
                               (is_code(get_flags(ea)) ? std::string()
                                                       : " (it is not code)"));
          return false;
        }

        // A refused name or prototype fails the whole INSERT: the function is
        // removed again (the instructions add_func created stay code), so the
        // statement does not half-apply.
        auto refuse = [&](const std::string &why) {
          del_func(ea);
          idasql_auto_wait();
          xsql::set_vtab_error(why);
          return false;
        };

        // Optional: set name (col 1) after creation
        if (argc > 1 && !argv[1].is_null()) {
          const char *name = argv[1].as_c_str();
          if (name && name[0] && !set_name(ea, name, SN_CHECK | SN_NOWARN))
            return refuse("funcs: IDA refused the name '" + std::string(name) + "' at " +
                          idasql::format_ea_hex(ea));
        }

        // Optional: apply prototype (col 2)
        if (argc > 2 && !argv[2].is_null()) {
          const char *decl = argv[2].as_c_str();
          if (decl && decl[0] && !apply_cdecl(nullptr, ea, decl, 0))
            return refuse("funcs: IDA could not apply the prototype '" + std::string(decl) + "' at " +
                          idasql::format_ea_hex(ea));
        }
        invalidate_callers(ea);

        const bool created = idasql_func_start(ea) != BADADDR;
        // Optional: regular comment (col 3) and repeatable comment (col 4)
        if (created && argc > 3 && !argv[3].is_null()) {
          const char *cmt = argv[3].as_c_str();
          if (cmt && !idasql_set_func_cmt(ea, cmt, false))
            return refuse("funcs: IDA refused the comment at " + idasql::format_ea_hex(ea));
        }
        if (created && argc > 4 && !argv[4].is_null()) {
          const char *rpt = argv[4].as_c_str();
          if (rpt && !idasql_set_func_cmt(ea, rpt, true))
            return refuse("funcs: IDA refused the repeatable comment at " + idasql::format_ea_hex(ea));
        }

        // Optional: writable flags (col 7). Only the whitelisted, non-structural
        // subset may be OR'd in; everything else is left as IDA analyzed it.
        if (created && flags) {
          static constexpr uint64 WRITABLE_MASK =
              FUNC_NORET | FUNC_LIB | FUNC_STATICDEF | FUNC_FRAME | FUNC_HIDDEN |
              FUNC_THUNK | FUNC_BOTTOMBP;
          const uint64 requested = static_cast<uint64>(*flags);
          if (!idasql_set_func_flags(ea, (idasql_func_flags(ea) & ~WRITABLE_MASK) |
                                             (requested & WRITABLE_MASK)))
            return refuse("funcs: IDA refused the flags at " + idasql::format_ea_hex(ea));
        }

        idasql_auto_wait();
        return true;
      })
      .build();
}

// ============================================================================
// FUNC_AT Table-valued function: the function(s) that own an address
// ============================================================================
//
// A function may be split into disjoint chunks, so "addr is inside function f"
// is not `addr >= f.addr AND addr < f.end_addr` (end_addr ends the entry chunk).
// func_at(addr) answers it from IDA's chunk table: one row per owning function,
// so a tail shared by several functions yields one row per owner, and an
// address outside every function yields none.

namespace {

class FuncAtGenerator final : public xsql::Generator<FuncAtRow> {
public:
  explicit FuncAtGenerator(ea_t ea) {
    idasql_fchunk_info_t chunk;
    if (!idasql_fchunk_info(ea, &chunk))
      return;
    idasql_for_each_owner_of(ea, [&](ea_t owner) {
      FuncAtRow row;
      row.func_ea = owner;
      row.addr = ea;
      row.chunk_start = chunk.start_ea;
      row.chunk_end = chunk.end_ea;
      row.is_tail = chunk.is_tail();
      rows_.push_back(row);
    });
  }

  bool next() override {
    ++idx_;
    return idx_ < rows_.size();
  }

  const FuncAtRow &current() const override { return rows_[idx_]; }

  int64_t rowid() const override {
    const FuncAtRow &row = rows_[idx_];
    return idasql::detail::pack_owned_address_rowid(row.func_ea, row.addr);
  }

private:
  std::vector<FuncAtRow> rows_;
  size_t idx_ = static_cast<size_t>(-1);
};

class EmptyFuncAtGenerator final : public xsql::Generator<FuncAtRow> {
public:
  bool next() override { return false; }
  const FuncAtRow &current() const override { return row_; }
  int64_t rowid() const override { return 0; }

private:
  FuncAtRow row_{};
};

constexpr const char *kFuncAtUsage =
    "func_at requires an address: SELECT * FROM func_at(<addr>)";

} // namespace

GeneratorTableDef<FuncAtRow> define_func_at() {
  return generator_table<FuncAtRow>("func_at")
      .column_int64("func_addr",
                    [](const FuncAtRow &r) -> int64_t {
                      return static_cast<int64_t>(r.func_ea);
                    })
      .column_text("name",
                   [](const FuncAtRow &r) -> std::string {
                     return safe_func_name(r.func_ea);
                   })
      .column_int64("chunk_start",
                    [](const FuncAtRow &r) -> int64_t {
                      return static_cast<int64_t>(r.chunk_start);
                    })
      .column_int64("chunk_end",
                    [](const FuncAtRow &r) -> int64_t {
                      return static_cast<int64_t>(r.chunk_end);
                    })
      .column_int("is_tail",
                  [](const FuncAtRow &r) -> int { return r.is_tail ? 1 : 0; })
      // The input: func_at(X) binds X to this hidden column.
      .hidden_column_int64("addr")
      .full_scan_error(kFuncAtUsage)
      .constraint_filter(
          {xsql::required_eq("addr", kFuncAtUsage)},
          [](const std::vector<xsql::GeneratorConstraintArg> &args)
              -> std::unique_ptr<xsql::Generator<FuncAtRow>> {
            std::optional<ea_t> ea;
            std::string error;
            if (args.empty() ||
                !resolve_address_key(args.front().value, "addr", ea, &error)) {
              xsql::set_vtab_error(error.empty() ? kFuncAtUsage : error);
              return nullptr;
            }
            // omit=1: a value no address equals (NULL, 4096.5) has no rows.
            if (!ea)
              return std::make_unique<EmptyFuncAtGenerator>();
            return std::make_unique<FuncAtGenerator>(*ea);
          },
          1.0, 1.0)
      .build();
}

} // namespace code
} // namespace idasql
