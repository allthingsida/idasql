// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "symbols_names.hpp"

#include "decompiler.hpp"
#include "address_resolution.hpp"

using namespace idasql::core;

namespace idasql {
namespace symbols {

// ============================================================================
// NAMES Table (with UPDATE/DELETE support)
// ============================================================================

void collect_name_rows(std::vector<NameRow> &rows) {
  rows.clear();
  auto folder_paths = dirtrees::collect_inode_paths(DIRTREE_NAMES);
  size_t count = get_nlist_size();
  rows.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    ea_t ea = get_nlist_ea(i);
    if (ea == BADADDR)
      continue;
    NameRow row;
    row.ea = ea;
    const char *n = get_nlist_name(i);
    row.name = n ? n : "";
    row.is_public = is_public_name(ea) ? 1 : 0;
    row.is_weak = is_weak_name(ea) ? 1 : 0;
    auto it = folder_paths.find(static_cast<uint64_t>(ea));
    if (it != folder_paths.end()) {
      row.folder_path = it->second.folder_path;
      row.full_path = it->second.full_path;
    }
    rows.push_back(std::move(row));
  }
}

// Why set_name() refused `name` at `ea`, for the error a failed INSERT or
// UPDATE reports (SQLite alone would say "SQL logic error"). Asked after the
// refusal, so it never changes what is accepted.
static std::string explain_name_refusal(ea_t ea, const char *name) {
  const std::string where = idasql::format_ea_hex(ea);
  const std::string quoted = std::string("'") + (name ? name : "") + "'";
  if (!is_mapped(ea))
    return where + " is not an address in the database";
  const ea_t head = get_item_head(ea);
  if (head != ea)
    return where + " is inside the item at " + idasql::format_ea_hex(head) +
           "; name the item's start";
  const ea_t owner = get_name_ea(BADADDR, name ? name : "");
  if (owner != BADADDR && owner != ea)
    return "the name " + quoted + " is already used at " +
           idasql::format_ea_hex(owner);
  qstring candidate(name ? name : "");
  if (!validate_name(&candidate, VNT_IDENT, SN_CHECK | SN_NOWARN))
    return quoted + " is not a valid name";
  return "IDA refused the name " + quoted + " at " + where;
}

bool lookup_name_row(NameRow &row, ea_t ea) {
  if (ea == BADADDR || get_name(ea).empty())
    return false;
  row.ea = ea;
  row.name = get_name(ea).c_str();
  row.is_public = is_public_name(ea) ? 1 : 0;
  row.is_weak = is_weak_name(ea) ? 1 : 0;
  auto path = dirtrees::find_inode_path(DIRTREE_NAMES, static_cast<uint64_t>(ea));
  if (path) {
    row.folder_path = path->folder_path;
    row.full_path = path->full_path;
  }
  return true;
}

CachedTableDef<NameRow> define_names() {
  return cached_table<NameRow>("names")
      .no_shared_cache()
      // UPDATE reconstructs from the real argv column values (NOCHANGE stays
      // disabled, so the unchanged ea/name carry real values): the name setter
      // reads the NEW name from the row. DELETE resolves by rowid (the ea)
      // through row_lookup().
      .update_from_column_values()
      .estimate_rows([]() -> size_t { return get_nlist_size(); })
      .cache_builder([](std::vector<NameRow> &rows) { collect_name_rows(rows); })
      .row_populator([](NameRow &row, int argc, xsql::FunctionArg *argv) {
        if (argc > 2 && !argv[2].is_null())
          row.ea = static_cast<ea_t>(argv[2].as_int64());
        if (argc > 3 && !argv[3].is_null()) {
          const char *name = argv[3].as_c_str();
          row.name = name ? name : "";
        }
        if (argc > 6 && !argv[6].is_null()) {
          const char *full = argv[6].as_c_str();
          row.full_path = full ? full : "";
        }
      })
      // Stable rowid = the address, matching the `addr` column and the addr
      // index. The full-scan (and index) rowid is therefore an ea that
      // round-trips through the ea-keyed row_lookup below, so a multi-row
      // full-scan DELETE resolves each row by its own address instead of by a
      // cache position that shifts as earlier rows are removed. (This also
      // removes the low-based-image aliasing where distinct rows collided on a
      // positional rowid.)
      .rowid([](const NameRow &row) -> int64_t {
        return static_cast<int64_t>(row.ea);
      })
      .row_lookup([](NameRow &row, int64_t rowid) -> bool {
        return lookup_name_row(row, static_cast<ea_t>(rowid));
      })
      .column_int64("addr",
                    [](const NameRow &row) -> int64_t {
                      return static_cast<int64_t>(row.ea);
                    })
      .column_text_rw(
          "name",
          [](const NameRow &row) -> std::string { return row.name; },
          [](NameRow &row, xsql::FunctionArg value) -> bool {
            const char *new_name = value.as_c_str();
            if (!new_name || !new_name[0]) {
              idasql_auto_wait();
              bool ok = set_name(row.ea, "", SN_NOWARN) != 0;
              if (ok) {
                row.name.clear();
                decompiler::invalidate_decompiler_cache(row.ea);
              } else {
                xsql::set_vtab_error("names: failed to clear " +
                                     idasql::format_ea_hex(row.ea));
              }
              idasql_auto_wait();
              return ok;
            }
            idasql_auto_wait();
            // row.name holds the NEW name from argv (update_from_column_values),
            // so re-read the TRUE pre-rename name from IDA for rollback.
            const std::string old_name = get_name(row.ea).c_str();
            auto old_path = dirtrees::find_inode_path(
                DIRTREE_NAMES, static_cast<uint64_t>(row.ea));
            const std::string old_folder =
                old_path ? old_path->folder_path : std::string();
            bool ok = set_name(row.ea, new_name, SN_CHECK | SN_NOWARN) != 0;
            if (ok) {
              row.name = new_name;
              if (!old_folder.empty()) {
                ok = dirtrees::move_inode_to_folder(
                    DIRTREE_NAMES, static_cast<uint64_t>(row.ea), row.name,
                    old_folder, "names.folder_path");
                if (!ok && !old_name.empty()) {
                  set_name(row.ea, old_name.c_str(), SN_CHECK);
                  row.name = old_name;
                  (void)dirtrees::move_inode_to_folder(
                      DIRTREE_NAMES, static_cast<uint64_t>(row.ea), old_name,
                      old_folder, "names.folder_path");
                }
              }
              row.folder_path.clear();
              row.full_path.clear();
              auto path = dirtrees::find_inode_path(
                  DIRTREE_NAMES, static_cast<uint64_t>(row.ea));
              if (path) {
                row.folder_path = path->folder_path;
                row.full_path = path->full_path;
              }
              decompiler::invalidate_decompiler_cache(row.ea);
            } else {
              xsql::set_vtab_error("names: failed to rename " +
                                   idasql::format_ea_hex(row.ea) + ": " +
                                   explain_name_refusal(row.ea, new_name));
            }
            idasql_auto_wait();
            return ok;
          })
      .column_int("is_public",
                  [](const NameRow &row) -> int { return row.is_public; })
      .column_int(
          "is_weak",
          [](const NameRow &row) -> int { return row.is_weak; })
      .column_text_nullable_rw(
          "folder_path",
          [](const NameRow &row) -> std::optional<std::string> {
            if (row.folder_path.empty())
              return std::nullopt;
            return row.folder_path;
          },
          [](NameRow &row, xsql::FunctionArg value) -> bool {
            if (row.name.empty() && value.is_null())
              return true;
            if (row.name.empty()) {
              xsql::set_vtab_error(
                  "names.folder_path: cannot move an unnamed address");
              return false;
            }
            const bool ok = dirtrees::move_inode_to_folder(
                DIRTREE_NAMES, static_cast<uint64_t>(row.ea), row.name, value,
                "names.folder_path");
            if (ok) {
              auto path = dirtrees::find_inode_path(
                  DIRTREE_NAMES, static_cast<uint64_t>(row.ea));
              if (path) {
                row.folder_path = path->folder_path;
                row.full_path = path->full_path;
              }
            }
            return ok;
          })
      .column_text("full_path", [](const NameRow &row) -> std::string {
        return row.full_path;
      })
      .index_on("addr", [](const NameRow &row) -> int64_t {
        return static_cast<int64_t>(row.ea);
      })
      // DELETE via set_name(ea, "") - removes the name
      .deletable([](NameRow &row) -> bool {
        idasql_auto_wait();
        bool ok = set_name(row.ea, "", SN_NOWARN) != 0;
        if (ok)
          decompiler::invalidate_decompiler_cache(row.ea);
        idasql_auto_wait();
        return ok;
      })
      .insertable([](int argc, xsql::FunctionArg *argv) -> bool {
        // address (col 0) and name (col 1) are both required
        if (argc < 2 || argv[0].is_null() || argv[1].is_null()) {
          xsql::set_vtab_error("names: INSERT requires addr and name");
          return false;
        }

        ea_t ea = BADADDR;
        if (!idasql::write_address(argv[0], "names", "addr", ea))
          return false;
        const char *name = argv[1].as_c_str();
        if (!name || !name[0]) {
          xsql::set_vtab_error(
              "names: INSERT requires a non-empty name (DELETE removes one)");
          return false;
        }

        idasql_auto_wait();
        bool ok = set_name(ea, name, SN_CHECK | SN_NOWARN) != 0;
        if (!ok) {
          xsql::set_vtab_error("names: cannot name " +
                               idasql::format_ea_hex(ea) + ": " +
                               explain_name_refusal(ea, name));
        }
        if (ok) {
          decompiler::invalidate_decompiler_cache(ea);
          if (argc > 4 && !argv[4].is_null()) {
            ok = dirtrees::move_inode_to_folder(
                DIRTREE_NAMES, static_cast<uint64_t>(ea), name, argv[4],
                "names.folder_path");
          }
        }
        idasql_auto_wait();
        return ok;
      })
      .build();
}

// ============================================================================
// ENTRIES Table (entry points / exports — canonical cross-tool name)
// ============================================================================

VTableDef define_exports() {
  return table("entries")
      .row_count([]() { return get_entry_qty(); })
      .column_int64("ordinal",
                    [](size_t i) -> int64_t {
                      return static_cast<int64_t>(get_entry_ordinal(i));
                    })
      .column_int64("addr",
                    [](size_t i) -> int64_t {
                      uval_t ord = get_entry_ordinal(i);
                      return static_cast<int64_t>(get_entry(ord));
                    })
      .column_text("name",
                   [](size_t i) -> std::string { return safe_entry_name(i); })
      .build();
}

} // namespace symbols
} // namespace idasql
