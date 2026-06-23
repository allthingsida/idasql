// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "symbols_bookmarks.hpp"

using namespace idasql::core;

namespace idasql {
namespace symbols {

// ============================================================================
// BOOKMARKS Table (with UPDATE/DELETE support)
// ============================================================================

void collect_bookmark_rows(std::vector<BookmarkRow> &rows) {
  rows.clear();

  auto folder_paths = dirtrees::collect_inode_paths(DIRTREE_IDAPLACE_BOOKMARKS);
  idaplace_t idaplace(inf_get_min_ea(), 0);
  renderer_info_t rinfo;
  lochist_entry_t loc(&idaplace, rinfo);

  for (const auto &entry_path : folder_paths) {
    idaplace_t place(0, 0);
    lochist_entry_t entry(&place, rinfo);
    qstring desc;
    uint32_t index = idasql_bookmarks_get_by_inode(
        &entry, &desc, static_cast<inode_t>(entry_path.first), nullptr);
    if (index != BOOKMARKS_BAD_INDEX && entry.place() != nullptr) {
      BookmarkRow row;
      row.index = index;
      row.ea = static_cast<idaplace_t *>(entry.place())->ea;
      row.desc = desc.c_str();
      row.inode = entry_path.first;
      row.folder_path = entry_path.second.folder_path;
      row.full_path = entry_path.second.full_path;
      rows.push_back(std::move(row));
    }
  }
}

uint64_t find_bookmark_inode(uint32_t index, ea_t ea) {
  std::vector<BookmarkRow> rows;
  collect_bookmark_rows(rows);
  for (const auto &row : rows) {
    if (row.index == index && row.ea == ea)
      return row.inode;
  }
  return 0;
}

CachedTableDef<BookmarkRow> define_bookmarks() {
  return cached_table<BookmarkRow>("bookmarks")
      .no_shared_cache()
      .estimate_rows([]() -> size_t { return 1024; })
      .cache_builder(
          [](std::vector<BookmarkRow> &rows) { collect_bookmark_rows(rows); })
      .row_populator([](BookmarkRow &row, int argc, xsql::FunctionArg *argv) {
        if (argc > 2 && !argv[2].is_null())
          row.index = static_cast<uint32_t>(argv[2].as_int());
        if (argc > 3 && !argv[3].is_null())
          row.ea = static_cast<ea_t>(argv[3].as_int64());
        if (argc > 4 && !argv[4].is_null()) {
          const char *d = argv[4].as_c_str();
          row.desc = d ? d : "";
        }
        if (argc > 5 && !argv[5].is_null())
          row.inode = static_cast<uint64_t>(argv[5].as_int64());
        if (argc > 7 && !argv[7].is_null()) {
          const char *full = argv[7].as_c_str();
          row.full_path = full ? full : "";
        }
      })
      .column_int("slot",
                  [](const BookmarkRow &row) -> int {
                    return static_cast<int>(row.index);
                  })
      .column_int64("address",
                    [](const BookmarkRow &row) -> int64_t {
                      return static_cast<int64_t>(row.ea);
                    })
      .column_text_rw(
          "description",
          [](const BookmarkRow &row) -> std::string { return row.desc; },
          [](BookmarkRow &row, const char *new_desc) -> bool {
            idasql_auto_wait();
            idaplace_t place(row.ea, 0);
            renderer_info_t rinfo;
            lochist_entry_t loc(&place, rinfo);
            bool ok = bookmarks_t_set_desc(qstring(new_desc ? new_desc : ""),
                                           loc, row.index, nullptr);
            if (ok)
              row.desc = new_desc ? new_desc : "";
            idasql_auto_wait();
            return ok;
          })
      .column_int64("inode",
                    [](const BookmarkRow &row) -> int64_t {
                      return static_cast<int64_t>(row.inode);
                    })
      .column_text_nullable_rw(
          "folder_path",
          [](const BookmarkRow &row) -> std::optional<std::string> {
            if (row.folder_path.empty())
              return std::nullopt;
            return row.folder_path;
          },
          [](BookmarkRow &row, xsql::FunctionArg value) -> bool {
            if (row.inode == 0) {
              xsql::set_vtab_error("bookmarks.folder_path: bookmark inode not found");
              return false;
            }
            std::string display = row.desc.empty()
                                      ? idasql::format_ea_hex(row.ea)
                                      : row.desc;
            const bool ok = dirtrees::move_inode_to_folder(
                DIRTREE_IDAPLACE_BOOKMARKS, row.inode, display, value,
                "bookmarks.folder_path");
            if (ok) {
              auto path = dirtrees::find_inode_path(
                  DIRTREE_IDAPLACE_BOOKMARKS, row.inode);
              if (path) {
                row.folder_path = path->folder_path;
                row.full_path = path->full_path;
              }
            }
            return ok;
          })
      .column_text("full_path", [](const BookmarkRow &row) -> std::string {
        return row.full_path;
      })
      .deletable([](BookmarkRow &row) -> bool {
        idasql_auto_wait();
        idaplace_t place(row.ea, 0);
        renderer_info_t rinfo;
        lochist_entry_t loc(&place, rinfo);
        bool ok = bookmarks_t::erase(loc, row.index, nullptr);
        idasql_auto_wait();
        return ok;
      })
      .insertable([](int argc, xsql::FunctionArg *argv) -> bool {
        if (argc < 2 || argv[1].is_null())
          return false;

        ea_t ea = static_cast<ea_t>(argv[1].as_int64());

        const char *desc = "";
        if (argc > 2 && !argv[2].is_null()) {
          desc = argv[2].as_c_str();
          if (!desc)
            desc = "";
        }

        idasql_auto_wait();

        idaplace_t place(ea, 0);
        renderer_info_t rinfo;
        lochist_entry_t loc(&place, rinfo);

        uint32_t slot = bookmarks_t::size(loc, nullptr);
        if (argc > 0 && !argv[0].is_null())
          slot = static_cast<uint32_t>(argv[0].as_int());

        uint32_t result = bookmarks_t::mark(loc, slot, nullptr, desc, nullptr);
        idasql_auto_wait();

        return result != BOOKMARKS_BAD_INDEX;
      })
      .build();
}

} // namespace symbols
} // namespace idasql
