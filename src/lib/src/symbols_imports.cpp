// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "symbols_imports.hpp"

using namespace idasql::core;

namespace idasql {
namespace symbols {

// ============================================================================
// IMPORTS Table
// ============================================================================

std::string get_import_module_name_safe(int idx) {
  qstring name;
  get_import_module_name(&name, idx);
  return std::string(name.c_str());
}
// ============================================================================
// IMPORTS Table (query-scoped cache)
// ============================================================================

CachedTableDef<ImportInfo> define_imports() {
  return cached_table<ImportInfo>("imports")
      .no_shared_cache()
      .estimate_rows([]() -> size_t {
        // Estimate: ~100 imports per module
        return get_import_module_qty() * 100;
      })
      .cache_builder([](std::vector<ImportInfo> &cache) {
        auto folder_paths = dirtrees::collect_inode_paths(DIRTREE_IMPORTS);
        uint mod_qty = get_import_module_qty();
        for (uint m = 0; m < mod_qty; m++) {
          ImportEnumContext ctx;
          ctx.cache = &cache;
          ctx.folder_paths = &folder_paths;
          ctx.module_idx = static_cast<int>(m);

          enum_import_names(
              m,
              [](ea_t ea, const char *name, uval_t ord, void *param) -> int {
                auto *ctx = static_cast<ImportEnumContext *>(param);
                ImportInfo info;
                info.module_idx = ctx->module_idx;
                info.ea = ea;
                info.name = name ? name : "";
                info.ord = ord;
                auto path_it = ctx->folder_paths->find(static_cast<uint64_t>(ea));
                if (path_it != ctx->folder_paths->end()) {
                  info.folder_path = path_it->second.folder_path;
                  info.full_path = path_it->second.full_path;
                }
                ctx->cache->push_back(info);
                return 1; // continue enumeration
              },
              &ctx);
        }
      })
      .column_int64("addr",
                    [](const ImportInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.ea);
                    })
      .column_text("name",
                   [](const ImportInfo &r) -> std::string { return r.name; })
      .column_int64("ordinal",
                    [](const ImportInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.ord);
                    })
      .column_text("module",
                   [](const ImportInfo &r) -> std::string {
                     return get_import_module_name_safe(r.module_idx);
                   })
      .column_int("module_idx",
                  [](const ImportInfo &r) -> int { return r.module_idx; })
      .column_text_nullable_rw(
          "folder_path",
          [](const ImportInfo &r) -> std::optional<std::string> {
            if (r.folder_path.empty())
              return std::nullopt;
            return r.folder_path;
          },
          [](ImportInfo &row, xsql::FunctionArg value) -> bool {
            std::string display = row.name.empty()
                                      ? idasql::format_ea_hex(row.ea)
                                      : row.name;
            const bool ok = dirtrees::move_inode_to_folder(
                DIRTREE_IMPORTS, static_cast<uint64_t>(row.ea), display, value,
                "imports.folder_path");
            if (ok) {
              auto path = dirtrees::find_inode_path(
                  DIRTREE_IMPORTS, static_cast<uint64_t>(row.ea));
              if (path) {
                row.folder_path = path->folder_path;
                row.full_path = path->full_path;
              }
            }
            return ok;
          })
      .column_text("full_path", [](const ImportInfo &r) -> std::string {
        return r.full_path;
      })
      .index_on("addr", [](const ImportInfo &r) -> int64_t {
        return static_cast<int64_t>(r.ea);
      })
      .build();
}

} // namespace symbols
} // namespace idasql
