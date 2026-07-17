// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "core.hpp"

#include "entities_search.hpp"

namespace idasql {
namespace core {

// ============================================================================
// CoreRegistry: every core table (code/symbols/memory/xrefs) in one place
// ============================================================================

CoreRegistry::CoreRegistry()
    : funcs(code::define_funcs()), blocks(code::define_blocks()),
      function_chunks(code::define_function_chunks()),
      instructions(code::define_instructions()),
      instruction_operands(code::define_instruction_operands()),
      disasm_calls(code::define_disasm_calls()),
      disasm_loops(code::define_disasm_loops()),
      call_graph(code::define_call_graph()),
      shortest_path(code::define_shortest_path()),
      cfg_edges(code::define_cfg_edges()), names(symbols::define_names()),
      entries(symbols::define_entries()), comments(symbols::define_comments()),
      bookmarks(symbols::define_bookmarks()), imports(symbols::define_imports()),
      segments(memory::define_segments()), heads(memory::define_heads()),
      bytes(memory::define_bytes()), strings(memory::define_strings()),
      netnode_kv(memory::define_netnode_kv()), xrefs(xrefs::define_xrefs()),
      data_refs(xrefs::define_data_refs()),
      dirtree_entries(dirtrees::define_dirtree_entries()),
      dirtree_folders(dirtrees::define_dirtree_folders()) {}

void CoreRegistry::register_all(xsql::Database &db) {
  // code domain
  register_cached_table(db, "funcs", &funcs);
  register_cached_table(db, "blocks", &blocks);
  register_cached_table(db, "function_chunks", &function_chunks);
  register_cached_table(db, "instructions", &instructions);
  register_cached_table(db, "instruction_operands", &instruction_operands);
  register_generator_table(db, "disasm_calls", &disasm_calls);
  register_generator_table(db, "disasm_loops", &disasm_loops);
  register_generator_table(db, "call_graph", &call_graph);
  register_generator_table(db, "shortest_path", &shortest_path);
  register_generator_table(db, "cfg_edges", &cfg_edges);

  // symbols domain
  register_cached_table(db, "names", &names);
  register_index_table(db, "entries", &entries);
  register_cached_table(db, "comments", &comments);
  register_cached_table(db, "bookmarks", &bookmarks);
  register_cached_table(db, "imports", &imports);

  // memory domain
  register_index_table(db, "segments", &segments);
  register_generator_table(db, "heads", &heads);
  register_generator_table(db, "bytes", &bytes);
  register_cached_table(db, "strings", &strings);
  register_cached_table(db, "netnode_kv", &netnode_kv);

  // xrefs domain
  register_cached_table(db, "xrefs", &xrefs);
  register_cached_table(db, "data_refs", &data_refs);

  // dirtree folder tables
  register_generator_table(db, "dirtree_entries", &dirtree_entries);
  register_generator_table(db, "dirtree_folders", &dirtree_folders);

  // Disassembly convenience views (calls_in_loops, funcs_with_loops, ...)
  code::register_disasm_views(db);

  // Grep-style entity search table
  search::register_grep_entities(db);

  // Create convenience views for common queries
  create_helper_views(db);
}

void CoreRegistry::create_helper_views(xsql::Database &db) {
  // callers view - who calls a function
  // Uses pre-computed from_func to avoid expensive range joins.
  db.exec(R"(
        CREATE VIEW IF NOT EXISTS callers AS
        SELECT
            x.to_addr as func_addr,
            x.from_addr as caller_addr,
            COALESCE(f.name, n.name, printf('sub_%X', x.from_func)) as caller_name,
            x.from_func as caller_func_addr
        FROM xrefs x
        LEFT JOIN funcs f ON f.addr = x.from_func
        LEFT JOIN names n ON n.addr = x.from_func
        WHERE x.is_code = 1 AND x.from_func IS NOT NULL
          AND x.to_addr IN (SELECT addr FROM funcs)
    )");

  // callees view - what does a function call
  // Uses from_func for grouping and table joins for name resolution.
  db.exec(R"(
        CREATE VIEW IF NOT EXISTS callees AS
        SELECT
            x.from_func as func_addr,
            COALESCE(f.name, fn.name, printf('sub_%X', x.from_func)) as func_name,
            x.to_addr as callee_addr,
            COALESCE(cn.name, cf.name, printf('sub_%X', x.to_addr)) as callee_name
        FROM xrefs x
        LEFT JOIN funcs f ON f.addr = x.from_func
        LEFT JOIN names fn ON fn.addr = x.from_func
        LEFT JOIN names cn ON cn.addr = x.to_addr
        LEFT JOIN funcs cf ON cf.addr = x.to_addr
        WHERE x.is_code = 1 AND x.from_func IS NOT NULL
          AND x.to_addr IN (SELECT addr FROM funcs)
    )");

  // string_refs view - which functions reference which strings
  db.exec(R"(
        CREATE VIEW IF NOT EXISTS string_refs AS
        SELECT
            s.addr as string_addr,
            s.content as string_value,
            s.length as string_length,
            x.from_addr as ref_addr,
            x.from_func as func_addr,
            COALESCE(f.name, n.name, printf('sub_%X', x.from_func)) as func_name
        FROM strings s
        JOIN xrefs x ON x.to_addr = s.addr
        LEFT JOIN funcs f ON f.addr = x.from_func
        LEFT JOIN names n ON n.addr = x.from_func
        WHERE x.from_func != 0
    )");
}

void CoreRegistry::register_index_table(xsql::Database &db, const char *name,
                                        const VTableDef *def) {
  std::string module_name = std::string("ida_") + name;
  db.register_table(module_name.c_str(), def);
  db.create_table(name, module_name.c_str());
}

} // namespace core
} // namespace idasql
