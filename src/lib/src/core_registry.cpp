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
      func_at(code::define_func_at()),
      instructions(code::define_instructions()),
      instruction_operands(code::define_instruction_operands()),
      disasm_calls(code::define_disasm_calls()),
      disasm_loops(code::define_disasm_loops()),
      call_graph(code::define_call_graph()),
      shortest_path(code::define_shortest_path()),
      cfg_edges(code::define_cfg_edges()),
      switch_tables(code::define_switch_tables()),
      switch_cases(code::define_switch_cases()),
      function_frames(code::define_function_frames()),
      data_items(code::define_data_items()),
      dominators(code::define_dominators()),
      post_dominators(code::define_post_dominators()),
      loops(code::define_loops()), names(symbols::define_names()),
      exports(symbols::define_exports()), comments(symbols::define_comments()),
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
  register_generator_table(db, "func_at", &func_at);
  register_cached_table(db, "instructions", &instructions);
  register_cached_table(db, "instruction_operands", &instruction_operands);
  register_generator_table(db, "disasm_calls", &disasm_calls);
  register_generator_table(db, "disasm_loops", &disasm_loops);
  register_generator_table(db, "call_graph", &call_graph);
  register_generator_table(db, "shortest_path", &shortest_path);
  register_generator_table(db, "cfg_edges", &cfg_edges);
  register_generator_table(db, "switch_tables", &switch_tables);
  register_generator_table(db, "switch_cases", &switch_cases);
  register_generator_table(db, "function_frames", &function_frames);
  register_generator_table(db, "data_items", &data_items);
  register_generator_table(db, "dominators", &dominators);
  register_generator_table(db, "post_dominators", &post_dominators);
  register_generator_table(db, "loops", &loops);

  // symbols domain
  register_cached_table(db, "names", &names);
  register_index_table(db, "entries", &exports);
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

  // func_summary view - one triage row per function, from decompiler-free tables.
  // Every count is a correlated lookup on a func_addr / from_func / to_addr
  // pushdown, so a WHERE func_addr = X row costs one function's worth of work.
  // Calls in and callers count call xrefs only (kind = 'call'), not jumps.
  // No string count: string_refs costs a strings lookup per data xref (about a
  // third of the whole view on a large database); per function, use the
  // string_refs view.
  db.exec(R"(
        CREATE VIEW IF NOT EXISTS func_summary AS
        SELECT func_addr, name, size, chunk_count, block_count, edge_count,
               edge_count - block_count + 2 AS cyclomatic,
               call_sites_out, callees, call_sites_in, callers, loop_count,
               switch_count, data_reads, data_writes,
               frame_size, uses_chkstk
        FROM (
            SELECT
                f.addr AS func_addr,
                f.name AS name,
                f.size AS size,
                f.chunk_count AS chunk_count,
                (SELECT COUNT(*) FROM blocks b WHERE b.func_addr = f.addr) AS block_count,
                (SELECT COUNT(*) FROM cfg_edges e WHERE e.func_addr = f.addr) AS edge_count,
                (SELECT COUNT(*) FROM disasm_calls c WHERE c.func_addr = f.addr) AS call_sites_out,
                (SELECT COUNT(DISTINCT c.callee_addr) FROM disasm_calls c
                  WHERE c.func_addr = f.addr) AS callees,
                (SELECT COUNT(DISTINCT x.from_addr) FROM xrefs x
                  WHERE x.to_addr = f.addr AND x.kind = 'call') AS call_sites_in,
                (SELECT COUNT(DISTINCT x.from_func) FROM xrefs x
                  WHERE x.to_addr = f.addr AND x.kind = 'call') AS callers,
                (SELECT COUNT(*) FROM loops l WHERE l.func_addr = f.addr) AS loop_count,
                (SELECT COUNT(*) FROM switch_tables st WHERE st.func_addr = f.addr) AS switch_count,
                (SELECT COUNT(*) FROM xrefs x
                  WHERE x.from_func = f.addr AND x.kind = 'read') AS data_reads,
                (SELECT COUNT(*) FROM xrefs x
                  WHERE x.from_func = f.addr AND x.kind = 'write') AS data_writes,
                (SELECT fr.frame_size FROM function_frames fr
                  WHERE fr.func_addr = f.addr) AS frame_size,
                (SELECT fr.uses_chkstk FROM function_frames fr
                  WHERE fr.func_addr = f.addr) AS uses_chkstk
            FROM funcs f
        )
    )");
}

void CoreRegistry::register_index_table(xsql::Database &db, const char *name,
                                        const VTableDef *def) {
  // Native canonical registration: module name == table name (no ida_ prefix).
  db.register_table(name, def);
  db.create_table(name, name);
}

} // namespace core
} // namespace idasql
