// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * core.hpp - Master umbrella for the core SQL table domains.
 *
 * Aggregates the per-domain umbrellas (code, symbols, memory, xrefs) and the
 * shared helpers (core_common), and declares `CoreRegistry` — the single
 * registry that owns and registers every table across those domains, plus the
 * dirtree folder tables and the convenience views.
 */

#pragma once

#include "core_common.hpp"

#include "code.hpp"
#include "memory.hpp"
#include "symbols.hpp"
#include "xrefs.hpp"

namespace idasql {
namespace core {

// ============================================================================
// CoreRegistry - owns every core table across the code/symbols/memory/xrefs
// domains (and the dirtree folder tables).
// ============================================================================

struct CoreRegistry {
  // code domain
  CachedTableDef<code::FuncRow> funcs;
  CachedTableDef<code::BlockInfo> blocks;
  CachedTableDef<code::FunctionChunkInfo> function_chunks;
  GeneratorTableDef<code::FuncAtRow> func_at;
  CachedTableDef<code::InstructionRow> instructions;
  CachedTableDef<code::InstructionOperandRow> instruction_operands;
  GeneratorTableDef<code::DisasmCallInfo> disasm_calls;
  GeneratorTableDef<code::LoopInfo> disasm_loops;
  GeneratorTableDef<code::CallGraphRow> call_graph;
  GeneratorTableDef<code::ShortestPathRow> shortest_path;
  GeneratorTableDef<code::CfgEdgeInfo> cfg_edges;
  GeneratorTableDef<code::SwitchTableInfo> switch_tables;
  GeneratorTableDef<code::SwitchCaseInfo> switch_cases;
  GeneratorTableDef<code::FrameInfo> function_frames;
  GeneratorTableDef<code::DataItemRow> data_items;
  GeneratorTableDef<code::DominatorRow> dominators;
  GeneratorTableDef<code::PostDominatorRow> post_dominators;
  GeneratorTableDef<code::LoopRow> loops;

  // symbols domain
  CachedTableDef<symbols::NameRow> names;
  VTableDef exports;
  CachedTableDef<symbols::CommentRow> comments;
  CachedTableDef<symbols::BookmarkRow> bookmarks;
  CachedTableDef<symbols::ImportInfo> imports;

  // memory domain
  VTableDef segments;
  GeneratorTableDef<memory::HeadRow> heads;
  GeneratorTableDef<memory::ByteRow> bytes;
  CachedTableDef<string_info_t> strings;
  CachedTableDef<memory::NetnodeKvRow> netnode_kv;

  // xrefs domain
  CachedTableDef<xrefs::XrefInfo> xrefs;
  CachedTableDef<xrefs::DataRefInfo> data_refs;

  // dirtree folder tables (idasql::dirtrees row types)
  GeneratorTableDef<dirtrees::DirtreeEntryRow> dirtree_entries;
  GeneratorTableDef<dirtrees::DirtreeFolderRow> dirtree_folders;

  CoreRegistry();

  void register_all(xsql::Database &db);

  void create_helper_views(xsql::Database &db);

private:
  void register_index_table(xsql::Database &db, const char *name,
                            const VTableDef *def);

  // Native canonical registration: the vtable module IS the canonical table name
  // (no ida_ prefix, no alias). The family tools never coexist in one process, so
  // the prefix disambiguated nothing -- one true name per table.
  template <typename RowData>
  void register_cached_table(xsql::Database &db, const char *name,
                             const CachedTableDef<RowData> *def) {
    db.register_cached_table(name, def);
    db.create_table(name, name);
  }

  template <typename RowData>
  void register_generator_table(xsql::Database &db, const char *name,
                                const GeneratorTableDef<RowData> *def) {
    db.register_generator_table(name, def);
    db.create_table(name, name);
  }
};

} // namespace core
} // namespace idasql
