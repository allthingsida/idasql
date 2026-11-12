// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

#include "code.hpp"
#include "memory.hpp"
#include "symbols.hpp"
#include "xrefs.hpp"

namespace idasql {
namespace core {

struct CoreRegistry {
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

  CachedTableDef<symbols::NameRow> names;
  VTableDef exports;
  CachedTableDef<symbols::CommentRow> comments;
  CachedTableDef<symbols::BookmarkRow> bookmarks;
  CachedTableDef<symbols::ImportInfo> imports;

  VTableDef segments;
  GeneratorTableDef<memory::HeadRow> heads;
  GeneratorTableDef<memory::ByteRow> bytes;
  CachedTableDef<string_info_t> strings;
  CachedTableDef<memory::NetnodeKvRow> netnode_kv;

  CachedTableDef<xrefs::XrefInfo> xrefs;
  CachedTableDef<xrefs::DataRefInfo> data_refs;

  GeneratorTableDef<dirtrees::DirtreeEntryRow> dirtree_entries;
  GeneratorTableDef<dirtrees::DirtreeFolderRow> dirtree_folders;

  CoreRegistry();

  void register_all(xsql::Database &db);

  void create_helper_views(xsql::Database &db);

private:
  void register_index_table(xsql::Database &db, const char *name,
                            const VTableDef *def);

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

}
}
