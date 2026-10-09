// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_blocks.hpp - `blocks` and `function_chunks` tables, plus the
 * per-function block iterator (constraint pushdown on func_ea).
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace code {

struct BlockInfo {
  ea_t func_ea;
  ea_t start_ea;
  ea_t end_ea;
  int index = 0;              // block ordinal in the function's flow chart
};

struct FunctionChunkInfo {
  ea_t func_ea = BADADDR;     // owning function's entry (start_ea)
  ea_t chunk_start = BADADDR;
  ea_t chunk_end = BADADDR;
  int block_count = 0;
  asize_t total_size = 0;     // size of THIS chunk
  bool is_tail = false;       // chunk_start != func_ea
  uint64 flags = 0;           // FUNC_* flags of the chunk (FUNC_TAIL on tails)
  size_t index = 0;           // 0 = entry chunk, 1..n = tails in address order
};

/**
 * Iterator for the chunks of one function.
 * Used when query has: WHERE func_addr = X
 * Walks only that function's chunks instead of building the whole
 * function_chunks cache (which charts every chunk in the database).
 */
class FunctionChunksInFuncIterator : public xsql::RowIterator {
  std::vector<FunctionChunkInfo> rows_;
  int idx_ = -1;

public:
  explicit FunctionChunksInFuncIterator(ea_t func_ea);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

/**
 * Iterator for blocks in a specific function.
 * Used when query has: WHERE func_ea = X
 * Charts the single function for O(func_blocks) instead of
 * O(all_blocks)
 */
class BlocksInFuncIterator : public xsql::RowIterator {
  ea_t func_ea_;
  idasql_flow_chart fc_;
  int idx_ = -1;
  bool valid_ = false;

public:
  explicit BlocksInFuncIterator(ea_t func_ea);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

CachedTableDef<BlockInfo> define_blocks();
CachedTableDef<FunctionChunkInfo> define_function_chunks();

} // namespace code
} // namespace idasql
