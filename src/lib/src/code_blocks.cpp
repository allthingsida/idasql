// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_blocks.hpp"

#include "function_rowid.hpp"

using namespace idasql::core;

namespace idasql {
namespace code {

// ============================================================================
// BLOCKS Table (basic blocks)
// ============================================================================
//
// A function's flow chart covers every chunk, so a block of a tail shared by
// functions A and C is a row under A and a row under C. The rowid is
// (function, block ordinal) for both the full scan and the func_addr pushdown:
// an address-only rowid made SQLite drop C's copy from a MULTI-INDEX OR plan.

BlocksInFuncIterator::BlocksInFuncIterator(ea_t func_ea) : func_ea_(func_ea) {
  // func_addr is the owner's ENTRY address; an interior or tail address is a
  // different key and matches nothing, as in the full scan.
  if (idasql_is_func_start(func_ea)) {
    fc_.create_func(func_ea, FC_NOEXT);
  }
}

bool BlocksInFuncIterator::next() {
  ++idx_;
  valid_ = (idx_ < fc_.size());
  return valid_;
}

bool BlocksInFuncIterator::eof() const { return idx_ >= 0 && !valid_; }

void BlocksInFuncIterator::column(xsql::FunctionContext &ctx, int col) {
  if (!valid_ || idx_ < 0 || idx_ >= fc_.size()) {
    ctx.result_null();
    return;
  }
  const qbasic_block_t &bb = fc_.blocks[idx_];
  switch (col) {
  case 0:
    ctx.result_int64(static_cast<int64_t>(func_ea_));
    break;
  case 1:
    ctx.result_int64(static_cast<int64_t>(bb.start_ea));
    break;
  case 2:
    ctx.result_int64(static_cast<int64_t>(bb.end_ea));
    break;
  case 3:
    ctx.result_int64(static_cast<int64_t>(bb.end_ea - bb.start_ea));
    break;
  default:
    ctx.result_null();
    break;
  }
}

int64_t BlocksInFuncIterator::rowid() const {
  if (!valid_ || idx_ < 0 || idx_ >= fc_.size())
    return 0;
  return idasql::detail::pack_function_rowid(func_ea_,
                                             static_cast<size_t>(idx_));
}

CachedTableDef<BlockInfo> define_blocks() {
  return cached_table<BlockInfo>("blocks")
      .no_shared_cache()
      .estimate_rows([]() -> size_t {
        // Heuristic: ~10 blocks per function
        return get_func_qty() * 10;
      })
      .cache_builder([](std::vector<BlockInfo> &cache) {
        size_t func_qty = get_func_qty();
        for (size_t i = 0; i < func_qty; i++) {
          // Cooperative cancellation across the per-function build.
          if ((i & 1023u) == 0 && xsql::vtab_interrupted()) {
            xsql::set_vtab_error("query interrupted: timeout while building blocks");
            return;
          }
          const ea_t func_start = idasql_func_ea_by_num(i);
          if (func_start == BADADDR)
            continue;

          idasql_flow_chart fc;
          fc.create_func(func_start, FC_NOEXT);

          for (int j = 0; j < fc.size(); j++) {
            const qbasic_block_t &bb = fc.blocks[j];
            BlockInfo bi;
            bi.func_ea = func_start;
            bi.start_ea = bb.start_ea;
            bi.end_ea = bb.end_ea;
            bi.index = j;
            cache.push_back(bi);
          }
        }
      })
      .rowid([](const BlockInfo &r) -> int64_t {
        return idasql::detail::pack_function_rowid(
            r.func_ea, static_cast<size_t>(r.index));
      })
      .column_int64("func_addr",
                    [](const BlockInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.func_ea);
                    })
      .column_int64("start_addr",
                    [](const BlockInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.start_ea);
                    })
      .column_int64("end_addr",
                    [](const BlockInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.end_ea);
                    })
      .column_int64("size",
                    [](const BlockInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.end_ea - r.start_ea);
                    })
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<BlocksInFuncIterator>(
                static_cast<ea_t>(func_addr));
          },
          10.0, 10.0)
      .build();
}

// ============================================================================
// FUNCTION_CHUNKS Table
// ============================================================================
//
// One row per (function, chunk): the entry chunk and every tail, and a tail
// shared by several functions appears once under each of them. Both the full
// scan and the func_addr pushdown build rows with append_function_chunk_rows(),
// and the rowid is (function, chunk index), so the two paths agree row for row.

// block_count must count ONE chunk's basic blocks, not the whole owner
// function's. A function chart ignores the [ea1, ea2) range (it charts the
// entire function), so chart the range form over the chunk bounds to cover only
// [chunk_start, chunk_end) -- otherwise every chunk of a function reports the
// same function-wide block count.
static int count_chunk_blocks(ea_t start, ea_t end) {
  idasql_flow_chart fc;
  fc.create_range(start, end, FC_NOEXT);
  return fc.size();
}

// Append the chunks of the function whose ENTRY is `owner`: the entry chunk
// first, then the tails in address order. An address that is not a function
// entry appends nothing.
static void append_function_chunk_rows(ea_t owner,
                                       std::vector<FunctionChunkInfo> &rows) {
  if (!idasql_is_func_start(owner))
    return;
  size_t index = 0;
  idasql_for_each_func_chunk(owner, [&](const range_t &chunk, bool is_entry) {
    idasql_fchunk_info_t fchunk;
    const bool have_fchunk = idasql_fchunk_info(chunk.start_ea, &fchunk);
    FunctionChunkInfo row;
    row.func_ea = owner;
    row.chunk_start = chunk.start_ea;
    row.chunk_end = chunk.end_ea;
    row.total_size = chunk.end_ea - chunk.start_ea;
    row.is_tail = !is_entry;
    row.flags = have_fchunk ? fchunk.flags : 0;
    row.block_count = count_chunk_blocks(chunk.start_ea, chunk.end_ea);
    row.index = index++;
    rows.push_back(row);
  });
}

static int64_t function_chunk_rowid(const FunctionChunkInfo &row) {
  return idasql::detail::pack_function_rowid(row.func_ea, row.index);
}

// Column order MUST match define_function_chunks() below.
static void function_chunk_column(xsql::FunctionContext &ctx,
                                  const FunctionChunkInfo &row, int col) {
  switch (col) {
  case 0: ctx.result_int64(static_cast<int64_t>(row.func_ea)); break;
  case 1: ctx.result_int64(static_cast<int64_t>(row.chunk_start)); break;
  case 2: ctx.result_int64(static_cast<int64_t>(row.chunk_end)); break;
  case 3: ctx.result_int(row.block_count); break;
  case 4: ctx.result_int64(static_cast<int64_t>(row.total_size)); break;
  case 5: ctx.result_int(row.is_tail ? 1 : 0); break;
  case 6: ctx.result_int64(static_cast<int64_t>(row.flags)); break;
  default: ctx.result_null(); break;
  }
}

FunctionChunksInFuncIterator::FunctionChunksInFuncIterator(ea_t func_ea) {
  append_function_chunk_rows(func_ea, rows_);
}

bool FunctionChunksInFuncIterator::next() {
  ++idx_;
  return idx_ < static_cast<int>(rows_.size());
}

bool FunctionChunksInFuncIterator::eof() const {
  return idx_ >= static_cast<int>(rows_.size());
}

void FunctionChunksInFuncIterator::column(xsql::FunctionContext &ctx, int col) {
  if (idx_ < 0 || idx_ >= static_cast<int>(rows_.size())) {
    ctx.result_null();
    return;
  }
  function_chunk_column(ctx, rows_[idx_], col);
}

int64_t FunctionChunksInFuncIterator::rowid() const {
  if (idx_ < 0 || idx_ >= static_cast<int>(rows_.size()))
    return 0;
  return function_chunk_rowid(rows_[idx_]);
}

CachedTableDef<FunctionChunkInfo> define_function_chunks() {
  return cached_table<FunctionChunkInfo>("function_chunks")
      .no_shared_cache()
      .estimate_rows([]() -> size_t { return get_fchunk_qty(); })
      .cache_builder([](std::vector<FunctionChunkInfo> &cache) {
        cache.reserve(get_fchunk_qty());
        const size_t func_qty = get_func_qty();
        for (size_t i = 0; i < func_qty; i++) {
          // Cooperative cancellation across the per-function build.
          if ((i & 1023u) == 0 && xsql::vtab_interrupted()) {
            xsql::set_vtab_error(
                "query interrupted: timeout while building function_chunks");
            return;
          }
          const ea_t func_start = idasql_func_ea_by_num(i);
          if (func_start != BADADDR)
            append_function_chunk_rows(func_start, cache);
        }
      })
      .rowid([](const FunctionChunkInfo &row) -> int64_t {
        return function_chunk_rowid(row);
      })
      .column_int64("func_addr",
                    [](const FunctionChunkInfo &row) -> int64_t {
                      return static_cast<int64_t>(row.func_ea);
                    })
      .column_int64("chunk_start",
                    [](const FunctionChunkInfo &row) -> int64_t {
                      return static_cast<int64_t>(row.chunk_start);
                    })
      .column_int64("chunk_end",
                    [](const FunctionChunkInfo &row) -> int64_t {
                      return static_cast<int64_t>(row.chunk_end);
                    })
      .column_int(
          "block_count",
          [](const FunctionChunkInfo &row) -> int { return row.block_count; })
      .column_int64("total_size",
                    [](const FunctionChunkInfo &row) -> int64_t {
                      return static_cast<int64_t>(row.total_size);
                    })
      .column_int("is_tail",
                  [](const FunctionChunkInfo &row) -> int {
                    return row.is_tail ? 1 : 0;
                  })
      .column_int64("flags",
                    [](const FunctionChunkInfo &row) -> int64_t {
                      return static_cast<int64_t>(row.flags);
                    })
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<FunctionChunksInFuncIterator>(
                static_cast<ea_t>(func_addr));
          },
          2.0, 2.0)
      .build();
}

} // namespace code
} // namespace idasql
