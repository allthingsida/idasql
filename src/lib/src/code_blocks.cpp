// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_blocks.hpp"

using namespace idasql::core;

namespace idasql {
namespace code {

// ============================================================================
// BLOCKS Table (basic blocks)
// ============================================================================

BlocksInFuncIterator::BlocksInFuncIterator(ea_t func_ea) : func_ea_(func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn) {
    fc_.create("", pfn, pfn->start_ea, pfn->end_ea, FC_NOEXT);
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
  return static_cast<int64_t>(fc_.blocks[idx_].start_ea);
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
          func_t *func = getn_func(i);
          if (!func)
            continue;

          qflow_chart_t fc;
          fc.create("", func, func->start_ea, func->end_ea, FC_NOEXT);

          for (int j = 0; j < fc.size(); j++) {
            const qbasic_block_t &bb = fc.blocks[j];
            BlockInfo bi;
            bi.func_ea = func->start_ea;
            bi.start_ea = bb.start_ea;
            bi.end_ea = bb.end_ea;
            cache.push_back(bi);
          }
        }
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

CachedTableDef<FunctionChunkInfo> define_function_chunks() {
  return cached_table<FunctionChunkInfo>("function_chunks")
      .no_shared_cache()
      .estimate_rows([]() -> size_t { return get_fchunk_qty(); })
      .cache_builder([](std::vector<FunctionChunkInfo> &cache) {
        size_t chunk_qty = get_fchunk_qty();
        cache.reserve(chunk_qty);

        for (size_t i = 0; i < chunk_qty; i++) {
          // Cooperative cancellation across the per-chunk build.
          if ((i & 1023u) == 0 && xsql::vtab_interrupted()) {
            xsql::set_vtab_error(
                "query interrupted: timeout while building function_chunks");
            return;
          }
          func_t *chunk = getn_fchunk(static_cast<int>(i));
          if (!chunk)
            continue;

          func_t *owner = get_func(chunk->start_ea);
          if (!owner)
            continue;

          FunctionChunkInfo row;
          row.func_ea = owner->start_ea;
          row.chunk_start = chunk->start_ea;
          row.chunk_end = chunk->end_ea;
          row.total_size = chunk->size();

          // block_count must count THIS chunk's basic blocks, not the whole
          // owner function's. qflow_chart_t::create ignores the [ea1, ea2) range
          // when a non-null pfn is passed (it charts the entire function), so
          // pass nullptr with the chunk bounds to chart only [chunk_start,
          // chunk_end) -- otherwise every chunk of a function reports the same
          // function-wide block count.
          qflow_chart_t fc;
          fc.create("", nullptr, chunk->start_ea, chunk->end_ea, FC_NOEXT);
          row.block_count = fc.size();

          cache.push_back(row);
        }
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
      .build();
}

} // namespace code
} // namespace idasql
