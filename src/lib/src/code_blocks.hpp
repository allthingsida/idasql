// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace code {

struct BlockInfo {
  ea_t func_ea;
  ea_t start_ea;
  ea_t end_ea;
  int index = 0;
};

struct FunctionChunkInfo {
  ea_t func_ea = BADADDR;
  ea_t chunk_start = BADADDR;
  ea_t chunk_end = BADADDR;
  int block_count = 0;
  asize_t total_size = 0;
  bool is_tail = false;
  uint64 flags = 0;
  size_t index = 0;
};

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

}
}
