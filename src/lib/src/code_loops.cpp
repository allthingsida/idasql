// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_loops.hpp"

#include "address_resolution.hpp"
#include "decompiler.hpp"

using namespace idasql::core;

namespace idasql {
namespace code {

void collect_loops_for_func(std::vector<LoopInfo> &loops, func_t *pfn) {
  if (!pfn)
    return;

  qflow_chart_t fc;
  fc.create("", pfn, pfn->start_ea, pfn->end_ea, FC_NOEXT);

  for (int i = 0; i < fc.size(); i++) {
    const qbasic_block_t &block = fc.blocks[i];

    for (int j = 0; j < fc.nsucc(i); j++) {
      int succ_idx = fc.succ(i, j);
      if (succ_idx < 0 || succ_idx >= fc.size())
        continue;

      const qbasic_block_t &succ = fc.blocks[succ_idx];

      if (succ.start_ea <= block.start_ea) {
        LoopInfo li;
        li.func_addr = pfn->start_ea;
        li.loop_id = succ_idx;
        li.header_ea = succ.start_ea;
        li.header_end_ea = succ.end_ea;
        li.back_edge_block_ea = block.start_ea;
        li.back_edge_block_end = block.end_ea;
        loops.push_back(li);
      }
    }
  }
}

// ============================================================================
// DisasmCallsInFuncIterator
// ============================================================================

class LoopsInFuncIterator : public xsql::RowIterator {
  std::vector<LoopInfo> loops_;
  size_t idx_ = 0;
  bool started_ = false;

public:
  explicit LoopsInFuncIterator(ea_t func_addr) {
    func_t *pfn = get_func(func_addr);
    if (pfn) {
      collect_loops_for_func(loops_, pfn);
    }
  }

  bool next() override {
    if (!started_) {
      started_ = true;
      if (loops_.empty())
        return false;
      idx_ = 0;
      return true;
    }
    if (idx_ + 1 < loops_.size()) {
      ++idx_;
      return true;
    }
    idx_ = loops_.size();
    return false;
  }

  bool eof() const override { return started_ && idx_ >= loops_.size(); }

  void column(xsql::FunctionContext &ctx, int col) override {
    if (idx_ >= loops_.size()) {
      ctx.result_null();
      return;
    }
    const auto &li = loops_[idx_];
    switch (col) {
    case 0:
      ctx.result_int64(static_cast<int64_t>(li.func_addr));
      break;
    case 1:
      ctx.result_int(li.loop_id);
      break;
    case 2:
      ctx.result_int64(static_cast<int64_t>(li.header_ea));
      break;
    case 3:
      ctx.result_int64(static_cast<int64_t>(li.header_end_ea));
      break;
    case 4:
      ctx.result_int64(static_cast<int64_t>(li.back_edge_block_ea));
      break;
    case 5:
      ctx.result_int64(static_cast<int64_t>(li.back_edge_block_end));
      break;
    }
  }

  int64_t rowid() const override { return static_cast<int64_t>(idx_); }
};

// ============================================================================
// DisasmLoopsGenerator
// ============================================================================

class DisasmLoopsGenerator : public xsql::Generator<LoopInfo> {
  size_t func_idx_ = 0;
  std::vector<LoopInfo> loops_;
  size_t idx_ = 0;
  int64_t rowid_ = -1;
  bool started_ = false;

  bool load_next_func() {
    size_t func_qty = get_func_qty();
    while (func_idx_ < func_qty) {
      func_t *pfn = getn_func(func_idx_++);
      if (!pfn)
        continue;

      loops_.clear();
      collect_loops_for_func(loops_, pfn);
      if (!loops_.empty()) {
        idx_ = 0;
        return true;
      }
    }
    return false;
  }

public:
  bool next() override {
    if (!started_) {
      started_ = true;
      if (!load_next_func())
        return false;
      rowid_ = 0;
      return true;
    }

    if (idx_ + 1 < loops_.size()) {
      ++idx_;
      ++rowid_;
      return true;
    }

    if (!load_next_func())
      return false;
    ++rowid_;
    return true;
  }

  const LoopInfo &current() const override { return loops_[idx_]; }
  int64_t rowid() const override { return rowid_; }
};

// ============================================================================
// Table definitions
// ============================================================================

GeneratorTableDef<LoopInfo> define_disasm_loops() {
  return generator_table<LoopInfo>("disasm_loops")
      .estimate_rows([]() -> size_t { return get_func_qty() * 2; })
      .generator([]() -> std::unique_ptr<xsql::Generator<LoopInfo>> {
        return std::make_unique<DisasmLoopsGenerator>();
      })
      .column_int64("func_addr",
                    [](const LoopInfo &r) -> int64_t { return r.func_addr; })
      .column_int("loop_id", [](const LoopInfo &r) -> int { return r.loop_id; })
      .column_int64("header_addr",
                    [](const LoopInfo &r) -> int64_t { return r.header_ea; })
      .column_int64(
          "header_end_addr",
          [](const LoopInfo &r) -> int64_t { return r.header_end_ea; })
      .column_int64(
          "back_edge_block_addr",
          [](const LoopInfo &r) -> int64_t { return r.back_edge_block_ea; })
      .column_int64(
          "back_edge_block_end",
          [](const LoopInfo &r) -> int64_t { return r.back_edge_block_end; })
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<LoopsInFuncIterator>(
                static_cast<ea_t>(func_addr));
          },
          5.0)
      .build();
}

// ============================================================================
// Helper: get callees/callers of a function
// ============================================================================

} // namespace code
} // namespace idasql
