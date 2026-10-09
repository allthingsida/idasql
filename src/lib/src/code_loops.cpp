// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_loops.hpp"

#include "address_resolution.hpp"
#include "code_graph_tables.hpp"
#include "decompiler.hpp"
#include "function_rowid.hpp"

using namespace idasql::core;

namespace idasql {
namespace code {

// One row per natural-loop back edge: a latch -> header edge where the header
// dominates the latch (the `loops` table's definition). Address order is not
// used: a forward jump into a lower-addressed tail or cold block is not a loop.
// func_ea must be a function's entry address (a function key, as on every
// table); loop_id is the header's block index.
void collect_loops_for_func(std::vector<LoopInfo> &loops, ea_t func_ea) {
  if (!idasql_is_func_start(func_ea))
    return;
  xsql::graph::DirectedGraph g(0);
  std::vector<ea_t> addr, end_ea;
  size_t entry = 0;
  if (!build_func_graph(func_ea, g, addr, end_ea, entry))
    return;
  for (const auto &lp : xsql::graph::natural_loops(g, entry)) {
    LoopInfo li;
    li.func_addr = func_ea;
    li.loop_id = static_cast<int>(lp.header);
    li.header_ea = addr[lp.header];
    li.header_end_ea = end_ea[lp.header];
    li.back_edge_block_ea = addr[lp.latch];
    li.back_edge_block_end = end_ea[lp.latch];
    loops.push_back(li);
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
    collect_loops_for_func(loops_, func_addr);
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

  int64_t rowid() const override {
    return idx_ < loops_.size() ? idasql::detail::pack_function_rowid(loops_[idx_].func_addr, idx_) : -1;
  }
};

// ============================================================================
// DisasmLoopsGenerator
// ============================================================================

class DisasmLoopsGenerator : public xsql::Generator<LoopInfo> {
  size_t func_idx_ = 0;
  std::vector<LoopInfo> loops_;
  size_t idx_ = 0;
  bool started_ = false;

  bool load_next_func() {
    size_t func_qty = get_func_qty();
    while (func_idx_ < func_qty) {
      const ea_t func_ea = idasql_func_ea_by_num(func_idx_++);
      if (func_ea == BADADDR)
        continue;

      loops_.clear();
      collect_loops_for_func(loops_, func_ea);
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
      return load_next_func();
    }

    if (idx_ + 1 < loops_.size()) {
      ++idx_;
      return true;
    }

    return load_next_func();
  }

  const LoopInfo &current() const override { return loops_[idx_]; }
  // (function, back edge index): the same on the full scan and the pushdown.
  int64_t rowid() const override {
    return idasql::detail::pack_function_rowid(loops_[idx_].func_addr, idx_);
  }
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
