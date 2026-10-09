// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_cfg.hpp"

#include "address_resolution.hpp"
#include "decompiler.hpp"
#include "function_rowid.hpp"

using namespace idasql::core;

namespace idasql {
namespace code {

namespace {

bool cfg_scan_interrupted() {
  if (!xsql::vtab_interrupted())
    return false;
  xsql::set_vtab_error("query interrupted while scanning cfg_edges");
  return true;
}

// The label of edge j out of two-way block i, from addresses, never successor
// order: the successor that starts where the block ends is the fall-through
// ("false"), the other the branch target ("true") -- the convention bnsql
// (TrueBranch/FalseBranch) and ghidrasql (CONDITIONAL_JUMP/FALL_THROUGH) follow.
// Block-end rather than "the instruction after the jump" also holds for
// delay-slot ISAs. A two-target switch is not a condition.
const char *two_way_edge_type(const idasql_flow_chart &fc, int i, int j) {
  const auto &b = fc.blocks[i];
  const ea_t last = prev_head(b.end_ea, b.start_ea);
  switch_info_t si;
  if (last != BADADDR && get_switch_info(&si, last) > 0)
    return "normal";
  const int s0 = fc.succ(i, 0);
  const int s1 = fc.succ(i, 1);
  if (s0 == s1)  // a conditional jump to the next instruction
    return j == 0 ? "false" : "true";
  const bool f0 = fc.blocks[s0].start_ea == b.end_ea;
  const bool f1 = fc.blocks[s1].start_ea == b.end_ea;
  if (f0 == f1)  // neither or both fall through: no polarity to report
    return "normal";
  return ((j == 0) ? f0 : f1) ? "false" : "true";
}

// The edges of one function, in block order. False when the query was interrupted.
bool collect_cfg_edges(ea_t func_ea, std::vector<CfgEdgeInfo> &out) {
  out.clear();
  if (cfg_scan_interrupted())
    return false;
  idasql_flow_chart fc;
  fc.create_func(func_ea, FC_NOEXT);
  if (cfg_scan_interrupted())
    return false;
  for (int i = 0; i < fc.size(); i++) {
    if ((i & 1023) == 0 && cfg_scan_interrupted()) {
      out.clear();
      return false;
    }
    const int nsucc = fc.nsucc(i);
    for (int j = 0; j < nsucc; j++) {
      const int succ_idx = fc.succ(i, j);
      if (succ_idx < 0 || succ_idx >= fc.size())
        continue;
      CfgEdgeInfo edge;
      edge.func_ea = func_ea;
      edge.from_addr = fc.blocks[i].start_ea;
      edge.to_addr = fc.blocks[succ_idx].start_ea;
      // One successor is plain flow; three or more is a switch.
      edge.edge_type = nsucc == 2 ? two_way_edge_type(fc, i, j) : "normal";
      out.push_back(std::move(edge));
    }
  }
  if (cfg_scan_interrupted()) {
    out.clear();
    return false;
  }
  return true;
}

}  // namespace

class CfgEdgesInFuncIterator : public xsql::RowIterator {
  std::vector<CfgEdgeInfo> edges_;
  size_t idx_ = 0;
  bool started_ = false;

public:
  explicit CfgEdgesInFuncIterator(ea_t func_ea) {
    if (!idasql_is_func_start(func_ea))
      return;
    (void)collect_cfg_edges(func_ea, edges_);
  }

  bool next() override {
    if (!started_) {
      started_ = true;
      if (edges_.empty())
        return false;
      idx_ = 0;
      return true;
    }
    if (idx_ + 1 < edges_.size()) {
      ++idx_;
      return true;
    }
    idx_ = edges_.size();
    return false;
  }

  bool eof() const override { return started_ && idx_ >= edges_.size(); }

  void column(xsql::FunctionContext &ctx, int col) override {
    if (idx_ >= edges_.size()) {
      ctx.result_null();
      return;
    }
    const auto &e = edges_[idx_];
    switch (col) {
    case 0:
      ctx.result_int64(static_cast<int64_t>(e.func_ea));
      break;
    case 1:
      ctx.result_int64(static_cast<int64_t>(e.from_addr));
      break;
    case 2:
      ctx.result_int64(static_cast<int64_t>(e.to_addr));
      break;
    case 3:
      ctx.result_text(e.edge_type);
      break;
    default:
      ctx.result_null();
      break;
    }
  }

  int64_t rowid() const override {
    return idx_ < edges_.size()
               ? idasql::detail::pack_function_rowid(edges_[idx_].func_ea, idx_)
               : -1;
  }
};

class CfgEdgesGenerator : public xsql::Generator<CfgEdgeInfo> {
  size_t func_idx_ = 0;
  std::vector<CfgEdgeInfo> current_edges_;
  size_t edge_idx_ = 0;

  bool load_next_func() {
    size_t func_qty = get_func_qty();
    while (func_idx_ < func_qty) {
      if (cfg_scan_interrupted())
        return false;
      const ea_t func_ea = idasql_func_ea_by_num(func_idx_++);
      if (func_ea == BADADDR)
        continue;

      if (!collect_cfg_edges(func_ea, current_edges_))
        return false;

      if (!current_edges_.empty()) {
        edge_idx_ = 0;
        return true;
      }
    }
    return false;
  }

public:
  bool next() override {
    // Try next edge in current function
    if (!current_edges_.empty() && edge_idx_ + 1 < current_edges_.size()) {
      ++edge_idx_;
      return true;
    }
    // Load next function
    if (load_next_func()) {
      return true;
    }
    return false;
  }

  const CfgEdgeInfo &current() const override {
    return current_edges_[edge_idx_];
  }
  int64_t rowid() const override {
    return idasql::detail::pack_function_rowid(
        current_edges_[edge_idx_].func_ea, edge_idx_);
  }
};

GeneratorTableDef<CfgEdgeInfo> define_cfg_edges() {
  return xsql::generator_table<CfgEdgeInfo>("cfg_edges")
      .generator([]() -> std::unique_ptr<xsql::Generator<CfgEdgeInfo>> {
        return std::make_unique<CfgEdgesGenerator>();
      })
      .column_int64("func_addr",
                    [](const CfgEdgeInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.func_ea);
                    })
      .column_int64("from_addr",
                    [](const CfgEdgeInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.from_addr);
                    })
      .column_int64("to_addr",
                    [](const CfgEdgeInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.to_addr);
                    })
      .column_text(
          "edge_type",
          [](const CfgEdgeInfo &r) -> std::string { return r.edge_type; })
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<CfgEdgesInFuncIterator>(
                static_cast<ea_t>(func_addr));
          },
          1.0, 20.0)
      .build();
}

// ============================================================================
// Views
// ============================================================================

bool register_disasm_views(xsql::Database &db) {
  const char *v_leaf_funcs = R"(
        CREATE VIEW IF NOT EXISTS disasm_v_leaf_funcs AS
        SELECT f.addr, f.name
        FROM funcs f
        LEFT JOIN disasm_calls c ON c.func_addr = f.addr
        GROUP BY f.addr
        HAVING COUNT(c.callee_addr) = 0
    )";
  db.exec(v_leaf_funcs);

  // disasm_v_call_chains: thin wrapper over call_graph table.
  // For targeted traversal, use call_graph directly:
  //   SELECT * FROM call_graph WHERE start=X AND direction='down' AND
  //   max_depth=10
  const char *v_call_chains = R"(
        CREATE VIEW IF NOT EXISTS disasm_v_call_chains AS
        WITH RECURSIVE call_chain(root_func, current_func, depth) AS (
            SELECT DISTINCT func_addr, callee_addr, 1
            FROM disasm_calls
            WHERE callee_addr IS NOT NULL AND callee_addr != 0

            UNION ALL

            SELECT cc.root_func, c.callee_addr, cc.depth + 1
            FROM call_chain cc
            JOIN disasm_calls c ON c.func_addr = cc.current_func
            WHERE cc.depth < 10
              AND c.callee_addr IS NOT NULL
              AND c.callee_addr != 0
        )
        SELECT DISTINCT
            root_func,
            current_func,
            depth
        FROM call_chain
    )";
  db.exec(v_call_chains);

  const char *v_calls_in_loops = R"(
        CREATE VIEW IF NOT EXISTS disasm_v_calls_in_loops AS
        SELECT
            c.func_addr,
            c.addr,
            c.callee_addr,
            c.callee_name,
            l.loop_id,
            l.header_addr as loop_header,
            l.back_edge_block_addr,
            l.back_edge_block_end
        FROM disasm_calls c
        JOIN disasm_loops l ON l.func_addr = c.func_addr
        WHERE c.addr >= MIN(l.header_addr, l.back_edge_block_addr)
          AND c.addr < MAX(l.header_end_addr, l.back_edge_block_end)
    )";
  db.exec(v_calls_in_loops);

  const char *v_funcs_with_loops = R"(
        CREATE VIEW IF NOT EXISTS disasm_v_funcs_with_loops AS
        SELECT
            f.addr,
            f.name,
            COUNT(DISTINCT l.loop_id) as loop_count
        FROM funcs f
        JOIN disasm_loops l ON l.func_addr = f.addr
        GROUP BY f.addr
    )";
  db.exec(v_funcs_with_loops);

  return true;
}

// ============================================================================
// Registry
// ============================================================================

} // namespace code
} // namespace idasql
