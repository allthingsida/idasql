// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_cfg.hpp"

#include "address_resolution.hpp"
#include "decompiler.hpp"

using namespace idasql::core;

namespace idasql {
namespace code {

class CfgEdgesInFuncIterator : public xsql::RowIterator {
  std::vector<CfgEdgeInfo> edges_;
  size_t idx_ = 0;
  bool started_ = false;

public:
  explicit CfgEdgesInFuncIterator(ea_t func_ea) {
    func_t *pfn = get_func(func_ea);
    if (!pfn)
      return;

    qflow_chart_t fc;
    fc.create("", pfn, pfn->start_ea, pfn->end_ea, FC_NOEXT);

    for (int i = 0; i < fc.size(); i++) {
      int nsucc = fc.nsucc(i);
      for (int j = 0; j < nsucc; j++) {
        int succ_idx = fc.succ(i, j);
        if (succ_idx < 0 || succ_idx >= fc.size())
          continue;

        CfgEdgeInfo edge;
        edge.func_ea = pfn->start_ea;
        edge.from_block = fc.blocks[i].start_ea;
        edge.to_block = fc.blocks[succ_idx].start_ea;

        if (nsucc == 1) {
          edge.edge_type = "normal";
        } else if (nsucc == 2) {
          edge.edge_type = (j == 0) ? "true" : "false";
        } else {
          // Switch/multi-way branch
          edge.edge_type = "normal";
        }

        edges_.push_back(std::move(edge));
      }
    }
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
      ctx.result_int64(static_cast<int64_t>(e.from_block));
      break;
    case 2:
      ctx.result_int64(static_cast<int64_t>(e.to_block));
      break;
    case 3:
      ctx.result_text(e.edge_type);
      break;
    default:
      ctx.result_null();
      break;
    }
  }

  int64_t rowid() const override { return static_cast<int64_t>(idx_); }
};

class CfgEdgesGenerator : public xsql::Generator<CfgEdgeInfo> {
  size_t func_idx_ = 0;
  std::vector<CfgEdgeInfo> current_edges_;
  size_t edge_idx_ = 0;

  bool load_next_func() {
    size_t func_qty = get_func_qty();
    while (func_idx_ < func_qty) {
      func_t *pfn = getn_func(func_idx_++);
      if (!pfn)
        continue;

      current_edges_.clear();
      qflow_chart_t fc;
      fc.create("", pfn, pfn->start_ea, pfn->end_ea, FC_NOEXT);

      for (int i = 0; i < fc.size(); i++) {
        int nsucc = fc.nsucc(i);
        for (int j = 0; j < nsucc; j++) {
          int succ_idx = fc.succ(i, j);
          if (succ_idx < 0 || succ_idx >= fc.size())
            continue;

          CfgEdgeInfo edge;
          edge.func_ea = pfn->start_ea;
          edge.from_block = fc.blocks[i].start_ea;
          edge.to_block = fc.blocks[succ_idx].start_ea;
          if (nsucc == 1)
            edge.edge_type = "normal";
          else if (nsucc == 2)
            edge.edge_type = (j == 0) ? "true" : "false";
          else
            edge.edge_type = "normal";
          current_edges_.push_back(std::move(edge));
        }
      }

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
    return load_next_func();
  }

  const CfgEdgeInfo &current() const override {
    return current_edges_[edge_idx_];
  }
  int64_t rowid() const override {
    return static_cast<int64_t>(current_edges_[edge_idx_].from_block);
  }
};

GeneratorTableDef<CfgEdgeInfo> define_cfg_edges() {
  return xsql::generator_table<CfgEdgeInfo>("cfg_edges")
      .column_int64("func_addr",
                    [](const CfgEdgeInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.func_ea);
                    })
      .column_int64("from_block",
                    [](const CfgEdgeInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.from_block);
                    })
      .column_int64("to_block",
                    [](const CfgEdgeInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.to_block);
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
        WHERE c.addr >= l.header_addr AND c.addr < l.back_edge_block_end
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
