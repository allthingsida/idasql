// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// dominators / post_dominators / loops — canonical cross-tool CFG-graph tables.
// Each maps a function's flow-chart basic blocks onto opaque node
// ids and runs the generic RE-agnostic xsql::graph module; the address mapping stays
// entirely here.

#include "code_graph_tables.hpp"
#include "function_rowid.hpp"

#include <algorithm>
#include <set>

#include <xsql/graph.hpp>

using namespace idasql::core;

namespace idasql {
namespace code {

namespace {

// `func_ea` when it is a function's entry address, else BADADDR: func_addr is
// the owner's ENTRY address, and an interior or tail address matches nothing.
ea_t func_start_at(ea_t func_ea) {
  return idasql_is_func_start(func_ea) ? func_ea : BADADDR;
}

bool graph_scan_interrupted() {
  if (!xsql::vtab_interrupted())
    return false;
  xsql::set_vtab_error("query interrupted while scanning CFG graph tables");
  return true;
}

}  // namespace

// Build the block-level CFG of one function: a DirectedGraph over block ids plus the
// id->address and id->end maps and the entry block id. `func_ea` is the
// function's entry address. Returns false for BADADDR or an empty flow chart.
bool build_func_graph(ea_t func_ea, xsql::graph::DirectedGraph &g_out,
                      std::vector<ea_t> &addr, std::vector<ea_t> &end_ea,
                      size_t &entry) {
  if (func_ea == BADADDR)
    return false;
  if (graph_scan_interrupted())
    return false;
  idasql_flow_chart fc;
  if (!fc.create_func(func_ea, FC_NOEXT))
    return false;
  if (graph_scan_interrupted())
    return false;
  const int n = fc.size();
  if (n <= 0)
    return false;

  addr.assign(static_cast<size_t>(n), BADADDR);
  end_ea.assign(static_cast<size_t>(n), BADADDR);
  entry = 0;
  for (int i = 0; i < n; ++i) {
    if ((i & 1023) == 0 && graph_scan_interrupted())
      return false;
    addr[i] = fc.blocks[i].start_ea;
    end_ea[i] = fc.blocks[i].end_ea;
    if (fc.blocks[i].start_ea == func_ea)
      entry = static_cast<size_t>(i);
  }

  xsql::graph::DirectedGraph g(static_cast<size_t>(n));
  for (int i = 0; i < n; ++i) {
    if ((i & 1023) == 0 && graph_scan_interrupted())
      return false;
    const int ns = fc.nsucc(i);
    for (int j = 0; j < ns; ++j) {
      int s = fc.succ(i, j);
      if (s >= 0 && s < n)
        g.add_edge(static_cast<size_t>(i), static_cast<size_t>(s));
    }
  }
  if (graph_scan_interrupted())
    return false;
  g_out = std::move(g);
  return true;
}

namespace {

// Depth of every node in a (post)dominator tree given as parent links (kNoNode at
// a root): each chain is walked once and memoised, so a long chain costs O(n),
// not O(n * depth). -1 for a node with no path to a root. False on interrupt.
bool tree_depths(const std::vector<size_t> &parent, std::vector<int64_t> &depth) {
  const size_t n = parent.size();
  depth.assign(n, -1);
  std::vector<size_t> chain;
  for (size_t v = 0; v < n; ++v) {
    if ((v & 1023u) == 0 && graph_scan_interrupted())
      return false;
    size_t cur = v;
    chain.clear();
    while (depth[cur] < 0) {
      chain.push_back(cur);
      if (parent[cur] == xsql::graph::kNoNode) {
        depth[cur] = 0;
        chain.pop_back();
        break;
      }
      cur = parent[cur];
      if (chain.size() > n)  // a cycle: not a tree
        return false;
    }
    for (int64_t d = depth[cur]; !chain.empty(); chain.pop_back())
      depth[chain.back()] = ++d;
  }
  return true;
}

void collect_dominators(ea_t func_ea, std::vector<DominatorRow> &out) {
  xsql::graph::DirectedGraph g(0);
  std::vector<ea_t> addr, end_ea;
  size_t entry = 0;
  if (!build_func_graph(func_ea, g, addr, end_ea, entry))
    return;
  auto idom = xsql::graph::immediate_dominators(g, entry);
  if (graph_scan_interrupted())
    return;
  // The entry is the tree's root (immediate_dominators may name it its own idom).
  std::vector<size_t> parent(idom.begin(), idom.end());
  if (entry < parent.size())
    parent[entry] = xsql::graph::kNoNode;
  std::vector<int64_t> depths;
  if (!tree_depths(parent, depths))
    return;
  for (size_t i = 0; i < g.node_count(); ++i) {
    if ((i & 1023u) == 0 && graph_scan_interrupted()) {
      out.clear();
      return;
    }
    if (idom[i] == xsql::graph::kNoNode)
      continue;  // unreachable from entry
    DominatorRow r;
    r.func_ea = func_ea;
    r.node_addr = addr[i];
    r.is_entry = (i == entry);
    if (i == entry) {
      r.has_idom = false;
      r.depth = 0;
    } else {
      r.has_idom = true;
      r.idom_addr = addr[idom[i]];
      r.depth = depths[i];
    }
    out.push_back(std::move(r));
  }
  if (graph_scan_interrupted())
    out.clear();
}

void collect_post_dominators(ea_t func_ea, std::vector<PostDominatorRow> &out) {
  xsql::graph::DirectedGraph g(0);
  std::vector<ea_t> addr, end_ea;
  size_t entry = 0;
  if (!build_func_graph(func_ea, g, addr, end_ea, entry))
    return;
  auto ipdom = xsql::graph::immediate_post_dominators(g);
  if (graph_scan_interrupted())
    return;
  std::vector<int64_t> depths;
  if (!tree_depths(std::vector<size_t>(ipdom.begin(), ipdom.end()), depths))
    return;
  for (size_t i = 0; i < g.node_count(); ++i) {
    if ((i & 1023u) == 0 && graph_scan_interrupted()) {
      out.clear();
      return;
    }
    PostDominatorRow r;
    r.func_ea = func_ea;
    r.node_addr = addr[i];
    r.is_exit = g.successors(i).empty();  // a function sink
    if (ipdom[i] == xsql::graph::kNoNode) {
      r.has_ipdom = false;
      r.depth = 0;
    } else {
      r.has_ipdom = true;
      r.ipdom_addr = addr[ipdom[i]];
      r.depth = depths[i];
    }
    out.push_back(std::move(r));
  }
  if (graph_scan_interrupted())
    out.clear();
}

void collect_loops(ea_t func_ea, std::vector<LoopRow> &out) {
  xsql::graph::DirectedGraph g(0);
  std::vector<ea_t> addr, end_ea;
  size_t entry = 0;
  if (!build_func_graph(func_ea, g, addr, end_ea, entry))
    return;
  auto loops = xsql::graph::natural_loops(g, entry);
  if (graph_scan_interrupted())
    return;
  for (size_t li = 0; li < loops.size(); ++li) {
    if ((li & 1023u) == 0 && graph_scan_interrupted()) {
      out.clear();
      return;
    }
    const auto &lp = loops[li];
    LoopRow r;
    r.func_ea = func_ea;
    r.header_addr = addr[lp.header];
    r.latch_addr = addr[lp.latch];
    r.block_count = static_cast<int64_t>(lp.body.size());
    r.loop_kind = "natural";
    ea_t mn = BADADDR, mx = 0;
    for (size_t b : lp.body) {
      if (mn == BADADDR || addr[b] < mn)
        mn = addr[b];
      if (end_ea[b] > mx)
        mx = end_ea[b];
    }
    r.start_addr = mn;
    r.end_addr = mx;
    // Nesting depth: 1 + number of loops whose body strictly contains this one's
    // (bodies are sorted, so std::includes works directly).
    int64_t depth = 1;
    for (size_t lj = 0; lj < loops.size(); ++lj) {
      if ((lj & 1023u) == 0 && graph_scan_interrupted()) {
        out.clear();
        return;
      }
      if (lj == li)
        continue;
      const auto &oth = loops[lj].body;
      if (oth.size() > lp.body.size() &&
          std::includes(oth.begin(), oth.end(), lp.body.begin(), lp.body.end()))
        ++depth;
    }
    r.depth = depth;
    out.push_back(std::move(r));
  }
  if (graph_scan_interrupted())
    out.clear();
}

// ---- per-table column emission (shared by the generator and filter_eq cursor) ----

void emit_column(xsql::FunctionContext &ctx, int col, const DominatorRow &r) {
  switch (col) {
  case 0: ctx.result_int64(static_cast<int64_t>(r.func_ea)); break;
  case 1: ctx.result_int64(static_cast<int64_t>(r.node_addr)); break;
  case 2:
    if (r.has_idom) ctx.result_int64(static_cast<int64_t>(r.idom_addr));
    else ctx.result_null();
    break;
  case 3: ctx.result_int64(r.depth); break;
  case 4: ctx.result_int64(r.is_entry ? 1 : 0); break;
  default: ctx.result_null(); break;
  }
}

void emit_column(xsql::FunctionContext &ctx, int col, const PostDominatorRow &r) {
  switch (col) {
  case 0: ctx.result_int64(static_cast<int64_t>(r.func_ea)); break;
  case 1: ctx.result_int64(static_cast<int64_t>(r.node_addr)); break;
  case 2:
    if (r.has_ipdom) ctx.result_int64(static_cast<int64_t>(r.ipdom_addr));
    else ctx.result_null();
    break;
  case 3: ctx.result_int64(r.depth); break;
  case 4: ctx.result_int64(r.is_exit ? 1 : 0); break;
  default: ctx.result_null(); break;
  }
}

void emit_column(xsql::FunctionContext &ctx, int col, const LoopRow &r) {
  switch (col) {
  case 0: ctx.result_int64(static_cast<int64_t>(r.func_ea)); break;
  case 1: ctx.result_int64(static_cast<int64_t>(r.header_addr)); break;
  case 2: ctx.result_int64(static_cast<int64_t>(r.latch_addr)); break;
  case 3: ctx.result_int64(static_cast<int64_t>(r.start_addr)); break;
  case 4: ctx.result_int64(static_cast<int64_t>(r.end_addr)); break;
  case 5: ctx.result_int64(r.depth); break;
  case 6: ctx.result_text(r.loop_kind); break;
  case 7: ctx.result_int64(r.block_count); break;
  default: ctx.result_null(); break;
  }
}

// ---- generic vector-backed cursor helpers (one collect() per table) ----

template <typename Row>
class VecIterator : public xsql::RowIterator {
public:
  std::vector<Row> rows_;
  size_t idx_ = 0;
  bool started_ = false;

  bool next() override {
    if (!started_) {
      started_ = true;
      idx_ = 0;
      return !rows_.empty();
    }
    if (idx_ + 1 < rows_.size()) {
      ++idx_;
      return true;
    }
    idx_ = rows_.size();
    return false;
  }
  bool eof() const override { return started_ && idx_ >= rows_.size(); }
  void column(xsql::FunctionContext &ctx, int col) override {
    if (idx_ >= rows_.size()) {
      ctx.result_null();
      return;
    }
    emit_column(ctx, col, rows_[idx_]);
  }
  int64_t rowid() const override {
    return idx_ < rows_.size()
               ? idasql::detail::pack_function_rowid(rows_[idx_].func_ea, idx_)
               : -1;
  }
};

template <typename Row, typename Collect>
class VecGenerator : public xsql::Generator<Row> {
  Collect collect_;
  size_t func_idx_ = 0;
  std::vector<Row> current_;
  size_t row_idx_ = 0;

  bool load_next_func() {
    size_t qty = get_func_qty();
    while (func_idx_ < qty) {
      if (graph_scan_interrupted())
        return false;
      const ea_t func_ea = idasql_func_ea_by_num(func_idx_++);
      if (func_ea == BADADDR)
        continue;
      current_.clear();
      collect_(func_ea, current_);
      if (!current_.empty()) {
        row_idx_ = 0;
        return true;
      }
    }
    return false;
  }

public:
  explicit VecGenerator(Collect collect) : collect_(collect) {}
  bool next() override {
    if (!current_.empty() && row_idx_ + 1 < current_.size()) {
      ++row_idx_;
      return true;
    }
    if (load_next_func()) {
      return true;
    }
    return false;
  }
  const Row &current() const override { return current_[row_idx_]; }
  int64_t rowid() const override {
    return idasql::detail::pack_function_rowid(current_[row_idx_].func_ea,
                                               row_idx_);
  }
};

}  // namespace

GeneratorTableDef<DominatorRow> define_dominators() {
  return xsql::generator_table<DominatorRow>("dominators")
      .generator([]() -> std::unique_ptr<xsql::Generator<DominatorRow>> {
        return std::make_unique<VecGenerator<DominatorRow, decltype(&collect_dominators)>>(
            &collect_dominators);
      })
      .column_int64("func_addr",
                    [](const DominatorRow &r) { return static_cast<int64_t>(r.func_ea); })
      .column_int64("node_addr",
                    [](const DominatorRow &r) { return static_cast<int64_t>(r.node_addr); })
      .column("idom_addr", xsql::ColumnType::Integer,
              [](xsql::FunctionContext &ctx, const DominatorRow &r) {
                if (r.has_idom)
                  ctx.result_int64(static_cast<int64_t>(r.idom_addr));
                else
                  ctx.result_null();
              })
      .column_int64("depth", [](const DominatorRow &r) { return r.depth; })
      .column_int64("is_entry",
                    [](const DominatorRow &r) { return r.is_entry ? 1 : 0; })
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            auto it = std::make_unique<VecIterator<DominatorRow>>();
            collect_dominators(
                func_start_at(static_cast<ea_t>(func_addr)), it->rows_);
            return it;
          },
          1.0, 8.0)
      .build();
}

GeneratorTableDef<PostDominatorRow> define_post_dominators() {
  return xsql::generator_table<PostDominatorRow>("post_dominators")
      .generator([]() -> std::unique_ptr<xsql::Generator<PostDominatorRow>> {
        return std::make_unique<
            VecGenerator<PostDominatorRow, decltype(&collect_post_dominators)>>(
            &collect_post_dominators);
      })
      .column_int64("func_addr",
                    [](const PostDominatorRow &r) { return static_cast<int64_t>(r.func_ea); })
      .column_int64("node_addr",
                    [](const PostDominatorRow &r) { return static_cast<int64_t>(r.node_addr); })
      .column("ipdom_addr", xsql::ColumnType::Integer,
              [](xsql::FunctionContext &ctx, const PostDominatorRow &r) {
                if (r.has_ipdom)
                  ctx.result_int64(static_cast<int64_t>(r.ipdom_addr));
                else
                  ctx.result_null();
              })
      .column_int64("depth", [](const PostDominatorRow &r) { return r.depth; })
      .column_int64("is_exit",
                    [](const PostDominatorRow &r) { return r.is_exit ? 1 : 0; })
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            auto it = std::make_unique<VecIterator<PostDominatorRow>>();
            collect_post_dominators(
                func_start_at(static_cast<ea_t>(func_addr)), it->rows_);
            return it;
          },
          1.0, 8.0)
      .build();
}

GeneratorTableDef<LoopRow> define_loops() {
  return xsql::generator_table<LoopRow>("loops")
      .generator([]() -> std::unique_ptr<xsql::Generator<LoopRow>> {
        return std::make_unique<VecGenerator<LoopRow, decltype(&collect_loops)>>(
            &collect_loops);
      })
      .column_int64("func_addr",
                    [](const LoopRow &r) { return static_cast<int64_t>(r.func_ea); })
      .column_int64("header_addr",
                    [](const LoopRow &r) { return static_cast<int64_t>(r.header_addr); })
      .column_int64("latch_addr",
                    [](const LoopRow &r) { return static_cast<int64_t>(r.latch_addr); })
      .column_int64("start_addr",
                    [](const LoopRow &r) { return static_cast<int64_t>(r.start_addr); })
      .column_int64("end_addr",
                    [](const LoopRow &r) { return static_cast<int64_t>(r.end_addr); })
      .column_int64("depth", [](const LoopRow &r) { return r.depth; })
      .column_text("loop_kind", [](const LoopRow &r) { return r.loop_kind; })
      .column_int64("block_count", [](const LoopRow &r) { return r.block_count; })
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            auto it = std::make_unique<VecIterator<LoopRow>>();
            collect_loops(
                func_start_at(static_cast<ea_t>(func_addr)), it->rows_);
            return it;
          },
          1.0, 4.0)
      .build();
}

} // namespace code
} // namespace idasql
