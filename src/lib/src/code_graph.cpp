// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_graph.hpp"

#include "address_resolution.hpp"
#include "decompiler.hpp"

#include <queue>
#include <unordered_set>

using namespace idasql::core;

namespace idasql {
namespace code {

namespace {

void append_unique_function(std::vector<ea_t> &funcs,
                            std::unordered_set<ea_t> &seen, ea_t func_ea) {
  if (func_ea == BADADDR)
    return;
  if (seen.insert(func_ea).second) {
    funcs.push_back(func_ea);
  }
}

int clamp_call_graph_depth(int max_depth) {
  if (max_depth <= 0)
    return 0;
  if (max_depth > 100)
    return 100;
  return max_depth;
}

int clamp_shortest_path_depth(int max_depth) {
  if (max_depth <= 0)
    return 1;
  if (max_depth > 100)
    return 100;
  return max_depth;
}

} // namespace

void get_function_callees(ea_t func_addr, std::vector<ea_t> &callees) {
  func_t *pfn = get_func(func_addr);
  if (!pfn)
    return;

  func_item_iterator_t fii;
  if (!fii.set(pfn))
    return;

  std::unordered_set<ea_t> seen(callees.begin(), callees.end());

  auto collect_callees_from_item = [&](ea_t ea) {
    insn_t insn;
    const bool decoded = decode_insn(&insn, ea) > 0;
    if (decoded && is_call_insn(insn)) {
      ea_t callee = get_first_fcref_from(ea);
      if (callee != BADADDR) {
        func_t *callee_fn = get_func(callee);
        if (callee_fn) {
          append_unique_function(callees, seen, callee_fn->start_ea);
        }
      }
    }

    xrefblk_t xb;
    // XREF_NOFLOW: keep call/jump code xrefs but skip ordinary fall-through
    // flow xrefs, which would otherwise create phantom call edges.
    for (bool ok = xb.first_from(ea, XREF_NOFLOW); ok; ok = xb.next_from()) {
      if (!xb.iscode)
        continue;

      func_t *callee_fn = get_func(xb.to);
      if (!callee_fn)
        continue;
      if (callee_fn->start_ea != xb.to)
        continue;

      append_unique_function(callees, seen, callee_fn->start_ea);
    }
  };

  collect_callees_from_item(fii.current());
  while (fii.next_code()) {
    collect_callees_from_item(fii.current());
  }
}

void get_function_callers(ea_t func_addr, std::vector<ea_t> &callers) {
  xrefblk_t xb;
  // XREF_NOFLOW: keep call/jump code xrefs but skip ordinary fall-through
  // flow xrefs, which would otherwise create phantom caller edges.
  for (bool ok = xb.first_to(func_addr, XREF_NOFLOW); ok; ok = xb.next_to()) {
    if (!xb.iscode)
      continue;
    func_t *caller_fn = get_func(xb.from);
    if (caller_fn)
      callers.push_back(caller_fn->start_ea);
  }
}

// ============================================================================
// CallGraphGenerator - BFS traversal of the call graph
// ============================================================================

class CallGraphGenerator : public xsql::Generator<CallGraphRow> {
  std::vector<CallGraphRow> results_;
  size_t pos_ = 0;

public:
  CallGraphGenerator(ea_t start, const std::string &direction, int max_depth) {
    // Validate start is a function
    func_t *start_fn = get_func(start);
    if (!start_fn)
      return;
    ea_t start_ea = start_fn->start_ea;

    bool go_down = (direction == "down" || direction == "both");
    bool go_up = (direction == "up" || direction == "both");

    std::unordered_set<ea_t> visited;
    // queue: (func_addr, depth, parent_addr)
    std::queue<std::tuple<ea_t, int, ea_t>> queue;

    queue.push({start_ea, 0, BADADDR});
    visited.insert(start_ea);

    uint64_t scanned = 0;
    while (!queue.empty()) {
      // Cooperative cancellation -- honor the query deadline on huge graphs.
      if (((++scanned) & 4095u) == 0 && xsql::vtab_interrupted()) {
        xsql::set_vtab_error(
            "query interrupted: timeout while building call_graph");
        results_.clear();
        return;
      }
      auto [func_ea, depth, parent] = queue.front();
      queue.pop();

      CallGraphRow row;
      row.func_addr = func_ea;
      row.func_name = safe_name(func_ea);
      row.depth = depth;
      row.parent_addr = parent;
      results_.push_back(std::move(row));

      if (depth >= max_depth)
        continue;

      std::vector<ea_t> neighbors;
      if (go_down)
        get_function_callees(func_ea, neighbors);
      if (go_up)
        get_function_callers(func_ea, neighbors);

      for (ea_t neighbor : neighbors) {
        if (visited.insert(neighbor).second) {
          queue.push({neighbor, depth + 1, func_ea});
        }
      }
    }
  }

  bool next() override {
    if (pos_ < results_.size()) {
      ++pos_;
      return pos_ <= results_.size();
    }
    return false;
  }

  const CallGraphRow &current() const override { return results_[pos_ - 1]; }
  int64_t rowid() const override { return static_cast<int64_t>(pos_); }
};

std::unique_ptr<xsql::Generator<CallGraphRow>>
make_call_graph_generator(ea_t start, const char *direction, int max_depth) {
  return std::make_unique<CallGraphGenerator>(
      start, direction ? direction : "down", clamp_call_graph_depth(max_depth));
}

GeneratorTableDef<CallGraphRow> define_call_graph() {
  return xsql::generator_table<CallGraphRow>("call_graph")
      .column_int64("func_addr",
                    [](const CallGraphRow &r) -> int64_t {
                      return static_cast<int64_t>(r.func_addr);
                    })
      .column_text(
          "func_name",
          [](const CallGraphRow &r) -> std::string { return r.func_name; })
      .column_int("depth", [](const CallGraphRow &r) -> int { return r.depth; })
      .column_int64("parent_addr",
                    [](const CallGraphRow &r) -> int64_t {
                      return r.parent_addr != BADADDR
                                 ? static_cast<int64_t>(r.parent_addr)
                                 : 0;
                    })
      .hidden_column_int64("start")
      .hidden_column_text("direction")
      .hidden_column_int("max_depth")
      .parametric_filter(
          {"start", "direction", "max_depth"},
          [](const std::vector<xsql::FunctionArg> &args)
              -> std::unique_ptr<xsql::Generator<CallGraphRow>> {
            return make_call_graph_generator(
                static_cast<ea_t>(args[0].as_int64()), args[1].as_c_str(),
                args[2].as_int());
          },
          1.0, 100.0)
      .parametric_filter(
          {"start", "direction"},
          [](const std::vector<xsql::FunctionArg> &args)
              -> std::unique_ptr<xsql::Generator<CallGraphRow>> {
            return make_call_graph_generator(
                static_cast<ea_t>(args[0].as_int64()), args[1].as_c_str(), 10);
          },
          1.0, 100.0)
      .parametric_filter(
          {"start", "max_depth"},
          [](const std::vector<xsql::FunctionArg> &args)
              -> std::unique_ptr<xsql::Generator<CallGraphRow>> {
            return make_call_graph_generator(
                static_cast<ea_t>(args[0].as_int64()), "down",
                args[1].as_int());
          },
          1.0, 100.0)
      .parametric_filter(
          {"start"},
          [](const std::vector<xsql::FunctionArg> &args)
              -> std::unique_ptr<xsql::Generator<CallGraphRow>> {
            return make_call_graph_generator(
                static_cast<ea_t>(args[0].as_int64()), "down", 10);
          },
          1.0, 100.0)
      .build();
}

// ============================================================================
// ShortestPathGenerator - Bidirectional BFS for shortest call path
// ============================================================================

class ShortestPathGenerator : public xsql::Generator<ShortestPathRow> {
  std::vector<ShortestPathRow> results_;
  size_t pos_ = 0;

public:
  ShortestPathGenerator(ea_t from_addr, ea_t to_addr, int max_depth) {
    func_t *from_fn = get_func(from_addr);
    func_t *to_fn = get_func(to_addr);
    if (!from_fn || !to_fn)
      return;
    ea_t from_ea = from_fn->start_ea;
    ea_t to_ea = to_fn->start_ea;

    // Same function
    if (from_ea == to_ea) {
      ShortestPathRow row;
      row.step = 0;
      row.func_addr = from_ea;
      row.func_name = safe_name(from_ea);
      results_.push_back(std::move(row));
      return;
    }

    // Bidirectional BFS
    // Forward: from_ea -> callees
    // Backward: to_ea -> callers
    std::unordered_map<ea_t, ea_t> forward_parent;  // node -> parent
    std::unordered_map<ea_t, ea_t> backward_parent; // node -> parent
    std::queue<ea_t> forward_queue, backward_queue;

    forward_parent[from_ea] = BADADDR;
    backward_parent[to_ea] = BADADDR;
    forward_queue.push(from_ea);
    backward_queue.push(to_ea);

    ea_t meeting_point = BADADDR;

    for (int d = 0; d < max_depth && meeting_point == BADADDR; d++) {
      // Cooperative cancellation -- honor the query deadline on huge graphs.
      if (xsql::vtab_interrupted()) {
        xsql::set_vtab_error(
            "query interrupted: timeout while building shortest_path");
        results_.clear();
        return;
      }
      // Expand forward frontier
      if (!forward_queue.empty()) {
        size_t fsize = forward_queue.size();
        for (size_t i = 0; i < fsize && meeting_point == BADADDR; i++) {
          ea_t node = forward_queue.front();
          forward_queue.pop();

          std::vector<ea_t> callees;
          get_function_callees(node, callees);
          for (ea_t callee : callees) {
            if (forward_parent.count(callee))
              continue;
            forward_parent[callee] = node;
            if (backward_parent.count(callee)) {
              meeting_point = callee;
              break;
            }
            forward_queue.push(callee);
          }
        }
      }

      if (meeting_point != BADADDR)
        break;

      // Expand backward frontier
      if (!backward_queue.empty()) {
        size_t bsize = backward_queue.size();
        for (size_t i = 0; i < bsize && meeting_point == BADADDR; i++) {
          ea_t node = backward_queue.front();
          backward_queue.pop();

          std::vector<ea_t> callers;
          get_function_callers(node, callers);
          for (ea_t caller : callers) {
            if (backward_parent.count(caller))
              continue;
            backward_parent[caller] = node;
            if (forward_parent.count(caller)) {
              meeting_point = caller;
              break;
            }
            backward_queue.push(caller);
          }
        }
      }
    }

    if (meeting_point == BADADDR)
      return; // No path found

    // Reconstruct path: from_ea -> ... -> meeting_point -> ... -> to_ea
    // Forward half: trace back from meeting_point to from_ea
    std::vector<ea_t> forward_half;
    for (ea_t node = meeting_point; node != BADADDR;
         node = forward_parent[node]) {
      forward_half.push_back(node);
    }
    std::reverse(forward_half.begin(), forward_half.end());

    // Backward half: trace from meeting_point's backward child to to_ea
    std::vector<ea_t> backward_half;
    for (ea_t node = backward_parent[meeting_point]; node != BADADDR;
         node = backward_parent[node]) {
      backward_half.push_back(node);
    }

    // Build result
    int step = 0;
    for (ea_t ea : forward_half) {
      ShortestPathRow row;
      row.step = step++;
      row.func_addr = ea;
      row.func_name = safe_name(ea);
      results_.push_back(std::move(row));
    }
    for (ea_t ea : backward_half) {
      ShortestPathRow row;
      row.step = step++;
      row.func_addr = ea;
      row.func_name = safe_name(ea);
      results_.push_back(std::move(row));
    }
  }

  bool next() override {
    if (pos_ < results_.size()) {
      ++pos_;
      return pos_ <= results_.size();
    }
    return false;
  }

  const ShortestPathRow &current() const override { return results_[pos_ - 1]; }
  int64_t rowid() const override { return static_cast<int64_t>(pos_); }
};

std::unique_ptr<xsql::Generator<ShortestPathRow>>
make_shortest_path_generator(ea_t from_addr, ea_t to_addr, int max_depth) {
  return std::make_unique<ShortestPathGenerator>(
      from_addr, to_addr, clamp_shortest_path_depth(max_depth));
}

GeneratorTableDef<ShortestPathRow> define_shortest_path() {
  return xsql::generator_table<ShortestPathRow>("shortest_path")
      .column_int("step",
                  [](const ShortestPathRow &r) -> int { return r.step; })
      .column_int64("func_addr",
                    [](const ShortestPathRow &r) -> int64_t {
                      return static_cast<int64_t>(r.func_addr);
                    })
      .column_text(
          "func_name",
          [](const ShortestPathRow &r) -> std::string { return r.func_name; })
      .hidden_column_int64("from_addr")
      .hidden_column_int64("to_addr")
      .hidden_column_int("max_depth")
      .parametric_filter(
          {"from_addr", "to_addr", "max_depth"},
          [](const std::vector<xsql::FunctionArg> &args)
              -> std::unique_ptr<xsql::Generator<ShortestPathRow>> {
            return make_shortest_path_generator(
                static_cast<ea_t>(args[0].as_int64()),
                static_cast<ea_t>(args[1].as_int64()), args[2].as_int());
          },
          1.0, 10.0)
      .parametric_filter(
          {"from_addr", "to_addr"},
          [](const std::vector<xsql::FunctionArg> &args)
              -> std::unique_ptr<xsql::Generator<ShortestPathRow>> {
            return make_shortest_path_generator(
                static_cast<ea_t>(args[0].as_int64()),
                static_cast<ea_t>(args[1].as_int64()), 20);
          },
          1.0, 10.0)
      .build();
}

// ============================================================================
// CfgEdgesGenerator - Control flow graph edges per function
// ============================================================================

} // namespace code
} // namespace idasql
