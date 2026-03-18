// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

#include "disassembly.hpp"

namespace idasql {
namespace disassembly {

std::string safe_name(ea_t ea) {
  qstring name;
  get_name(&name, ea);
  return std::string(name.c_str());
}

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

class DisasmCallsInFuncIterator : public xsql::RowIterator {
  ea_t func_addr_;
  func_t *pfn_ = nullptr;
  func_item_iterator_t fii_;
  bool started_ = false;
  bool valid_ = false;
  ea_t current_ea_ = BADADDR;
  ea_t callee_addr_ = BADADDR;
  std::string callee_name_;

  bool find_next_call() {
    while (fii_.next_code()) {
      ea_t ea = fii_.current();
      insn_t insn;
      if (decode_insn(&insn, ea) > 0 && is_call_insn(insn)) {
        current_ea_ = ea;
        callee_addr_ = get_first_fcref_from(ea);
        if (callee_addr_ != BADADDR) {
          callee_name_ = safe_name(callee_addr_);
        } else {
          callee_name_.clear();
        }
        return true;
      }
    }
    return false;
  }

public:
  explicit DisasmCallsInFuncIterator(ea_t func_addr) : func_addr_(func_addr) {
    pfn_ = get_func(func_addr_);
  }

  bool next() override {
    if (!pfn_)
      return false;

    if (!started_) {
      started_ = true;
      if (!fii_.set(pfn_)) {
        valid_ = false;
        return false;
      }
      ea_t ea = fii_.current();
      insn_t insn;
      if (decode_insn(&insn, ea) > 0 && is_call_insn(insn)) {
        current_ea_ = ea;
        callee_addr_ = get_first_fcref_from(ea);
        if (callee_addr_ != BADADDR) {
          callee_name_ = safe_name(callee_addr_);
        } else {
          callee_name_.clear();
        }
        valid_ = true;
        return true;
      }
      valid_ = find_next_call();
      return valid_;
    }

    valid_ = find_next_call();
    return valid_;
  }

  bool eof() const override { return started_ && !valid_; }

  void column(xsql::FunctionContext &ctx, int col) override {
    switch (col) {
    case 0:
      ctx.result_int64(static_cast<int64_t>(func_addr_));
      break;
    case 1:
      ctx.result_int64(static_cast<int64_t>(current_ea_));
      break;
    case 2:
      if (callee_addr_ != BADADDR) {
        ctx.result_int64(static_cast<int64_t>(callee_addr_));
      } else {
        ctx.result_int64(0);
      }
      break;
    case 3:
      ctx.result_text(callee_name_.c_str());
      break;
    }
  }

  int64_t rowid() const override { return static_cast<int64_t>(current_ea_); }
};

// ============================================================================
// DisasmCallsGenerator
// ============================================================================

class DisasmCallsGenerator : public xsql::Generator<DisasmCallInfo> {
  size_t func_idx_ = 0;
  func_t *pfn_ = nullptr;
  func_item_iterator_t fii_;
  bool in_func_started_ = false;
  DisasmCallInfo current_;

  bool start_next_func() {
    size_t func_qty = get_func_qty();
    while (func_idx_ < func_qty) {
      pfn_ = getn_func(func_idx_++);
      if (!pfn_)
        continue;

      if (fii_.set(pfn_)) {
        in_func_started_ = false;
        return true;
      }
    }
    pfn_ = nullptr;
    return false;
  }

  bool find_next_call_in_current_func() {
    if (!pfn_)
      return false;

    while (true) {
      ea_t ea = BADADDR;
      if (!in_func_started_) {
        in_func_started_ = true;
        ea = fii_.current();
      } else {
        if (!fii_.next_code())
          return false;
        ea = fii_.current();
      }

      insn_t insn;
      if (decode_insn(&insn, ea) > 0 && is_call_insn(insn)) {
        current_.func_addr = pfn_->start_ea;
        current_.ea = ea;
        current_.callee_addr = get_first_fcref_from(ea);
        if (current_.callee_addr != BADADDR) {
          current_.callee_name = safe_name(current_.callee_addr);
        } else {
          current_.callee_name.clear();
        }
        return true;
      }
    }
  }

public:
  bool next() override {
    while (true) {
      if (!pfn_) {
        if (!start_next_func())
          return false;
      }

      if (find_next_call_in_current_func())
        return true;
      pfn_ = nullptr;
    }
  }

  const DisasmCallInfo &current() const override { return current_; }
  int64_t rowid() const override { return static_cast<int64_t>(current_.ea); }
};

// ============================================================================
// LoopsInFuncIterator
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

GeneratorTableDef<DisasmCallInfo> define_disasm_calls() {
  return generator_table<DisasmCallInfo>("disasm_calls")
      .estimate_rows([]() -> size_t { return get_func_qty() * 5; })
      .generator([]() -> std::unique_ptr<xsql::Generator<DisasmCallInfo>> {
        return std::make_unique<DisasmCallsGenerator>();
      })
      .column_int64(
          "func_addr",
          [](const DisasmCallInfo &r) -> int64_t { return r.func_addr; })
      .column_int64("ea",
                    [](const DisasmCallInfo &r) -> int64_t { return r.ea; })
      .column_int64("callee_addr",
                    [](const DisasmCallInfo &r) -> int64_t {
                      return r.callee_addr != BADADDR
                                 ? static_cast<int64_t>(r.callee_addr)
                                 : 0;
                    })
      .column_text(
          "callee_name",
          [](const DisasmCallInfo &r) -> std::string { return r.callee_name; })
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<DisasmCallsInFuncIterator>(
                static_cast<ea_t>(func_addr));
          },
          10.0)
      .build();
}

GeneratorTableDef<LoopInfo> define_disasm_loops() {
  return generator_table<LoopInfo>("disasm_loops")
      .estimate_rows([]() -> size_t { return get_func_qty() * 2; })
      .generator([]() -> std::unique_ptr<xsql::Generator<LoopInfo>> {
        return std::make_unique<DisasmLoopsGenerator>();
      })
      .column_int64("func_addr",
                    [](const LoopInfo &r) -> int64_t { return r.func_addr; })
      .column_int("loop_id", [](const LoopInfo &r) -> int { return r.loop_id; })
      .column_int64("header_ea",
                    [](const LoopInfo &r) -> int64_t { return r.header_ea; })
      .column_int64(
          "header_end_ea",
          [](const LoopInfo &r) -> int64_t { return r.header_end_ea; })
      .column_int64(
          "back_edge_block_ea",
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
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
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
  for (bool ok = xb.first_to(func_addr, XREF_ALL); ok; ok = xb.next_to()) {
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

    while (!queue.empty()) {
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
      .column_int64("func_ea",
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
          "func_ea",
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
        SELECT f.address, f.name
        FROM funcs f
        LEFT JOIN disasm_calls c ON c.func_addr = f.address
        GROUP BY f.address
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
            c.ea,
            c.callee_addr,
            c.callee_name,
            l.loop_id,
            l.header_ea as loop_header,
            l.back_edge_block_ea,
            l.back_edge_block_end
        FROM disasm_calls c
        JOIN disasm_loops l ON l.func_addr = c.func_addr
        WHERE c.ea >= l.header_ea AND c.ea < l.back_edge_block_end
    )";
  db.exec(v_calls_in_loops);

  const char *v_funcs_with_loops = R"(
        CREATE VIEW IF NOT EXISTS disasm_v_funcs_with_loops AS
        SELECT
            f.address,
            f.name,
            COUNT(DISTINCT l.loop_id) as loop_count
        FROM funcs f
        JOIN disasm_loops l ON l.func_addr = f.address
        GROUP BY f.address
    )";
  db.exec(v_funcs_with_loops);

  return true;
}

// ============================================================================
// Registry
// ============================================================================

DisassemblyRegistry::DisassemblyRegistry()
    : disasm_calls(define_disasm_calls()), disasm_loops(define_disasm_loops()),
      call_graph(define_call_graph()), shortest_path(define_shortest_path()),
      cfg_edges(define_cfg_edges()) {}

void DisassemblyRegistry::register_all(xsql::Database &db) {
  db.register_generator_table("ida_disasm_calls", &disasm_calls);
  db.create_table("disasm_calls", "ida_disasm_calls");

  db.register_generator_table("ida_disasm_loops", &disasm_loops);
  db.create_table("disasm_loops", "ida_disasm_loops");

  db.register_generator_table("ida_call_graph", &call_graph);
  db.create_table("call_graph", "ida_call_graph");

  db.register_generator_table("ida_shortest_path", &shortest_path);
  db.create_table("shortest_path", "ida_shortest_path");

  db.register_generator_table("ida_cfg_edges", &cfg_edges);
  db.create_table("cfg_edges", "ida_cfg_edges");

  register_disasm_views(db);
}

} // namespace disassembly
} // namespace idasql
