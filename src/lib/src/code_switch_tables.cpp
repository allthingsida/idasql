// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// `switch_tables` — reconstructed switch/case jump tables via the IDA analyzer's
// get_switch_info(). Canonical cross-tool surface, matching ghidrasql:
// func_addr, instr_addr, table_addr, min_case, max_case, case_count, default_addr.

#include "code_switch_tables.hpp"
#include "function_rowid.hpp"

#include <nalt.hpp>
#include <xref.hpp>   // calc_switch_cases, casevec_t

using namespace idasql::core;

namespace idasql {
namespace code {

namespace {

// `func_ea` when it is a function's entry address, else BADADDR: func_addr is
// the owner's ENTRY address, and an interior or tail address matches nothing.
ea_t func_start_at(ea_t func_ea) {
  return idasql_is_func_start(func_ea) ? func_ea : BADADDR;
}

bool switch_scan_interrupted() {
  if (!xsql::vtab_interrupted())
    return false;
  xsql::set_vtab_error("query interrupted while scanning switch tables");
  return true;
}

template <typename Visit>
bool for_each_func_code(ea_t func_ea, Visit visit) {
  if (func_ea == BADADDR)
    return true;
  idasql_func_item_iterator fii;
  if (!fii.set(func_ea))
    return true;

  size_t scanned = 0;
  auto visit_current = [&]() {
    if (((scanned++) & 1023u) == 0 && switch_scan_interrupted())
      return false;
    visit(fii.current());
    return true;
  };

  if (!visit_current())
    return false;
  while (fii.next_code()) {
    if (!visit_current())
      return false;
  }
  return !switch_scan_interrupted();
}

// Derive bounds from the actual case labels. switch_info_t::lowcase aliases the
// sparse switch's value-table address, so it is not a valid sparse bound.
void collect_switch_bounds(ea_t ea, const switch_info_t &si,
                           SwitchTableInfo &row) {
  casevec_t cases;
  eavec_t targets;
  if (!::calc_switch_cases(&cases, &targets, ea, si))
    return;

  row.case_count = 0;
  for (const auto &group : cases) {
    for (const sval_t value : group) {
      const int64_t v = static_cast<int64_t>(value);
      ++row.case_count;
      if (!row.has_cases) {
        row.min_case = v;
        row.max_case = v;
        row.has_cases = true;
      } else {
        row.min_case = qmin(row.min_case, v);
        row.max_case = qmax(row.max_case, v);
      }
    }
  }
}

// Walk one function's instructions and reconstruct every switch it contains.
// get_switch_info(&si, ea) returns > 0 when `ea` participates in a switch idiom;
// dedup by the idiom start (si.startea) so a switch is emitted exactly once.
bool collect_switches_in_func(ea_t func_ea, std::vector<SwitchTableInfo> &out) {
  if (func_ea == BADADDR)
    return true;
  qvector<ea_t> seen;
  const bool completed = for_each_func_code(func_ea, [&](ea_t ea) {
    switch_info_t si;
    if (get_switch_info(&si, ea) <= 0)
      return;
    ea_t key = (si.startea != BADADDR) ? si.startea : ea;
    if (seen.has(key))
      return;
    seen.push_back(key);

    SwitchTableInfo r;
    r.func_ea = func_ea;
    r.instr_addr = ea;
    r.table_addr = si.jumps;
    r.case_count = static_cast<int64_t>(si.ncases);
    collect_switch_bounds(ea, si, r);
    r.default_addr = si.defjump;
    r.has_default = (si.defjump != BADADDR);
    out.push_back(std::move(r));
  });
  if (!completed)
    out.clear();
  return completed;
}

// Enumerate the per-case (value -> target) rows of every switch in the function
// whose entry is `func_ea`. The processor's calc_switch_cases() fills `cv`
// (casevec_t: cv[i] is the value(s) mapped to targets[i] — IDA groups multiple
// case labels per target) and `targets` (eavec_t). Emit one row per (value,
// target), plus a default row (case_value NULL, is_default=1) when the switch
// has a default. dedup by idiom start, like collect_switches_in_func.
bool collect_switch_cases_in_func(ea_t func_ea, std::vector<SwitchCaseInfo> &out) {
  if (func_ea == BADADDR)
    return true;
  qvector<ea_t> seen;
  const bool completed = for_each_func_code(func_ea, [&](ea_t ea) {
    switch_info_t si;
    if (get_switch_info(&si, ea) <= 0)
      return;
    ea_t key = (si.startea != BADADDR) ? si.startea : ea;
    if (seen.has(key))
      return;
    seen.push_back(key);

    int64_t idx = 0;
    // The GLOBAL kernel calc_switch_cases (xref.hpp) computes cases for standard
    // switches (the processor_t::calc_switch_cases NOTIFICATION is only for custom jump
    // tables and returns nothing here). Returns false when cases can't be computed; the
    // switch still appears in switch_tables, just with no detail rows here.
    casevec_t cv;
    eavec_t targets;
    if (::calc_switch_cases(&cv, &targets, ea, si)) {
      const size_t n = qmin(cv.size(), targets.size());
      for (size_t i = 0; i < n; ++i) {
        for (const sval_t v : cv[i]) {
          SwitchCaseInfo r;
          r.func_ea = func_ea;
          r.switch_instr_addr = ea;
          r.case_index = idx++;
          r.case_value = static_cast<int64_t>(v);
          r.target_addr = targets[i];
          r.is_default = false;
          out.push_back(std::move(r));
        }
      }
    }
    if (si.defjump != BADADDR) {
      SwitchCaseInfo r;
      r.func_ea = func_ea;
      r.switch_instr_addr = ea;
      r.case_index = idx++;
      r.target_addr = si.defjump;
      r.is_default = true;   // case_value surfaced as NULL
      out.push_back(std::move(r));
    }
  });
  if (!completed)
    out.clear();
  return completed;
}

}  // namespace

// WHERE func_addr = X pushdown: reconstruct only that function's switches.
class SwitchTablesInFuncIterator : public xsql::RowIterator {
  std::vector<SwitchTableInfo> rows_;
  size_t idx_ = 0;
  bool started_ = false;

public:
  explicit SwitchTablesInFuncIterator(ea_t func_ea) {
    collect_switches_in_func(func_start_at(func_ea), rows_);
  }

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
    if (idx_ >= rows_.size()) { ctx.result_null(); return; }
    const auto &r = rows_[idx_];
    switch (col) {
    case 0: ctx.result_int64(static_cast<int64_t>(r.func_ea)); break;
    case 1: ctx.result_int64(static_cast<int64_t>(r.instr_addr)); break;
    case 2:
      if (r.table_addr != BADADDR)
        ctx.result_int64(static_cast<int64_t>(r.table_addr));
      else
        ctx.result_null();
      break;
    case 3:
      if (r.has_cases)
        ctx.result_int64(r.min_case);
      else
        ctx.result_null();
      break;
    case 4:
      if (r.has_cases)
        ctx.result_int64(r.max_case);
      else
        ctx.result_null();
      break;
    case 5: ctx.result_int64(r.case_count); break;
    case 6:
      if (r.has_default)
        ctx.result_int64(static_cast<int64_t>(r.default_addr));
      else
        ctx.result_null();
      break;
    default: ctx.result_null(); break;
    }
  }

  int64_t rowid() const override {
    return idx_ < rows_.size()
               ? idasql::detail::pack_function_rowid(rows_[idx_].func_ea, idx_)
               : -1;
  }
};

// Full-scan generator: every function, every switch.
class SwitchTablesGenerator : public xsql::Generator<SwitchTableInfo> {
  size_t func_idx_ = 0;
  std::vector<SwitchTableInfo> current_;
  size_t row_idx_ = 0;

  bool load_next_func() {
    size_t qty = get_func_qty();
    while (func_idx_ < qty) {
      const ea_t func_ea = idasql_func_ea_by_num(func_idx_++);
      if (func_ea == BADADDR)
        continue;
      current_.clear();
      if (!collect_switches_in_func(func_ea, current_))
        return false;
      if (!current_.empty()) {
        row_idx_ = 0;
        return true;
      }
    }
    return false;
  }

public:
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

  const SwitchTableInfo &current() const override { return current_[row_idx_]; }

  int64_t rowid() const override {
    return idasql::detail::pack_function_rowid(current_[row_idx_].func_ea,
                                               row_idx_);
  }
};

GeneratorTableDef<SwitchTableInfo> define_switch_tables() {
  return xsql::generator_table<SwitchTableInfo>("switch_tables")
      .generator([]() -> std::unique_ptr<xsql::Generator<SwitchTableInfo>> {
        return std::make_unique<SwitchTablesGenerator>();
      })
      .column_int64("func_addr",
                    [](const SwitchTableInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.func_ea);
                    })
      .column_int64("instr_addr",
                    [](const SwitchTableInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.instr_addr);
                    })
      .column("table_addr", xsql::ColumnType::Integer,
              [](xsql::FunctionContext &ctx, const SwitchTableInfo &r) {
                if (r.table_addr != BADADDR)
                  ctx.result_int64(static_cast<int64_t>(r.table_addr));
                else
                  ctx.result_null();
              })
      .column("min_case", xsql::ColumnType::Integer,
              [](xsql::FunctionContext &ctx, const SwitchTableInfo &r) {
                if (r.has_cases)
                  ctx.result_int64(r.min_case);
                else
                  ctx.result_null();
              })
      .column("max_case", xsql::ColumnType::Integer,
              [](xsql::FunctionContext &ctx, const SwitchTableInfo &r) {
                if (r.has_cases)
                  ctx.result_int64(r.max_case);
                else
                  ctx.result_null();
              })
      .column_int64("case_count",
                    [](const SwitchTableInfo &r) -> int64_t { return r.case_count; })
      .column("default_addr", xsql::ColumnType::Integer,
              [](xsql::FunctionContext &ctx, const SwitchTableInfo &r) {
                if (r.has_default)
                  ctx.result_int64(static_cast<int64_t>(r.default_addr));
                else
                  ctx.result_null();
              })
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<SwitchTablesInFuncIterator>(
                static_cast<ea_t>(func_addr));
          },
          1.0, 4.0)
      .build();
}

// WHERE func_addr = X pushdown: enumerate only that function's switch cases.
class SwitchCasesInFuncIterator : public xsql::RowIterator {
  std::vector<SwitchCaseInfo> rows_;
  size_t idx_ = 0;
  bool started_ = false;

public:
  explicit SwitchCasesInFuncIterator(ea_t func_ea) {
    collect_switch_cases_in_func(func_start_at(func_ea), rows_);
  }

  bool next() override {
    if (!started_) { started_ = true; idx_ = 0; return !rows_.empty(); }
    if (idx_ + 1 < rows_.size()) { ++idx_; return true; }
    idx_ = rows_.size();
    return false;
  }

  bool eof() const override { return started_ && idx_ >= rows_.size(); }

  void column(xsql::FunctionContext &ctx, int col) override {
    if (idx_ >= rows_.size()) { ctx.result_null(); return; }
    const auto &r = rows_[idx_];
    switch (col) {
    case 0: ctx.result_int64(static_cast<int64_t>(r.func_ea)); break;
    case 1: ctx.result_int64(static_cast<int64_t>(r.switch_instr_addr)); break;
    case 2: ctx.result_int64(r.case_index); break;
    case 3:
      if (r.is_default) ctx.result_null();
      else ctx.result_int64(r.case_value);
      break;
    case 4: ctx.result_int64(static_cast<int64_t>(r.target_addr)); break;
    case 5: ctx.result_int64(r.is_default ? 1 : 0); break;
    default: ctx.result_null(); break;
    }
  }

  int64_t rowid() const override {
    return idx_ < rows_.size()
               ? idasql::detail::pack_function_rowid(rows_[idx_].func_ea, idx_)
               : -1;
  }
};

// Full-scan generator: every function, every switch, every case.
class SwitchCasesGenerator : public xsql::Generator<SwitchCaseInfo> {
  size_t func_idx_ = 0;
  std::vector<SwitchCaseInfo> current_;
  size_t row_idx_ = 0;

  bool load_next_func() {
    size_t qty = get_func_qty();
    while (func_idx_ < qty) {
      const ea_t func_ea = idasql_func_ea_by_num(func_idx_++);
      if (func_ea == BADADDR)
        continue;
      current_.clear();
      if (!collect_switch_cases_in_func(func_ea, current_))
        return false;
      if (!current_.empty()) {
        row_idx_ = 0;
        return true;
      }
    }
    return false;
  }

public:
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

  const SwitchCaseInfo &current() const override { return current_[row_idx_]; }

  int64_t rowid() const override {
    return idasql::detail::pack_function_rowid(current_[row_idx_].func_ea,
                                               row_idx_);
  }
};

GeneratorTableDef<SwitchCaseInfo> define_switch_cases() {
  return xsql::generator_table<SwitchCaseInfo>("switch_cases")
      .generator([]() -> std::unique_ptr<xsql::Generator<SwitchCaseInfo>> {
        return std::make_unique<SwitchCasesGenerator>();
      })
      .column_int64("func_addr",
                    [](const SwitchCaseInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.func_ea);
                    })
      .column_int64("switch_instr_addr",
                    [](const SwitchCaseInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.switch_instr_addr);
                    })
      .column_int64("case_index",
                    [](const SwitchCaseInfo &r) -> int64_t { return r.case_index; })
      // NULL for the default row (is_default=1) — the default has no case value.
      .column("case_value", xsql::ColumnType::Integer,
              [](xsql::FunctionContext &ctx, const SwitchCaseInfo &r) {
                if (r.is_default)
                  ctx.result_null();
                else
                  ctx.result_int64(r.case_value);
              })
      .column_int64("target_addr",
                    [](const SwitchCaseInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.target_addr);
                    })
      .column_int64("is_default",
                    [](const SwitchCaseInfo &r) -> int64_t {
                      return r.is_default ? 1 : 0;
                    })
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<SwitchCasesInFuncIterator>(
                static_cast<ea_t>(func_addr));
          },
          1.0, 8.0)
      .build();
}

} // namespace code
} // namespace idasql
