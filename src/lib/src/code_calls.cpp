// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_calls.hpp"

#include "address_resolution.hpp"
#include "decompiler.hpp"

using namespace idasql::core;

namespace idasql {
namespace code {

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

class DisasmCallAtEaGenerator : public xsql::Generator<DisasmCallInfo> {
  DisasmCallInfo row_{};
  bool valid_ = false;
  bool started_ = false;

public:
  explicit DisasmCallAtEaGenerator(ea_t ea) {
    insn_t insn;
    if (ea != BADADDR && decode_insn(&insn, ea) > 0 && is_call_insn(insn)) {
      row_.ea = ea;
      func_t *f = get_func(ea);
      row_.func_addr = f ? f->start_ea : 0;
      row_.callee_addr = get_first_fcref_from(ea);
      if (row_.callee_addr != BADADDR) {
        row_.callee_name = safe_name(row_.callee_addr);
      }
      valid_ = true;
    }
  }

  bool next() override {
    if (started_ || !valid_)
      return false;
    started_ = true;
    return true;
  }

  const DisasmCallInfo &current() const override { return row_; }
  int64_t rowid() const override { return static_cast<int64_t>(row_.ea); }
};

// ============================================================================
// LoopsInFuncIterator
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
      .column_int64("addr",
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
      .column_rw(
          "callee_type", xsql::ColumnType::Text,
          [](xsql::FunctionContext &ctx, const DisasmCallInfo &r) {
            tinfo_t tif;
            if (!decompiler::get_callee_tinfo_at(r.ea, tif)) {
              ctx.result_null();
              return;
            }
            qstring out;
            if (tif.print(&out, nullptr, PRTYPE_1LINE | PRTYPE_SEMI)) {
              ctx.result_text(out.c_str());
            } else {
              ctx.result_null();
            }
          },
          [](DisasmCallInfo &row, xsql::FunctionArg val) -> bool {
            if (val.is_nochange())
              return true;
            if (!decompiler::hexrays_available()) {
              xsql::set_vtab_error("disasm_calls: cannot write callee_type: Hex-Rays decompiler is unavailable");
              return false;
            }
            const bool is_clear = val.is_null() || val.as_text().empty();
            if (is_clear) {
              if (!decompiler::clear_callee_tinfo_at(row.ea)) {
                xsql::set_vtab_error("disasm_calls: failed to clear callee_type");
                return false;
              }
              return true;
            }
            tinfo_t tif;
            qstring callee_name;
            const std::string decl = val.as_text();
            if (!decompiler::parse_callee_decl(decl.c_str(), tif, &callee_name)) {
              xsql::set_vtab_error("disasm_calls: failed to parse callee_type declaration");
              return false;
            }
            if (!decompiler::apply_callee_tinfo_at(row.ea, tif, callee_name.c_str())) {
              xsql::set_vtab_error("disasm_calls: failed to apply callee_type");
              return false;
            }
            return true;
          })
      .row_lookup([](DisasmCallInfo &row, int64_t raw_rowid) -> bool {
        const ea_t ea = static_cast<ea_t>(static_cast<uint64_t>(raw_rowid));
        DisasmCallAtEaGenerator gen(ea);
        if (!gen.next())
          return false;
        row = gen.current();
        return true;
      })
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<DisasmCallsInFuncIterator>(
                static_cast<ea_t>(func_addr));
          },
          10.0)
      .constraint_filter(
          {xsql::required_eq("addr", "")},
          [](const std::vector<xsql::GeneratorConstraintArg> &args)
              -> std::unique_ptr<xsql::Generator<DisasmCallInfo>> {
            ea_t ea = BADADDR;
            std::string error;
            if (args.empty() ||
                !resolve_address_value(args.front().value, "addr", ea, &error)) {
              xsql::set_vtab_error(error.empty() ? "disasm_calls: missing ea constraint" : error);
              return nullptr;
            }
            return std::make_unique<DisasmCallAtEaGenerator>(ea);
          },
          1.0, 1.0)
      .build();
}

} // namespace code
} // namespace idasql
