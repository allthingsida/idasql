// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_calls.hpp"

#include <idasql/string_utils.hpp>

#include "address_resolution.hpp"
#include "decompiler.hpp"
#include "function_rowid.hpp"

using namespace idasql::core;

namespace idasql {
namespace code {

// callee_type of the call at ea, as every access path reports it.
static void result_callee_type(xsql::FunctionContext &ctx, ea_t ea) {
  tinfo_t tif;
  if (!decompiler::get_callee_tinfo_at(ea, tif)) {
    ctx.result_null();
    return;
  }
  qstring out;
  if (tif.print(&out, nullptr, PRTYPE_1LINE | PRTYPE_SEMI)) {
    ctx.result_text(out.c_str());
  } else {
    ctx.result_null();
  }
}

// The call instructions of a function, collected with a scoped function item
// iterator: a live one locks the function, and a cursor stays open until its
// statement ends (a DELETE whose subquery reads disasm_calls would keep IDA from
// undefining the function's code).
static std::vector<ea_t> call_addrs_in(ea_t func_addr) {
  std::vector<ea_t> out;
  idasql_func_item_iterator fii;
  for (bool ok = fii.set(func_addr); ok; ok = fii.next_code()) {
    const ea_t ea = fii.current();
    insn_t insn;
    if (decode_insn(&insn, ea) > 0 && is_call_insn(insn))
      out.push_back(ea);
  }
  return out;
}

class DisasmCallsInFuncIterator : public xsql::RowIterator {
  ea_t func_addr_;
  std::vector<ea_t> calls_;
  size_t idx_ = 0;
  bool started_ = false;
  bool valid_ = false;
  ea_t current_ea_ = BADADDR;
  ea_t callee_addr_ = BADADDR;
  std::string callee_name_;

  bool load(size_t i) {
    if (i >= calls_.size())
      return false;
    current_ea_ = calls_[i];
    callee_addr_ = get_first_fcref_from(current_ea_);
    if (callee_addr_ != BADADDR)
      callee_name_ = safe_name(callee_addr_);
    else
      callee_name_.clear();
    return true;
  }

public:
  explicit DisasmCallsInFuncIterator(ea_t func_addr) : func_addr_(func_addr) {
    // func_addr is the owner's ENTRY address; an interior or tail address is a
    // different key and matches nothing, as in the full scan.
    if (idasql_is_func_start(func_addr_))
      calls_ = call_addrs_in(func_addr_);
  }

  bool next() override {
    if (!started_) {
      started_ = true;
      idx_ = 0;
    } else if (valid_) {
      ++idx_;
    }
    valid_ = load(idx_);
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
    case 4:
      result_callee_type(ctx, current_ea_);
      break;
    default:
      ctx.result_null();
      break;
    }
  }

  // (function, address): a call in a tail shared by A and C is a row under
  // each, and SQLite de-duplicates a MULTI-INDEX OR plan by rowid.
  int64_t rowid() const override {
    return idasql::detail::pack_owned_address_rowid(func_addr_, current_ea_);
  }
};

// ============================================================================
// DisasmCallsGenerator
// ============================================================================

class DisasmCallsGenerator : public xsql::Generator<DisasmCallInfo> {
  size_t func_idx_ = 0;
  ea_t func_ea_ = BADADDR;
  std::vector<ea_t> calls_;  // the current function's calls (see call_addrs_in)
  size_t call_idx_ = 0;
  DisasmCallInfo current_;

public:
  bool next() override {
    for (;;) {
      if (func_ea_ != BADADDR && call_idx_ < calls_.size()) {
        const ea_t ea = calls_[call_idx_++];
        current_ = DisasmCallInfo{};
        current_.func_addr = func_ea_;
        current_.owner = func_ea_;
        current_.ea = ea;
        current_.callee_addr = get_first_fcref_from(ea);
        if (current_.callee_addr != BADADDR)
          current_.callee_name = safe_name(current_.callee_addr);
        return true;
      }
      if (func_idx_ >= get_func_qty())
        return false;
      func_ea_ = idasql_func_ea_by_num(func_idx_++);
      calls_ = func_ea_ != BADADDR ? call_addrs_in(func_ea_) : std::vector<ea_t>{};
      call_idx_ = 0;
    }
  }

  const DisasmCallInfo &current() const override { return current_; }
  int64_t rowid() const override {
    return idasql::detail::pack_owned_address_rowid(current_.owner, current_.ea);
  }
};

// The call at one address: one row per owning function (several for a shared
// tail). disasm_calls lists the calls functions make, as its full scan walks
// functions: a call outside every function has no row on any path.
static bool make_call_row(ea_t ea, ea_t owner, DisasmCallInfo &row) {
  insn_t insn;
  if (ea == BADADDR || owner == BADADDR || decode_insn(&insn, ea) <= 0 || !is_call_insn(insn))
    return false;
  row = DisasmCallInfo{};
  row.ea = ea;
  row.owner = owner;
  row.func_addr = owner;
  row.callee_addr = get_first_fcref_from(ea);
  if (row.callee_addr != BADADDR)
    row.callee_name = safe_name(row.callee_addr);
  return true;
}

class DisasmCallAtEaGenerator : public xsql::Generator<DisasmCallInfo> {
  std::vector<DisasmCallInfo> rows_;
  size_t idx_ = static_cast<size_t>(-1);

public:
  explicit DisasmCallAtEaGenerator(ea_t ea) {
    std::vector<ea_t> owners;
    idasql_for_each_owner_of(ea, [&](ea_t owner) { owners.push_back(owner); });
    for (ea_t owner : owners) {
      DisasmCallInfo row;
      if (make_call_row(ea, owner, row))
        rows_.push_back(std::move(row));
    }
  }

  bool next() override {
    ++idx_;
    return idx_ < rows_.size();
  }

  const DisasmCallInfo &current() const override { return rows_[idx_]; }
  int64_t rowid() const override {
    return idasql::detail::pack_owned_address_rowid(rows_[idx_].owner,
                                                    rows_[idx_].ea);
  }
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
            result_callee_type(ctx, r.ea);
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
              xsql::set_vtab_error(
                  "disasm_calls: callee_type is not a function prototype IDA can parse: " + decl);
              return false;
            }
            if (!decompiler::apply_callee_tinfo_at(row.ea, tif, callee_name.c_str())) {
              // apply_callee_tinfo reports no reason. Measured: it refuses a prototype
              // the call's arguments do not fit, e.g. a 32-bit __fastcall one whose
              // arguments all go in registers at a call that pushes one.
              qstring printed;
              tif.print(&printed);
              xsql::set_vtab_error("disasm_calls: IDA refused callee_type '" +
                                   std::string(printed.c_str()) + "' at " + format_ea_hex(row.ea) +
                                   ": the prototype must fit the arguments this call passes "
                                   "(calling convention and stack arguments)");
              return false;
            }
            return true;
          })
      .row_lookup([](DisasmCallInfo &row, int64_t raw_rowid) -> bool {
        // The rowid is (owner, address): see the generators above.
        ea_t owner = BADADDR;
        ea_t ea = BADADDR;
        uint32_t sub = 0;
        if (!idasql::detail::unpack_owned_address_rowid(raw_rowid, 0, owner, ea,
                                                        sub))
          return false;
        return make_call_row(ea, owner, row);
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
            std::optional<ea_t> ea;
            std::string error;
            if (args.empty() ||
                !resolve_address_key(args.front().value, "addr", ea, &error)) {
              xsql::set_vtab_error(error.empty() ? "disasm_calls: missing ea constraint" : error);
              return nullptr;
            }
            // omit=1: a value no address equals (NULL, 4096.5) has no rows.
            if (!ea)
              return nullptr;
            return std::make_unique<DisasmCallAtEaGenerator>(*ea);
          },
          1.0, 1.0)
      .build();
}

} // namespace code
} // namespace idasql
