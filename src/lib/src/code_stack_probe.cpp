// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_stack_probe.hpp"

#include <algorithm>
#include <array>

using namespace idasql::core;

namespace idasql {
namespace code {

std::string stack_pointer_reg_name(ea_t ea) {
  idasql_segment_info_t seg;
  if (!idasql_segment_info(ea, &seg))
    return {};
  // segment bitness 0/1/2 = 16/32/64-bit code: name the register at that width
  // (AArch64 at width 4 would say WSP, x86 at width 8 in a 32-bit database nothing).
  static constexpr size_t kWidth[] = {2, 4, 8};
  if (seg.bitness > 2)
    return {};
  const int reg = str2reg("sp");
  if (reg < 0)
    return {};
  qstring name;
  if (get_reg_name(&name, reg, kWidth[seg.bitness]) <= 0)
    return {};
  return name.c_str();
}

bool is_stack_probe_name(ea_t ea, const std::string &raw) {
  // Stack-probe helpers of the MSVC, MinGW, Apple, LLVM/GNU and Rust runtimes, as
  // cleanup_name() leaves them (alloca_probe_8 / alloca_probe_16 fold into alloca_probe).
  static constexpr std::array<const char *, 6> kProbes = {
      "alloca_probe", "chkstk", "chkstk_ms", "chkstk_darwin", "probestack", "rust_probestack"};
  if (raw.empty())
    return false;
  std::string name = raw;
  // cleanup_name keeps an import prefix: "__imp___chkstk" would stay "imp___chkstk".
  for (const char *prefix : {"__imp_", "_imp_", "imp_"}) {
    const size_t n = std::char_traits<char>::length(prefix);
    if (name.compare(0, n, prefix) == 0) {
      name.erase(0, n);
      break;
    }
  }
  qstring clean;
  if (!cleanup_name(&clean, ea, name.c_str()))
    return false;
  const std::string c = clean.c_str();
  return std::find_if(kProbes.begin(), kProbes.end(),
                      [&](const char *p) { return c == p; }) != kProbes.end();
}

namespace {

bool probe_at(ea_t ea) {
  if (ea == BADADDR)
    return false;
  if (processor_t::is_alloca_probe(ea) == 1)  // the processor module's own test
    return true;
  return is_stack_probe_name(ea, safe_name(ea));
}

// The helper itself, or a one-instruction thunk in front of it: `jmp helper`, or
// `jmp [__imp_helper]` (an import thunk, which has only a data reference).
bool target_is_stack_probe(ea_t target) {
  if (probe_at(target))
    return true;
  insn_t insn;
  if (decode_insn(&insn, target) <= 0 || is_call_insn(insn))
    return false;
  const ea_t next = get_first_fcref_from(target);
  if (next != BADADDR)
    return next != target + insn.size && probe_at(next);
  const bool thunk = (idasql_func_flags(target) & FUNC_THUNK) != 0;
  return thunk && probe_at(get_first_dref_from(target));
}

} // namespace

bool function_calls_stack_probe(ea_t func_ea) {
  idasql_func_item_iterator fii;
  if (!fii.set(func_ea))
    return false;
  for (bool ok = true; ok; ok = fii.next_code()) {
    const ea_t ea = fii.current();
    insn_t insn;
    if (decode_insn(&insn, ea) <= 0 || !is_call_insn(insn))
      continue;
    const ea_t callee = get_first_fcref_from(ea);
    if (callee != BADADDR) {
      if (target_is_stack_probe(callee))
        return true;
    } else if (probe_at(get_first_dref_from(ea))) {
      return true;  // call through an import slot: call [__imp___chkstk]
    }
  }
  return false;
}

} // namespace code
} // namespace idasql
