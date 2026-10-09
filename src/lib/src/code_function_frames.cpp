// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// `function_frames` — per-function stack-frame layout from IDA's function
// frame fields (decompiler-free). Canonical cross-tool columns, matching
// ghidrasql: func_addr, frame_size, arg_size, local_size, saved_reg_size,
// stack_base_reg, has_frame_pointer; then func_name and uses_chkstk.

#include "code_function_frames.hpp"
#include "code_stack_probe.hpp"

#include <frame.hpp>

using namespace idasql::core;

namespace idasql {
namespace code {

namespace {

/**
 * Bytes of the stack-argument area of the function containing `ea`: the frame
 * type's size past the start of its arguments section (locals + saved registers
 * + return address). Counts every stack argument, unlike func_t::argsize (bytes
 * purged on return: 0 for __cdecl). 0 when there is no function or frame.
 */
asize_t idasql_func_stack_args_size(ea_t ea)
{
    tinfo_t frame;
#if IDASQL_HAS_EA_API
    const ea_t start = get_func_start(ea);
    if (start == BADADDR || !get_func_frame_ea(&frame, start))
        return 0;
    const ea_t args = frame_off_args_ea(start);
#else
    func_t *pfn = get_func(ea);
    if (pfn == nullptr || !get_func_frame(&frame, pfn))
        return 0;
    const ea_t args = frame_off_args(pfn);
#endif
    const size_t size = frame.get_size();
    if (args == BADADDR || size == BADSIZE || size <= static_cast<size_t>(args))
        return 0;
    return static_cast<asize_t>(size - static_cast<size_t>(args));
}

// The function record exposes the component sizes directly; the frame size
// also includes the architecture-specific return-address size in the aggregate
// footprint. False when `func_ea` is in no function.
bool frame_for_func(ea_t func_ea, FrameInfo *out) {
  idasql_func_info_t fi;
  if (!idasql_func_info(func_ea, &fi))
    return false;
  FrameInfo r;
  r.func_ea = fi.start_ea;
  r.local_size = static_cast<int64_t>(fi.frsize);
  r.saved_reg_size = static_cast<int64_t>(fi.frregs);
  r.arg_size = static_cast<int64_t>(idasql_func_stack_args_size(fi.start_ea));
  r.purged_size = static_cast<int64_t>(fi.argsize);
  r.frame_size = static_cast<int64_t>(idasql_func_frame_size(fi.start_ea));
  r.stack_base_reg = stack_pointer_reg_name(fi.start_ea);
  r.has_frame_pointer = (fi.flags & FUNC_FRAME) != 0;
  r.func_name = safe_func_name(fi.start_ea);
  *out = r;
  return true;
}

}  // namespace

bool FrameInfo::uses_chkstk() const {
  if (!uses_chkstk_)
    uses_chkstk_ = function_calls_stack_probe(func_ea);
  return *uses_chkstk_;
}

// WHERE func_addr = X pushdown: O(1) single-function read.
class FrameInFuncIterator : public xsql::RowIterator {
  std::vector<FrameInfo> rows_;
  size_t idx_ = 0;
  bool started_ = false;

public:
  explicit FrameInFuncIterator(ea_t func_ea) {
    FrameInfo r;
    if (idasql_is_func_start(func_ea) && frame_for_func(func_ea, &r))
      rows_.push_back(r);
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
    case 1: ctx.result_int64(r.frame_size); break;
    case 2: ctx.result_int64(r.arg_size); break;
    case 3: ctx.result_int64(r.local_size); break;
    case 4: ctx.result_int64(r.saved_reg_size); break;
    case 5:
      if (r.stack_base_reg.empty()) ctx.result_null();
      else ctx.result_text(r.stack_base_reg);
      break;
    case 6: ctx.result_int64(r.has_frame_pointer ? 1 : 0); break;
    case 7: ctx.result_text(r.func_name); break;
    case 8: ctx.result_int64(r.uses_chkstk() ? 1 : 0); break;
    case 9: ctx.result_int64(r.purged_size); break;
    default: ctx.result_null(); break;
    }
  }

  int64_t rowid() const override {
    return idx_ < rows_.size() ? static_cast<int64_t>(rows_[idx_].func_ea) : 0;
  }
};

// Full-scan: one row per function.
class FramesGenerator : public xsql::Generator<FrameInfo> {
  size_t func_idx_ = 0;
  FrameInfo cur_;

public:
  bool next() override {
    size_t qty = get_func_qty();
    while (func_idx_ < qty) {
      const ea_t func_ea = idasql_func_ea_by_num(func_idx_++);
      if (func_ea == BADADDR || !frame_for_func(func_ea, &cur_))
        continue;
      return true;
    }
    return false;
  }
  const FrameInfo &current() const override { return cur_; }
  int64_t rowid() const override { return static_cast<int64_t>(cur_.func_ea); }
};

GeneratorTableDef<FrameInfo> define_function_frames() {
  return xsql::generator_table<FrameInfo>("function_frames")
      .generator([]() -> std::unique_ptr<xsql::Generator<FrameInfo>> {
        return std::make_unique<FramesGenerator>();
      })
      .column_int64("func_addr",
                    [](const FrameInfo &r) -> int64_t {
                      return static_cast<int64_t>(r.func_ea);
                    })
      .column_int64("frame_size",
                    [](const FrameInfo &r) -> int64_t { return r.frame_size; })
      .column_int64("arg_size",
                    [](const FrameInfo &r) -> int64_t { return r.arg_size; })
      .column_int64("local_size",
                    [](const FrameInfo &r) -> int64_t { return r.local_size; })
      .column_int64("saved_reg_size",
                    [](const FrameInfo &r) -> int64_t { return r.saved_reg_size; })
      // The program's stack-pointer register; NULL when the module has no "sp".
      .column("stack_base_reg", xsql::ColumnType::Text,
              [](xsql::FunctionContext &ctx, const FrameInfo &r) {
                if (r.stack_base_reg.empty())
                  ctx.result_null();
                else
                  ctx.result_text(r.stack_base_reg);
              })
      .column_int64("has_frame_pointer",
                    [](const FrameInfo &r) -> int64_t {
                      return r.has_frame_pointer ? 1 : 0;
                    })
      // Column order above is shared with FrameInFuncIterator::column().
      .column_text("func_name",
                   [](const FrameInfo &r) -> std::string { return r.func_name; })
      .column_int64("uses_chkstk",
                    [](const FrameInfo &r) -> int64_t {
                      return r.uses_chkstk() ? 1 : 0;
                    })
      // Bytes the function pops off the stack on return (__stdcall's argument
      // bytes; 0 for __cdecl): IDA's func_t::argsize, which arg_size is not.
      .column_int64("purged_size",
                    [](const FrameInfo &r) -> int64_t { return r.purged_size; })
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<FrameInFuncIterator>(
                static_cast<ea_t>(func_addr));
          },
          1.0, 1.0)
      .build();
}

} // namespace code
} // namespace idasql
