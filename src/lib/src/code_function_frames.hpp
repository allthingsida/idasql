// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * code_function_frames.hpp - `function_frames` table (per-function stack-frame
 * layout). Canonical cross-tool columns (ghidra reference): func_addr, frame_size,
 * arg_size, local_size, saved_reg_size, stack_base_reg, has_frame_pointer; then
 * idasql's func_name and uses_chkstk. Served decompiler-free from IDA's frame APIs
 * and function fields.
 */

#pragma once

#include "core_common.hpp"

#include <optional>

namespace idasql {
namespace code {

// One row per analyzed function's stack frame. `stack_base_reg` is the stack-pointer
// register at the function's code width (as ghidrasql and bnsql report it: "rsp",
// "esp"), empty (SQL NULL) when the processor module has none named "sp".
struct FrameInfo {
  ea_t func_ea = BADADDR;
  int64_t frame_size = 0;
  int64_t arg_size = 0;      // the stack-argument area (ghidrasql's parameter size)
  int64_t local_size = 0;
  int64_t saved_reg_size = 0;
  std::string stack_base_reg;
  bool has_frame_pointer = false;
  std::string func_name;
  int64_t purged_size = 0;   // bytes the callee pops on return (func_t::argsize)

  // Decodes the whole function, so it is computed only when the column is read.
  bool uses_chkstk() const;

private:
  mutable std::optional<bool> uses_chkstk_;
};

GeneratorTableDef<FrameInfo> define_function_frames();

} // namespace code
} // namespace idasql
