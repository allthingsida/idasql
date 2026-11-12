// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

#include <optional>

namespace idasql {
namespace code {

struct FrameInfo {
  ea_t func_ea = BADADDR;
  int64_t frame_size = 0;
  int64_t arg_size = 0;
  int64_t local_size = 0;
  int64_t saved_reg_size = 0;
  std::string stack_base_reg;
  bool has_frame_pointer = false;
  std::string func_name;
  int64_t purged_size = 0;

  bool uses_chkstk() const;

private:
  mutable std::optional<bool> uses_chkstk_;
};

GeneratorTableDef<FrameInfo> define_function_frames();

}
}
