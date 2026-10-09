// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * code_stack_probe.hpp - stack facts shared by the frame surfaces:
 * the stack-pointer register name, and whether a function calls a stack-probe
 * helper (__chkstk, __alloca_probe, ___chkstk_ms, __rust_probestack...).
 */

#pragma once

#include "core_common.hpp"

#include <string>

namespace idasql {
namespace code {

// The stack-pointer register as IDA prints it for the code at `ea` ("esp" in 32-bit
// x86, "rsp" in x64, "SP" in AArch64, "$sp" in MIPS): the register the processor
// module answers to "sp", named at the width of the segment holding `ea`. "" when
// there is no such register (PowerPC's r1 is not called "sp") or no segment.
std::string stack_pointer_reg_name(ea_t ea);

// True when `name` (the name at `ea`) is a stack-probe helper: an optional
// "__imp_" import prefix removed, IDA's own cleanup_name() applied (leading
// underscores, "j_", "@N" and "_N" suffixes), then an exact match against the
// known probe-helper names. Never a substring match.
bool is_stack_probe_name(ea_t ea, const std::string &name);

// True when a call instruction anywhere in the function starting at `func_ea`
// (every chunk) reaches a stack-probe helper: directly, through a jmp thunk (to the
// helper or to its import slot), or through an import slot. The processor module's
// own probe test (processor_t::is_alloca_probe, x86/x64) is asked first.
bool function_calls_stack_probe(ea_t func_ea);

} // namespace code
} // namespace idasql
