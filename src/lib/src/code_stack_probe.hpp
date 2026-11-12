// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

#include <string>

namespace idasql {
namespace code {

std::string stack_pointer_reg_name(ea_t ea);

bool is_stack_probe_name(ea_t ea, const std::string &name);

bool function_calls_stack_probe(ea_t func_ea);

}
}
