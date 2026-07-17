// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * types_applied.hpp - `applied_types` table (type bindings at addresses).
 */

#pragma once

#include "types_common.hpp"

namespace idasql {
namespace types {

struct AppliedTypeEntry {
  ea_t ea = BADADDR;
};

GeneratorTableDef<AppliedTypeEntry> define_applied_types();

} // namespace types
} // namespace idasql
