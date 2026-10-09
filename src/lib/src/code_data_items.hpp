// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * code_data_items.hpp - `data_items` table (defined data items). Canonical
 * cross-tool schema (ghidra reference): addr, name, data_type, size, value_repr,
 * segment_name, is_string, is_initialized. Enumerates data heads (is_data flag).
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace code {

// One defined data item (columns resolved lazily from the address, like `heads`).
struct DataItemRow {
  ea_t ea = BADADDR;
};

GeneratorTableDef<DataItemRow> define_data_items();

} // namespace code
} // namespace idasql
