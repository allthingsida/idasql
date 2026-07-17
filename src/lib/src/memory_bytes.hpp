// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_bytes.hpp - `bytes` generator table (raw/patched byte access).
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace memory {

struct ByteRow {
  ea_t ea = BADADDR;
};

GeneratorTableDef<ByteRow> define_bytes();

} // namespace memory
} // namespace idasql
