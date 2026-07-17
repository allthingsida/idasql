// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_segments.hpp - `segments` table (start/end, name, class, perms).
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace memory {

VTableDef define_segments();

} // namespace memory
} // namespace idasql
