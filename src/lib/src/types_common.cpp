// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_common.hpp"

namespace idasql {
namespace types {

// ============================================================================
// Type Kind Classification
// ============================================================================

const char* get_type_kind(const tinfo_t& tif) {
    if (tif.is_struct()) return "struct";
    if (tif.is_union()) return "union";
    if (tif.is_enum()) return "enum";
    if (tif.is_typedef()) return "typedef";
    if (tif.is_func()) return "func";
    if (tif.is_ptr()) return "ptr";
    if (tif.is_array()) return "array";
    return "other";
}

// ============================================================================
// Type Entry Cache
// ============================================================================

} // namespace types
} // namespace idasql
