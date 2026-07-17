// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * types_common.hpp - Shared declarations for the idasql::types tables.
 *
 * Common includes plus the type-kind classifier used across the per-table type
 * definition units (types_base.cpp, types_members.cpp, ...). Each per-table
 * type header includes this one.
 */

#pragma once

#include <idasql/platform.hpp>

#include <idasql/string_utils.hpp>
#include <idasql/vtable.hpp>
#include <xsql/database.hpp>
#include <xsql/vtable.hpp>

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "dirtree_utils.hpp"
#include "ida_headers.hpp"

namespace idasql {
namespace types {

// Rowid packing for the per-member/per-value tables (types_members,
// types_enum_values). A row's stable rowid bit-packs the two coordinates that
// identify a member/value -- the type ordinal and the index within that type:
//   rowid = (int64(type_ordinal) << kRowidIndexBits) | index
// The LOW 31 bits hold the index and the HIGH 32 bits hold the (uint32) ordinal.
// 31 index bits is deliberate: every non-negative `int` index fits without any
// masking, and for any non-negative int64 rowid the high component (rowid >> 31)
// is <= UINT32_MAX, so the uint32 cast in unpack never wraps. That makes
// pack/unpack a true bijection over [0, 2^63): a crafted out-of-range rowid (e.g.
// real_rowid + (1<<56)) decodes to a DIFFERENT (ordinal, index) pair -- which the
// caller's build_*_entry then rejects -- instead of aliasing the original row.
// Rowids are ephemeral (recomputed each session, never stored in the .idb), so
// the scheme can change freely as long as the .rowid() lambda, the pushdown
// iterators, and row_lookup() all use these helpers and agree.
inline constexpr int kRowidIndexBits = 31;
inline constexpr int64_t kRowidIndexMask = (int64_t(1) << kRowidIndexBits) - 1;

inline int64_t pack_type_rowid(uint32_t ordinal, int index) {
    // index is a non-negative member/value index (< 2^31), so it fits the low
    // bits exactly; mask only as defense against a negative/garbage index.
    return (static_cast<int64_t>(ordinal) << kRowidIndexBits)
         | (static_cast<int64_t>(index) & kRowidIndexMask);
}

// Unpack a packed rowid. Returns false for a negative rowid. The high component
// of any non-negative int64 is <= UINT32_MAX, so the ordinal cast cannot wrap;
// the caller still validates (ordinal, index) against the live type.
inline bool unpack_type_rowid(int64_t rowid, uint32_t &ordinal, int &index) {
    if (rowid < 0) return false;
    ordinal = static_cast<uint32_t>(rowid >> kRowidIndexBits);
    index = static_cast<int>(rowid & kRowidIndexMask);
    return true;
}

// Classify a tinfo_t into a coarse kind string (struct/union/enum/...)
const char *get_type_kind(const tinfo_t &tif);

} // namespace types
} // namespace idasql
