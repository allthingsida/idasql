// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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

inline constexpr int kRowidIndexBits = 31;
inline constexpr int64_t kRowidIndexMask = (int64_t(1) << kRowidIndexBits) - 1;

inline int64_t pack_type_rowid(uint32_t ordinal, int index) {
    return (static_cast<int64_t>(ordinal) << kRowidIndexBits)
         | (static_cast<int64_t>(index) & kRowidIndexMask);
}

inline bool unpack_type_rowid(int64_t rowid, uint32_t &ordinal, int &index) {
    if (rowid < 0) return false;
    ordinal = static_cast<uint32_t>(rowid >> kRowidIndexBits);
    index = static_cast<int>(rowid & kRowidIndexMask);
    return true;
}

const char *get_type_kind(const tinfo_t &tif);

}
}
