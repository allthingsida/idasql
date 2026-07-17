// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * search_bytes.hpp - Binary pattern search table for IDASQL
 */

#pragma once

#include <idasql/platform.hpp>

#include <xsql/database.hpp>
#include <xsql/vtable.hpp>

#include <string>
#include <vector>

#include "ida_headers.hpp"

namespace idasql {
namespace search {

struct ByteSearchResult {
    ea_t address;
    std::vector<uchar> matched_bytes;
    std::string matched_hex;
};

size_t find_byte_pattern(
    const char* pattern,
    ea_t start_ea,
    ea_t end_ea,
    std::vector<ByteSearchResult>& results,
    size_t max_results = 0);

xsql::GeneratorTableDef<ByteSearchResult> define_byte_search();

bool register_byte_search(xsql::Database& db);

} // namespace search
} // namespace idasql
