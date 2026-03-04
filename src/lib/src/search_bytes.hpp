// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * search_bytes.hpp - Binary pattern search functions for IDASQL
 */

#pragma once

#include <idasql/platform.hpp>

#include <xsql/database.hpp>
#include <xsql/functions.hpp>
#include <xsql/json.hpp>
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

ea_t find_first_pattern(const char* pattern, ea_t start_ea, ea_t end_ea);

bool register_search_bytes(xsql::Database& db);

} // namespace search
} // namespace idasql
