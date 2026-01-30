// Copyright (c) 2025 Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * search_bytes.hpp - Binary pattern search functions for IDASQL
 *
 * Provides search_bytes() and search_first() functions for finding byte patterns.
 *
 * Pattern syntax (IDA native):
 *   - "48 8B 05"       - Exact bytes (hex, space-separated)
 *   - "48 ? 05"        - ? = any byte wildcard (whole byte only)
 *   - "48 ?? 05"       - ?? = same as ? (any byte)
 *   - "(01 02 03)"     - Alternatives (match any of these bytes)
 *
 * SQL usage:
 *   SELECT search_bytes('48 8B ? 00');                    -- Returns JSON array
 *   SELECT search_bytes('48 8B ? 00', 0x401000, 0x402000); -- With range
 *   SELECT search_first('48 8B ? 00');                    -- Returns first address
 *
 * Unlike Binary Ninja:
 *   - No nibble wildcards (? always means full byte)
 *   - No regex support
 *   - Supports alternatives like (01 02 03)
 */

#pragma once

#include <sqlite3.h>
#include <xsql/database.hpp>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

// IDA SDK
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>
#include <segment.hpp>

namespace idasql {
namespace search {

// ============================================================================
// Search Result
// ============================================================================

struct ByteSearchResult {
    ea_t address;
    std::vector<uchar> matched_bytes;
    std::string matched_hex;
};

// ============================================================================
// Binary Pattern Search Implementation
// ============================================================================

/**
 * Find all matches for a byte pattern in the given range.
 *
 * @param pattern   Pattern string like "48 8B ? 00" or "48 ?? (01 02) 00"
 * @param start_ea  Start of search range (default: inf_get_min_ea())
 * @param end_ea    End of search range (default: inf_get_max_ea())
 * @param results   Vector to store results
 * @param max_results Maximum results to return (0 = unlimited)
 * @return Number of matches found
 */
inline size_t find_byte_pattern(
    const char* pattern,
    ea_t start_ea,
    ea_t end_ea,
    std::vector<ByteSearchResult>& results,
    size_t max_results = 0)
{
    if (!pattern || !*pattern) return 0;

    // Parse the pattern string
    compiled_binpat_vec_t binpat;
    qstring errbuf;

    if (!parse_binpat_str(&binpat, start_ea, pattern, 16, PBSENC_DEF1BPU, &errbuf)) {
        // Pattern parse failed
        return 0;
    }

    if (binpat.empty()) return 0;

    // Get pattern length for reading matched bytes
    size_t pattern_len = binpat[0].bytes.size();

    ea_t ea = start_ea;
    size_t count = 0;

    while (ea < end_ea) {
        ea_t found = bin_search(ea, end_ea, binpat, BIN_SEARCH_FORWARD);
        if (found == BADADDR) break;

        ByteSearchResult result;
        result.address = found;

        // Read matched bytes
        result.matched_bytes.resize(pattern_len);
        for (size_t i = 0; i < pattern_len; i++) {
            result.matched_bytes[i] = get_byte(found + i);
        }

        // Build hex string
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < pattern_len; i++) {
            if (i > 0) hex << " ";
            hex << std::setw(2) << static_cast<int>(result.matched_bytes[i]);
        }
        result.matched_hex = hex.str();

        results.push_back(std::move(result));
        count++;

        if (max_results > 0 && count >= max_results) break;

        ea = found + 1;  // Move past this match
    }

    return count;
}

/**
 * Find first match for a byte pattern.
 *
 * @return Address of first match, or BADADDR if not found
 */
inline ea_t find_first_pattern(const char* pattern, ea_t start_ea, ea_t end_ea) {
    if (!pattern || !*pattern) return BADADDR;

    compiled_binpat_vec_t binpat;
    qstring errbuf;

    if (!parse_binpat_str(&binpat, start_ea, pattern, 16, PBSENC_DEF1BPU, &errbuf)) {
        return BADADDR;
    }

    if (binpat.empty()) return BADADDR;

    return bin_search(start_ea, end_ea, binpat, BIN_SEARCH_FORWARD);
}

// ============================================================================
// SQL Function Registration
// ============================================================================

// search_bytes(pattern) - Returns JSON array of all matches
static void sql_search_bytes_1(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "search_bytes requires pattern argument", -1);
        return;
    }

    const char* pattern = (const char*)sqlite3_value_text(argv[0]);
    if (!pattern) {
        sqlite3_result_error(ctx, "Invalid pattern", -1);
        return;
    }

    ea_t start_ea = inf_get_min_ea();
    ea_t end_ea = inf_get_max_ea();

    std::vector<ByteSearchResult> results;
    find_byte_pattern(pattern, start_ea, end_ea, results);

    // Build JSON array
    std::ostringstream json;
    json << "[";
    for (size_t i = 0; i < results.size(); i++) {
        if (i > 0) json << ",";
        json << "{\"address\":" << results[i].address;
        json << ",\"matched_hex\":\"" << results[i].matched_hex << "\"";
        json << ",\"size\":" << results[i].matched_bytes.size() << "}";
    }
    json << "]";

    std::string result = json.str();
    sqlite3_result_text(ctx, result.c_str(), -1, SQLITE_TRANSIENT);
}

// search_bytes(pattern, start, end) - Returns JSON array within range
static void sql_search_bytes_3(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 3) {
        sqlite3_result_error(ctx, "search_bytes requires (pattern, start, end) arguments", -1);
        return;
    }

    const char* pattern = (const char*)sqlite3_value_text(argv[0]);
    if (!pattern) {
        sqlite3_result_error(ctx, "Invalid pattern", -1);
        return;
    }

    ea_t start_ea = static_cast<ea_t>(sqlite3_value_int64(argv[1]));
    ea_t end_ea = static_cast<ea_t>(sqlite3_value_int64(argv[2]));

    std::vector<ByteSearchResult> results;
    find_byte_pattern(pattern, start_ea, end_ea, results);

    // Build JSON array
    std::ostringstream json;
    json << "[";
    for (size_t i = 0; i < results.size(); i++) {
        if (i > 0) json << ",";
        json << "{\"address\":" << results[i].address;
        json << ",\"matched_hex\":\"" << results[i].matched_hex << "\"";
        json << ",\"size\":" << results[i].matched_bytes.size() << "}";
    }
    json << "]";

    std::string result = json.str();
    sqlite3_result_text(ctx, result.c_str(), -1, SQLITE_TRANSIENT);
}

// search_first(pattern) - Returns first match address
static void sql_search_first_1(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "search_first requires pattern argument", -1);
        return;
    }

    const char* pattern = (const char*)sqlite3_value_text(argv[0]);
    if (!pattern) {
        sqlite3_result_error(ctx, "Invalid pattern", -1);
        return;
    }

    ea_t result = find_first_pattern(pattern, inf_get_min_ea(), inf_get_max_ea());
    if (result != BADADDR) {
        sqlite3_result_int64(ctx, static_cast<sqlite3_int64>(result));
    } else {
        sqlite3_result_null(ctx);
    }
}

// search_first(pattern, start, end) - Returns first match in range
static void sql_search_first_3(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 3) {
        sqlite3_result_error(ctx, "search_first requires (pattern, start, end) arguments", -1);
        return;
    }

    const char* pattern = (const char*)sqlite3_value_text(argv[0]);
    if (!pattern) {
        sqlite3_result_error(ctx, "Invalid pattern", -1);
        return;
    }

    ea_t start_ea = static_cast<ea_t>(sqlite3_value_int64(argv[1]));
    ea_t end_ea = static_cast<ea_t>(sqlite3_value_int64(argv[2]));

    ea_t result = find_first_pattern(pattern, start_ea, end_ea);
    if (result != BADADDR) {
        sqlite3_result_int64(ctx, static_cast<sqlite3_int64>(result));
    } else {
        sqlite3_result_null(ctx);
    }
}

/**
 * Register all search_bytes SQL functions.
 */
inline bool register_search_bytes(xsql::Database& db) {
    // search_bytes(pattern) - all matches as JSON
    sqlite3_create_function(db.handle(), "search_bytes", 1, SQLITE_UTF8,
                            nullptr, sql_search_bytes_1, nullptr, nullptr);

    // search_bytes(pattern, start, end) - matches in range
    sqlite3_create_function(db.handle(), "search_bytes", 3, SQLITE_UTF8,
                            nullptr, sql_search_bytes_3, nullptr, nullptr);

    // search_first(pattern) - first match address
    sqlite3_create_function(db.handle(), "search_first", 1, SQLITE_UTF8,
                            nullptr, sql_search_first_1, nullptr, nullptr);

    // search_first(pattern, start, end) - first match in range
    sqlite3_create_function(db.handle(), "search_first", 3, SQLITE_UTF8,
                            nullptr, sql_search_first_3, nullptr, nullptr);

    return true;
}

} // namespace search
} // namespace idasql
