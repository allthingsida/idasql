// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "search_bytes.hpp"

#include <sstream>
#include <iomanip>

namespace idasql {
namespace search {

size_t find_byte_pattern(
    const char* pattern,
    ea_t start_ea,
    ea_t end_ea,
    std::vector<ByteSearchResult>& results,
    size_t max_results)
{
    if (!pattern || !*pattern) return 0;

    compiled_binpat_vec_t binpat;
    qstring errbuf;

    if (!parse_binpat_str(&binpat, start_ea, pattern, 16, PBSENC_DEF1BPU, &errbuf)) {
        return 0;
    }

    if (binpat.empty()) return 0;

    size_t pattern_len = binpat[0].bytes.size();

    ea_t ea = start_ea;
    size_t count = 0;

    while (ea < end_ea) {
        ea_t found = bin_search(ea, end_ea, binpat, BIN_SEARCH_FORWARD);
        if (found == BADADDR) break;

        ByteSearchResult result;
        result.address = found;

        result.matched_bytes.resize(pattern_len);
        for (size_t i = 0; i < pattern_len; i++) {
            result.matched_bytes[i] = get_byte(found + i);
        }

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

        ea = found + 1;
    }

    return count;
}

ea_t find_first_pattern(const char* pattern, ea_t start_ea, ea_t end_ea) {
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
// SQL Function Implementations
// ============================================================================

static void sql_search_bytes_1(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("search_bytes requires pattern argument");
        return;
    }

    const char* pattern = argv[0].as_c_str();
    if (!pattern) {
        ctx.result_error("Invalid pattern");
        return;
    }

    ea_t start_ea = inf_get_min_ea();
    ea_t end_ea = inf_get_max_ea();

    std::vector<ByteSearchResult> results;
    find_byte_pattern(pattern, start_ea, end_ea, results);

    xsql::json arr = xsql::json::array();
    for (const auto& r : results) {
        arr.push_back({
            {"address", r.address},
            {"matched_hex", r.matched_hex},
            {"size", r.matched_bytes.size()}
        });
    }

    std::string result = arr.dump();
    ctx.result_text(result);
}

static void sql_search_bytes_3(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("search_bytes requires (pattern, start, end) arguments");
        return;
    }

    const char* pattern = argv[0].as_c_str();
    if (!pattern) {
        ctx.result_error("Invalid pattern");
        return;
    }

    ea_t start_ea = static_cast<ea_t>(argv[1].as_int64());
    ea_t end_ea = static_cast<ea_t>(argv[2].as_int64());

    std::vector<ByteSearchResult> results;
    find_byte_pattern(pattern, start_ea, end_ea, results);

    xsql::json arr = xsql::json::array();
    for (const auto& r : results) {
        arr.push_back({
            {"address", r.address},
            {"matched_hex", r.matched_hex},
            {"size", r.matched_bytes.size()}
        });
    }

    std::string result = arr.dump();
    ctx.result_text(result);
}

static void sql_search_first_1(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("search_first requires pattern argument");
        return;
    }

    const char* pattern = argv[0].as_c_str();
    if (!pattern) {
        ctx.result_error("Invalid pattern");
        return;
    }

    ea_t result = find_first_pattern(pattern, inf_get_min_ea(), inf_get_max_ea());
    if (result != BADADDR) {
        ctx.result_int64(static_cast<int64_t>(result));
    } else {
        ctx.result_null();
    }
}

static void sql_search_first_3(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("search_first requires (pattern, start, end) arguments");
        return;
    }

    const char* pattern = argv[0].as_c_str();
    if (!pattern) {
        ctx.result_error("Invalid pattern");
        return;
    }

    ea_t start_ea = static_cast<ea_t>(argv[1].as_int64());
    ea_t end_ea = static_cast<ea_t>(argv[2].as_int64());

    ea_t result = find_first_pattern(pattern, start_ea, end_ea);
    if (result != BADADDR) {
        ctx.result_int64(static_cast<int64_t>(result));
    } else {
        ctx.result_null();
    }
}

bool register_search_bytes(xsql::Database& db) {
    db.register_function("search_bytes", 1, xsql::ScalarFn(sql_search_bytes_1));
    db.register_function("search_bytes", 3, xsql::ScalarFn(sql_search_bytes_3));
    db.register_function("search_first", 1, xsql::ScalarFn(sql_search_first_1));
    db.register_function("search_first", 3, xsql::ScalarFn(sql_search_first_3));
    return true;
}

} // namespace search
} // namespace idasql
