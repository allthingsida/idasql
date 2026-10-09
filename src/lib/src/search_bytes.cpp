// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "search_bytes.hpp"

#include "core_common.hpp"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>

namespace idasql {
namespace search {

namespace {

constexpr int BYTE_SEARCH_ADDRESS = 0;
constexpr int BYTE_SEARCH_MATCHED_HEX = 1;
constexpr int BYTE_SEARCH_MATCHED_BYTES = 2;
constexpr int BYTE_SEARCH_SIZE = 3;
constexpr int BYTE_SEARCH_PATTERN = 4;
constexpr int BYTE_SEARCH_START_EA = 5;
constexpr int BYTE_SEARCH_END_EA = 6;
constexpr int BYTE_SEARCH_MAX_RESULTS = 7;

std::string format_matched_hex(const std::vector<uchar>& bytes) {
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (size_t i = 0; i < bytes.size(); i++) {
        if (i > 0) hex << " ";
        hex << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return hex.str();
}

void fill_match_result(ByteSearchResult& result, ea_t address, size_t pattern_len) {
    result.address = address;
    result.matched_bytes.resize(pattern_len);
    for (size_t i = 0; i < pattern_len; i++) {
        result.matched_bytes[i] = get_byte(address + i);
    }
    result.matched_hex = format_matched_hex(result.matched_bytes);
}

ea_t saturating_next_ea(ea_t ea) {
    const ea_t max_ea = std::numeric_limits<ea_t>::max();
    if (ea >= max_ea) return max_ea;
    return ea + 1;
}

class EmptyByteSearchGenerator final : public xsql::Generator<ByteSearchResult> {
public:
    bool next() override { return false; }
    const ByteSearchResult& current() const override { return current_; }
    int64_t rowid() const override { return 0; }

private:
    ByteSearchResult current_{};
};

// Scans the addr window for a byte pattern in SQL order. The window's unsigned
// spans (xsql::Int64KeyRange::unsigned_spans) are searched in turn -- the part
// at or above 2^63 first, since those addresses are negative INTEGERs -- each
// within the unsigned [start_addr, end_addr) scan bounds. A match belongs to the
// span its START falls in; bin_search needs the whole match below its end
// bound, so a span's scan end is widened by the pattern length (saturating at
// the top of the address space).
class ByteSearchGenerator final : public xsql::Generator<ByteSearchResult> {
public:
    ByteSearchGenerator(const std::string& pattern, ea_t start_ea, ea_t end_ea,
                        const xsql::Int64KeyRange& addr_range, size_t max_results)
        : max_results_(max_results)
    {
        if (pattern.empty() || end_ea <= start_ea) return;

        qstring errbuf;
        if (!parse_binpat_str(&binpat_, start_ea, pattern.c_str(), 16, PBSENC_DEF1BPU, &errbuf)) {
            return;
        }
        if (binpat_.empty()) return;
        pattern_len_ = binpat_[0].bytes.size();
        if (pattern_len_ == 0) return;

        const ea_t len = static_cast<ea_t>(pattern_len_);
        for (const xsql::U64Span& span : addr_range.unsigned_spans()) {
            const ea_t lo = static_cast<ea_t>(span.lo);
            const ea_t hi = static_cast<ea_t>(span.hi);
            const ea_t tail_end = hi >= BADADDR - len ? BADADDR : hi + len;
            Window window;
            window.next = std::max(start_ea, lo);
            window.end = std::min(end_ea, tail_end);
            window.last_start = hi;
            if (window.next < window.end) windows_.push_back(window);
        }
    }

    bool next() override {
        if (max_results_ > 0 && emitted_ >= max_results_) return false;
        while (window_ < windows_.size()) {
            Window& window = windows_[window_];
            if (window.next < window.end) {
                const ea_t found =
                    bin_search(window.next, window.end, binpat_, BIN_SEARCH_FORWARD);
                if (found != BADADDR && found >= window.next && found <= window.last_start) {
                    fill_match_result(current_, found, pattern_len_);
                    window.next = saturating_next_ea(found);
                    emitted_++;
                    rowid_++;
                    return true;
                }
            }
            ++window_;
        }
        return false;
    }

    const ByteSearchResult& current() const override {
        return current_;
    }

    int64_t rowid() const override {
        return rowid_;
    }

private:
    struct Window {
        ea_t next = BADADDR;        // where the scan resumes
        ea_t end = BADADDR;         // bin_search's exclusive end bound
        ea_t last_start = BADADDR;  // the last address a match may start at
    };

    compiled_binpat_vec_t binpat_;
    std::vector<Window> windows_;
    size_t window_ = 0;
    size_t pattern_len_ = 0;
    size_t max_results_ = 0;
    size_t emitted_ = 0;
    int64_t rowid_ = 0;
    ByteSearchResult current_{};
};

std::unique_ptr<xsql::Generator<ByteSearchResult>> make_byte_search_generator(
    const std::vector<xsql::GeneratorConstraintArg>& args)
{
    // Every constraint here is omit=1. The inputs (pattern, start_addr,
    // end_addr, max_results) take a value only when a native column of their
    // type would equal it -- NULL, 4096.5 or a blob pattern requests nothing
    // -- and the addr bounds are compared the way SQLite compares the INTEGER
    // addr column (xsql::Int64KeyRange).
    std::string pattern;
    ea_t start_ea = inf_get_min_ea();
    ea_t end_ea = inf_get_max_ea();
    size_t max_results = 0;
    xsql::Int64KeyRange addr_range;

    for (const auto& arg : args) {
        if (arg.column_index == BYTE_SEARCH_ADDRESS) {
            if (arg.op == xsql::ConstraintOp::Like) continue;
            addr_range.constrain(arg.op, arg.value);
            continue;
        }
        if (arg.op != xsql::ConstraintOp::Eq) continue;
        switch (arg.column_index) {
            case BYTE_SEARCH_PATTERN: {
                const std::optional<std::string> text = xsql::exact_text(arg.value);
                if (!text) return std::make_unique<EmptyByteSearchGenerator>();
                pattern = *text;
                break;
            }
            case BYTE_SEARCH_START_EA:
            case BYTE_SEARCH_END_EA:
            case BYTE_SEARCH_MAX_RESULTS: {
                const std::optional<int64_t> value = xsql::exact_int64(arg.value);
                if (!value) return std::make_unique<EmptyByteSearchGenerator>();
                if (arg.column_index == BYTE_SEARCH_START_EA) {
                    start_ea = std::max(start_ea, core::normalize_sql_ea(*value));
                } else if (arg.column_index == BYTE_SEARCH_END_EA) {
                    end_ea = std::min(end_ea, core::normalize_sql_ea(*value));
                } else {
                    max_results = *value > 0 ? static_cast<size_t>(*value) : 0;
                }
                break;
            }
            default:
                break;
        }
    }

    if (pattern.empty() || addr_range.empty()) {
        return std::make_unique<EmptyByteSearchGenerator>();
    }

    return std::make_unique<ByteSearchGenerator>(pattern, start_ea, end_ea, addr_range,
                                                 max_results);
}

} // namespace

xsql::GeneratorTableDef<ByteSearchResult> define_byte_search() {
    return xsql::generator_table<ByteSearchResult>("byte_search")
        .column_int64("addr", [](const ByteSearchResult& row) {
            return static_cast<int64_t>(row.address);
        })
        .column_text("matched_hex", [](const ByteSearchResult& row) {
            return row.matched_hex;
        })
        .column_blob("matched_bytes", [](const ByteSearchResult& row) {
            return std::vector<uint8_t>(row.matched_bytes.begin(), row.matched_bytes.end());
        })
        .column_int("size", [](const ByteSearchResult& row) {
            return static_cast<int>(row.matched_bytes.size());
        })
        .hidden_column_text("pattern")
        .hidden_column_int64("start_addr")
        .hidden_column_int64("end_addr")
        .hidden_column_int("max_results")
        .full_scan_error(
            "byte_search requires WHERE pattern = '<IDA byte pattern>'; "
            "matched_hex is an output column, not the search input")
        .constraint_filter(
            {
                xsql::required_eq("pattern", "byte_search requires WHERE pattern = '<IDA byte pattern>'"),
                xsql::optional_eq("start_addr"),
                xsql::optional_eq("end_addr"),
                xsql::optional_eq("max_results"),
                xsql::optional_ge("addr"),
                xsql::optional_gt("addr"),
                xsql::optional_lt("addr"),
                xsql::optional_le("addr"),
            },
            make_byte_search_generator,
            1.0,
            100.0)
        .order_by_consumed("addr")
        .build();
}

bool register_byte_search(xsql::Database& db) {
    static auto byte_search = define_byte_search();
    return db.register_generator_table("byte_search", &byte_search) &&
           db.create_table("byte_search", "byte_search");
}

} // namespace search
} // namespace idasql
