// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "search_bytes.hpp"

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

ea_t as_ea(const xsql::FunctionArg& value) {
    return static_cast<ea_t>(value.as_int64());
}

size_t as_size(const xsql::FunctionArg& value) {
    const int64_t v = value.as_int64();
    return v > 0 ? static_cast<size_t>(v) : 0;
}

class EmptyByteSearchGenerator final : public xsql::Generator<ByteSearchResult> {
public:
    bool next() override { return false; }
    const ByteSearchResult& current() const override { return current_; }
    int64_t rowid() const override { return 0; }

private:
    ByteSearchResult current_{};
};

class ByteSearchGenerator final : public xsql::Generator<ByteSearchResult> {
public:
    ByteSearchGenerator(std::string pattern, ea_t start_ea, ea_t end_ea, size_t max_results)
        : start_ea_(start_ea),
          end_ea_(end_ea),
          next_ea_(start_ea),
          max_results_(max_results)
    {
        if (pattern.empty() || end_ea_ <= start_ea_) {
            return;
        }

        qstring errbuf;
        if (!parse_binpat_str(&binpat_, start_ea_, pattern.c_str(), 16, PBSENC_DEF1BPU, &errbuf)) {
            return;
        }

        if (binpat_.empty()) {
            return;
        }

        pattern_len_ = binpat_[0].bytes.size();
        valid_ = pattern_len_ > 0;
    }

    bool next() override {
        if (!valid_) return false;
        if (max_results_ > 0 && emitted_ >= max_results_) return false;
        if (next_ea_ >= end_ea_) return false;

        ea_t found = bin_search(next_ea_, end_ea_, binpat_, BIN_SEARCH_FORWARD);
        if (found == BADADDR) return false;

        fill_match_result(current_, found, pattern_len_);
        next_ea_ = saturating_next_ea(found);
        emitted_++;
        rowid_++;
        return true;
    }

    const ByteSearchResult& current() const override {
        return current_;
    }

    int64_t rowid() const override {
        return rowid_;
    }

private:
    compiled_binpat_vec_t binpat_;
    ea_t start_ea_ = BADADDR;
    ea_t end_ea_ = BADADDR;
    ea_t next_ea_ = BADADDR;
    size_t pattern_len_ = 0;
    size_t max_results_ = 0;
    size_t emitted_ = 0;
    int64_t rowid_ = 0;
    bool valid_ = false;
    ByteSearchResult current_{};
};

std::unique_ptr<xsql::Generator<ByteSearchResult>> make_byte_search_generator(
    const std::vector<xsql::GeneratorConstraintArg>& args)
{
    std::string pattern;
    ea_t start_ea = inf_get_min_ea();
    ea_t end_ea = inf_get_max_ea();
    size_t max_results = 0;

    for (const auto& arg : args) {
        switch (arg.column_index) {
            case BYTE_SEARCH_PATTERN:
                if (arg.op == xsql::ConstraintOp::Eq) {
                    const char* text = arg.value.as_c_str();
                    pattern = text ? text : "";
                }
                break;
            case BYTE_SEARCH_START_EA:
                if (arg.op == xsql::ConstraintOp::Eq) {
                    start_ea = std::max(start_ea, as_ea(arg.value));
                }
                break;
            case BYTE_SEARCH_END_EA:
                if (arg.op == xsql::ConstraintOp::Eq) {
                    end_ea = std::min(end_ea, as_ea(arg.value));
                }
                break;
            case BYTE_SEARCH_MAX_RESULTS:
                if (arg.op == xsql::ConstraintOp::Eq) {
                    max_results = as_size(arg.value);
                }
                break;
            case BYTE_SEARCH_ADDRESS:
                if (arg.op == xsql::ConstraintOp::Ge) {
                    start_ea = std::max(start_ea, as_ea(arg.value));
                } else if (arg.op == xsql::ConstraintOp::Gt) {
                    start_ea = std::max(start_ea, saturating_next_ea(as_ea(arg.value)));
                } else if (arg.op == xsql::ConstraintOp::Lt) {
                    end_ea = std::min(end_ea, as_ea(arg.value));
                } else if (arg.op == xsql::ConstraintOp::Le) {
                    end_ea = std::min(end_ea, saturating_next_ea(as_ea(arg.value)));
                }
                break;
            default:
                break;
        }
    }

    if (pattern.empty()) {
        return std::make_unique<EmptyByteSearchGenerator>();
    }

    return std::make_unique<ByteSearchGenerator>(std::move(pattern), start_ea, end_ea, max_results);
}

} // namespace

size_t find_byte_pattern(
    const char* pattern,
    ea_t start_ea,
    ea_t end_ea,
    std::vector<ByteSearchResult>& results,
    size_t max_results)
{
    results.clear();

    ByteSearchGenerator generator(pattern ? pattern : "", start_ea, end_ea, max_results);
    while (generator.next()) {
        results.push_back(generator.current());
    }
    return results.size();
}

xsql::GeneratorTableDef<ByteSearchResult> define_byte_search() {
    return xsql::generator_table<ByteSearchResult>("byte_search")
        .column_int64("address", [](const ByteSearchResult& row) {
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
        .hidden_column_int64("start_ea")
        .hidden_column_int64("end_ea")
        .hidden_column_int("max_results")
        .full_scan_error(
            "byte_search requires WHERE pattern = '<IDA byte pattern>'; "
            "matched_hex is an output column, not the search input")
        .constraint_filter(
            {
                xsql::required_eq("pattern", "byte_search requires WHERE pattern = '<IDA byte pattern>'"),
                xsql::optional_eq("start_ea"),
                xsql::optional_eq("end_ea"),
                xsql::optional_eq("max_results"),
                xsql::optional_ge("address"),
                xsql::optional_gt("address"),
                xsql::optional_lt("address"),
                xsql::optional_le("address"),
            },
            make_byte_search_generator,
            1.0,
            100.0)
        .order_by_consumed("address")
        .build();
}

bool register_byte_search(xsql::Database& db) {
    static auto byte_search = define_byte_search();
    return db.register_generator_table("ida_byte_search", &byte_search) &&
           db.create_table("byte_search", "ida_byte_search");
}

} // namespace search
} // namespace idasql
