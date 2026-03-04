// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

#include <idasql/platform.hpp>

#include <sstream>
#include <string>
#include <vector>

#include "metadata_welcome.hpp"

#include "ida_headers.hpp"

namespace idasql {
namespace metadata {
namespace {

static std::string format_hex_u64(uint64_t value) {
    char buf[32];
    qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)value);
    return std::string(buf);
}

static std::string get_primary_entry_name() {
    if (get_entry_qty() <= 0) {
        return "";
    }
    qstring name;
    const uval_t ord = get_entry_ordinal(0);
    get_entry_name(&name, ord);
    return std::string(name.c_str());
}

static void collect_welcome(std::vector<WelcomeRow>& rows) {
    rows.clear();

    WelcomeRow row;
    row.processor = inf_get_procname().c_str();
    row.is_64bit = inf_is_64bit() ? 1 : 0;
    row.min_ea = format_hex_u64(static_cast<uint64_t>(inf_get_min_ea()));
    row.max_ea = format_hex_u64(static_cast<uint64_t>(inf_get_max_ea()));
    row.start_ea = format_hex_u64(static_cast<uint64_t>(inf_get_start_ea()));

    row.entry_name = get_primary_entry_name();
    if (row.entry_name.empty()) {
        qstring fallback_name;
        if (get_name(&fallback_name, inf_get_start_ea()) > 0) {
            row.entry_name = fallback_name.c_str();
        }
    }

    row.funcs_count = static_cast<int>(get_func_qty());
    row.segments_count = static_cast<int>(get_segm_qty());
    row.names_count = static_cast<int>(get_nlist_size());

    std::ostringstream summary;
    summary << row.processor << " " << (row.is_64bit ? "64-bit" : "32-bit");
    if (!row.entry_name.empty()) {
        summary << " | entry: " << row.entry_name << " @ " << row.start_ea;
    } else {
        summary << " | start: " << row.start_ea;
    }
    summary << " | funcs: " << row.funcs_count;
    summary << " | segs: " << row.segments_count;
    row.summary = summary.str();

    rows.push_back(std::move(row));
}

} // namespace

CachedTableDef<WelcomeRow> define_welcome() {
    return cached_table<WelcomeRow>("welcome")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 1; })
        .cache_builder([](std::vector<WelcomeRow>& rows) {
            collect_welcome(rows);
        })
        .column_text("summary", [](const WelcomeRow& row) -> std::string { return row.summary; })
        .column_text("processor", [](const WelcomeRow& row) -> std::string { return row.processor; })
        .column_int("is_64bit", [](const WelcomeRow& row) -> int { return row.is_64bit; })
        .column_text("min_ea", [](const WelcomeRow& row) -> std::string { return row.min_ea; })
        .column_text("max_ea", [](const WelcomeRow& row) -> std::string { return row.max_ea; })
        .column_text("start_ea", [](const WelcomeRow& row) -> std::string { return row.start_ea; })
        .column_text("entry_name", [](const WelcomeRow& row) -> std::string { return row.entry_name; })
        .column_int("funcs_count", [](const WelcomeRow& row) -> int { return row.funcs_count; })
        .column_int("segments_count", [](const WelcomeRow& row) -> int { return row.segments_count; })
        .column_int("names_count", [](const WelcomeRow& row) -> int { return row.names_count; })
        .build();
}

} // namespace metadata
} // namespace idasql
