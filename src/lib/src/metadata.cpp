// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <idasql/platform.hpp>

#include <string>
#include <vector>

#include "metadata.hpp"

#include "ida_headers.hpp"

namespace idasql {
namespace metadata {
namespace {

static void collect_db_info(std::vector<MetadataItem>& rows) {
    rows.clear();

    auto add_str = [&](const char* k, const std::string& v) {
        rows.push_back({k, v, "string"});
    };
    auto add_int = [&](const char* k, int64_t v) {
        rows.push_back({k, std::to_string(v), "int"});
    };
    auto add_hex = [&](const char* k, uint64_t v) {
        char buf[32];
        qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
        rows.push_back({k, buf, "hex"});
    };
    auto add_bool = [&](const char* k, bool v) {
        rows.push_back({k, v ? "true" : "false", "bool"});
    };

    add_str("processor", inf_get_procname().c_str());
    add_int("filetype", inf_get_filetype());
    add_int("ostype", inf_get_ostype());
    add_int("apptype", inf_get_apptype());

    add_hex("min_ea", inf_get_min_ea());
    add_hex("max_ea", inf_get_max_ea());
    add_hex("start_ea", inf_get_start_ea());
    add_hex("main_ea", inf_get_main());

    add_int("cc_id", inf_get_cc_id());
    add_bool("is_32bit", !inf_is_64bit());
    add_bool("is_64bit", inf_is_64bit());
    add_bool("is_be", inf_is_be());

    add_int("database_change_count", inf_get_database_change_count());
    add_int("version", IDA_SDK_VERSION);
}

static CachedTableDef<MetadataItem> define_db_info() {
    return cached_table<MetadataItem>("db_info")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 16; })
        .cache_builder([](std::vector<MetadataItem>& rows) {
            collect_db_info(rows);
        })
        .column_text("key", [](const MetadataItem& row) -> std::string {
            return row.key;
        })
        .column_text("value", [](const MetadataItem& row) -> std::string {
            return row.value;
        })
        .column_text("type", [](const MetadataItem& row) -> std::string {
            return row.type;
        })
        .build();
}

static void collect_ida_info(std::vector<MetadataItem>& rows) {
    rows.clear();

    auto add_bool = [&](const char* k, bool v) {
        rows.push_back({k, v ? "1" : "0", "bool"});
    };
    auto add_int = [&](const char* k, int64_t v) {
        rows.push_back({k, std::to_string(v), "int"});
    };

    add_bool("show_auto", inf_should_create_stkvars());
    add_bool("show_void", inf_is_graph_view());
    add_bool("is_dll", inf_is_dll());
    add_bool("is_flat", inf_is_flat_off32());
    add_bool("wide_fids", inf_is_wide_high_byte_first());

    add_int("long_demnames", inf_get_long_demnames());
    add_int("short_demnames", inf_get_short_demnames());
    add_int("demnames", inf_get_demnames());

    add_int("max_autoname_len", inf_get_max_autoname_len());
}

static CachedTableDef<MetadataItem> define_ida_info() {
    return cached_table<MetadataItem>("ida_info")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 16; })
        .cache_builder([](std::vector<MetadataItem>& rows) {
            collect_ida_info(rows);
        })
        .column_text("key", [](const MetadataItem& row) -> std::string {
            return row.key;
        })
        .column_text("value", [](const MetadataItem& row) -> std::string {
            return row.value;
        })
        .column_text("type", [](const MetadataItem& row) -> std::string {
            return row.type;
        })
        .build();
}

} // namespace

MetadataRegistry::MetadataRegistry()
    : db_info(define_db_info())
    , ida_info(define_ida_info())
    , welcome(define_welcome()) {}

void MetadataRegistry::register_all(xsql::Database& db) {
    db.register_cached_table("ida_db_info", &db_info);
    db.create_table("db_info", "ida_db_info");

    db.register_cached_table("ida_ida_info", &ida_info);
    db.create_table("ida_info", "ida_ida_info");

    db.register_cached_table("ida_welcome", &welcome);
    db.create_table("welcome", "ida_welcome");
}

} // namespace metadata
} // namespace idasql
