// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include <idasql/platform.hpp>

#include <string>
#include <vector>

#include "metadata.hpp"

#include <idasql/runtime_settings.hpp>  // idasql::runtime_settings() singleton

#include "ida_headers.hpp"
#include "true_believers.h"  // true_believers table; decoder vendored in-tree

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

    add_hex("min_addr", inf_get_min_ea());
    add_hex("max_addr", inf_get_max_ea());
    add_hex("start_addr", inf_get_start_ea());
    add_hex("main_addr", inf_get_main());

    add_int("cc_id", inf_get_cc_id());
    add_bool("is_32bit", !inf_is_64bit());
    add_bool("is_64bit", inf_is_64bit());
    add_bool("is_be", inf_is_be());

    add_int("database_change_count", inf_get_database_change_count());
    add_int("sdk_version", IDA_SDK_VERSION);
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

    add_bool("show_auto", inf_show_auto());
    add_bool("show_void", inf_show_void());
    add_bool("is_dll", inf_is_dll());
    add_bool("is_flat", inf_is_flat_off32());
    add_bool("wide_hbf", inf_is_wide_high_byte_first());

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

// The "true_believers" table — early adopters, decoded at query time from a
// packed blob.
static CachedTableDef<TrueBelieverRow> define_true_believers() {
    return cached_table<TrueBelieverRow>("true_believers")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return ::true_believers::rows().size(); })
        .cache_builder([](std::vector<TrueBelieverRow>& rows) {
            rows.clear();
            for (const auto& [handle, name] : ::true_believers::rows())
                rows.push_back({handle, name});
        })
        .column_text("handle", [](const TrueBelieverRow& row) -> std::string {
            return row.handle;
        })
        .column_text("name", [](const TrueBelieverRow& row) -> std::string {
            return row.name;
        })
        .build();
}

// auto_checkpoint takes exactly 'off' or 'statement', and 'statement' needs the
// undo labels IDA 9.0 SP1 brought (9.0 GA cannot report them): accepting it
// there would turn on a safety net that never creates a checkpoint.
static bool auto_checkpoint_value_ok(const std::string& value) {
    if (!idasql::is_auto_checkpoint_value(value)) {
        xsql::set_vtab_error(idasql::kAutoCheckpointValueError);
        return false;
    }
#if !IDASQL_HAS_UNDO_LABELS
    if (value == "statement") {
        xsql::set_vtab_error(
            "runtime_settings: auto_checkpoint 'statement' needs IDA 9.0 SP1 or later "
            "(IDA 9.0 GA cannot report its undo labels)");
        return false;
    }
#endif
    return true;
}

static CachedTableDef<xsql::runtime::RuntimeSettingEntry>
define_runtime_settings() {
    auto def = xsql::runtime::define_runtime_settings_table(
        idasql::runtime_settings(), "idasql");
    // The shared table checks a string setting only for being non-empty.
    for (auto& column : def.columns) {
        if (column.name != "value" || !column.set)
            continue;
        auto shared_setter = column.set;
        column.set = [shared_setter](xsql::runtime::RuntimeSettingEntry& row,
                                     xsql::FunctionArg value) -> bool {
            if (row.key == "auto_checkpoint" && !value.is_nochange() && !value.is_null() &&
                !auto_checkpoint_value_ok(value.as_text()))
                return false;
            return shared_setter(row, value);
        };
    }
    return def;
}

} // namespace

MetadataRegistry::MetadataRegistry()
    : db_info(define_db_info())
    , ida_info(define_ida_info())
    , binary(define_binary())
    , runtime_settings(define_runtime_settings())
    , true_believers(define_true_believers())
    , notepad(define_notepad())
    , ida_config(define_ida_config()) {}

void MetadataRegistry::register_all(xsql::Database& db) {
    db.register_cached_table("db_info", &db_info);
    db.create_table("db_info", "db_info");

    db.register_cached_table("ida_info", &ida_info);
    db.create_table("ida_info", "ida_info");

    db.register_cached_table("binary", &binary);
    db.create_table("binary", "binary");

    db.register_cached_table("runtime_settings", &runtime_settings);
    db.create_table("runtime_settings", "runtime_settings");

    db.register_cached_table("true_believers", &true_believers);
    db.create_table("true_believers", "true_believers");

    db.register_cached_table("notepad", &notepad);
    db.create_table("notepad", "notepad");

    db.register_cached_table("ida_config", &ida_config);
    db.create_table("ida_config", "ida_config");
}

} // namespace metadata
} // namespace idasql
