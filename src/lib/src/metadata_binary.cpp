// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// binary — orientation/metadata table, canonical key/value/type shape
// (one row per fact). Columns: (key TEXT, value TEXT, type TEXT) with
// type in {string, hex, bool, int}. Canonical core keys shared with
// bnsql/ghidrasql/r2sql: tool_name, tool_version, processor, filetype,
// image_base, entry_point, min_addr, max_addr, is_64bit, bits, endianness,
// filename, summary, md5, sha256. idasql extras: idasql_version, entry_name,
// funcs_count, segments_count, names_count, strings_count, input_file_path,
// idb_path. (The old wide column start_addr became the canonical key
// entry_point; db_info still carries a start_addr key.)

#include <idasql/platform.hpp>

#include <sstream>
#include <string>
#include <vector>

#include "metadata_binary.hpp"

#include "idasql_version.hpp"
#include "ida_headers.hpp"
#include <idasql/string_utils.hpp>

namespace idasql {
namespace metadata {
namespace {

using idasql::format_ea_hex;
using idasql::to_hex;

static std::string get_primary_entry_name() {
    if (get_entry_qty() <= 0) {
        return "";
    }
    qstring name;
    const uval_t ord = get_entry_ordinal(0);
    get_entry_name(&name, ord);
    return std::string(name.c_str());
}

static void collect_binary(std::vector<MetadataItem>& rows) {
    rows.clear();

    auto add_str = [&](const char* k, const std::string& v) {
        rows.push_back({k, v, "string"});
    };
    auto add_int = [&](const char* k, int64_t v) {
        rows.push_back({k, std::to_string(v), "int"});
    };
    auto add_hex = [&](const char* k, uint64_t v) {
        rows.push_back({k, format_ea_hex(v), "hex"});
    };
    auto add_bool = [&](const char* k, bool v) {
        rows.push_back({k, v ? "true" : "false", "bool"});
    };

    const std::string processor = inf_get_procname().c_str();
    const bool is_64bit = inf_is_64bit();
    const std::string entry_point_hex =
        format_ea_hex(static_cast<uint64_t>(inf_get_start_ea()));

    std::string entry_name = get_primary_entry_name();
    if (entry_name.empty()) {
        qstring fallback_name;
        if (get_name(&fallback_name, inf_get_start_ea()) > 0) {
            entry_name = fallback_name.c_str();
        }
    }

    const int funcs_count = static_cast<int>(get_func_qty());
    const int segments_count = static_cast<int>(get_segm_qty());
    const int strings_count = static_cast<int>(get_strlist_qty());

    // summary first: agents doing `SELECT * FROM binary` see the digest up top.
    {
        std::ostringstream summary;
        summary << processor << " " << (is_64bit ? "64-bit" : "32-bit");
        if (!entry_name.empty()) {
            summary << " | entry: " << entry_name << " @ " << entry_point_hex;
        } else {
            summary << " | entry: " << entry_point_hex;
        }
        summary << " | funcs: " << funcs_count;
        summary << " | segs: " << segments_count;
        summary << " | strings: " << strings_count;
        add_str("summary", summary.str());
    }

    // Tool identity.
    add_str("tool_name", "idasql");
    add_str("tool_version", IDASQL_VERSION_STRING);
    add_str("idasql_version", IDASQL_VERSION_STRING);  // legacy-named extra

    // Canonical core keys.
    add_str("processor", processor);
    {
        char ftype[MAXSTR];
        add_str("filetype", get_file_type_name(ftype, sizeof(ftype)) > 0 ? ftype : "");
    }
    add_hex("image_base", static_cast<uint64_t>(get_imagebase()));
    rows.push_back({"entry_point", entry_point_hex, "hex"});
    add_hex("min_addr", static_cast<uint64_t>(inf_get_min_ea()));
    add_hex("max_addr", static_cast<uint64_t>(inf_get_max_ea()));
    add_bool("is_64bit", is_64bit);
    add_int("bits", inf_get_app_bitness());
    add_str("endianness", inf_is_be() ? "big" : "little");

    // File identity. Every API is bounded by the buffer size we pass and
    // guarded by its return code, falling back to an empty string when absent.
    {
        char fname[QMAXPATH];
        add_str("filename", (get_root_filename(fname, sizeof(fname)) > 0) ? fname : "");
    }

    // idasql extras.
    add_str("entry_name", entry_name);
    add_int("funcs_count", funcs_count);
    add_int("segments_count", segments_count);
    add_int("names_count", static_cast<int>(get_nlist_size()));
    add_int("strings_count", strings_count);
    {
        char fpath[QMAXPATH];
        add_str("input_file_path",
                (get_input_file_path(fpath, sizeof(fpath)) > 0) ? fpath : "");
    }
    {
        // Full path of the IDB/I64 on disk (may differ from input_file_path if moved).
        const char* idb = get_path(PATH_TYPE_IDB);
        add_str("idb_path", (idb != nullptr) ? idb : "");
    }

    // Best-effort core hashes (kept even when empty: the row's presence is the
    // idasql contract; value is "" when the input file hash is unavailable).
    {
        uchar md5[16];
        add_str("md5", retrieve_input_file_md5(md5) ? to_hex(md5, sizeof(md5)) : "");
    }
    {
        uchar sha256[32];
        add_str("sha256",
                retrieve_input_file_sha256(sha256) ? to_hex(sha256, sizeof(sha256)) : "");
    }
}

} // namespace

CachedTableDef<MetadataItem> define_binary() {
    return cached_table<MetadataItem>("binary")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 23; })
        .cache_builder([](std::vector<MetadataItem>& rows) {
            collect_binary(rows);
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

} // namespace metadata
} // namespace idasql
