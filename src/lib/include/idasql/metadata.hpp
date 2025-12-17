/**
 * ida_metadata.hpp - IDA database metadata as virtual tables
 *
 * These tables provide metadata about the database itself, not entities within it.
 * Many of these work even without a fully loaded database.
 *
 * Tables:
 *   db_info     - Database information (processor, file type, etc.)
 *   ida_info    - IDA analysis settings and flags
 */

#pragma once

#include <idasql/vtable.hpp>

// IDA SDK headers
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>

namespace idasql {
namespace metadata {

// ============================================================================
// Helper: Key-Value pair for metadata tables
// ============================================================================

struct MetadataItem {
    std::string key;
    std::string value;
    std::string type;  // "string", "int", "hex", "bool"
};

// ============================================================================
// DB_INFO Table - Database information
// ============================================================================

inline std::vector<MetadataItem>& get_db_info_cache() {
    static std::vector<MetadataItem> cache;
    return cache;
}

inline void rebuild_db_info_cache() {
    auto& cache = get_db_info_cache();
    cache.clear();

    auto add_str = [&](const char* k, const std::string& v) {
        cache.push_back({k, v, "string"});
    };
    auto add_int = [&](const char* k, int64_t v) {
        cache.push_back({k, std::to_string(v), "int"});
    };
    auto add_hex = [&](const char* k, uint64_t v) {
        char buf[32];
        qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
        cache.push_back({k, buf, "hex"});
    };
    auto add_bool = [&](const char* k, bool v) {
        cache.push_back({k, v ? "true" : "false", "bool"});
    };

    // Processor info
    add_str("processor", inf_get_procname().c_str());
    add_int("filetype", inf_get_filetype());
    add_int("ostype", inf_get_ostype());
    add_int("apptype", inf_get_apptype());

    // Address info
    add_hex("min_ea", inf_get_min_ea());
    add_hex("max_ea", inf_get_max_ea());
    add_hex("start_ea", inf_get_start_ea());
    add_hex("main_ea", inf_get_main());

    // Addressing
    add_int("cc_id", inf_get_cc_id());
    add_bool("is_32bit", !inf_is_64bit());
    add_bool("is_64bit", inf_is_64bit());
    add_bool("is_be", inf_is_be());

    // Database info
    add_int("database_change_count", inf_get_database_change_count());
    add_int("version", IDA_SDK_VERSION);
}

inline VTableDef define_db_info() {
    return table("db_info")
        .count([]() {
            rebuild_db_info_cache();
            return get_db_info_cache().size();
        })
        .column_text("key", [](size_t i) -> std::string {
            auto& cache = get_db_info_cache();
            return i < cache.size() ? cache[i].key : "";
        })
        .column_text("value", [](size_t i) -> std::string {
            auto& cache = get_db_info_cache();
            return i < cache.size() ? cache[i].value : "";
        })
        .column_text("type", [](size_t i) -> std::string {
            auto& cache = get_db_info_cache();
            return i < cache.size() ? cache[i].type : "";
        })
        .build();
}

// ============================================================================
// IDA_INFO Table - IDA analysis flags (from inf structure)
// ============================================================================

inline std::vector<MetadataItem>& get_ida_info_cache() {
    static std::vector<MetadataItem> cache;
    return cache;
}

inline void rebuild_ida_info_cache() {
    auto& cache = get_ida_info_cache();
    cache.clear();

    auto add_bool = [&](const char* k, bool v) {
        cache.push_back({k, v ? "1" : "0", "bool"});
    };
    auto add_int = [&](const char* k, int64_t v) {
        cache.push_back({k, std::to_string(v), "int"});
    };

    // Analysis flags
    add_bool("show_auto", inf_should_create_stkvars());  // approximate
    add_bool("show_void", inf_is_graph_view());
    add_bool("is_dll", inf_is_dll());
    add_bool("is_flat", inf_is_flat_off32());
    add_bool("wide_fids", inf_is_wide_high_byte_first());

    // Naming
    add_int("long_demnames", inf_get_long_demnames());
    add_int("short_demnames", inf_get_short_demnames());
    add_int("demnames", inf_get_demnames());

    // Limits
    add_int("max_autoname_len", inf_get_max_autoname_len());
}

inline VTableDef define_ida_info() {
    return table("ida_info")
        .count([]() {
            rebuild_ida_info_cache();
            return get_ida_info_cache().size();
        })
        .column_text("key", [](size_t i) -> std::string {
            auto& cache = get_ida_info_cache();
            return i < cache.size() ? cache[i].key : "";
        })
        .column_text("value", [](size_t i) -> std::string {
            auto& cache = get_ida_info_cache();
            return i < cache.size() ? cache[i].value : "";
        })
        .column_text("type", [](size_t i) -> std::string {
            auto& cache = get_ida_info_cache();
            return i < cache.size() ? cache[i].type : "";
        })
        .build();
}

// ============================================================================
// Metadata Registry
// ============================================================================

struct MetadataRegistry {
    VTableDef db_info;
    VTableDef ida_info;

    MetadataRegistry()
        : db_info(define_db_info())
        , ida_info(define_ida_info())
    {}

    void register_all(sqlite3* db) {
        register_vtable(db, "ida_db_info", &db_info);
        create_vtable(db, "db_info", "ida_db_info");

        register_vtable(db, "ida_ida_info", &ida_info);
        create_vtable(db, "ida_info", "ida_ida_info");
    }
};

} // namespace metadata
} // namespace idasql
