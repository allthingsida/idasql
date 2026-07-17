// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "metadata_runtime_settings.hpp"

#include <string>
#include <vector>

#include <idasql/runtime_settings.hpp>

namespace idasql {
namespace metadata {

static void collect_runtime_settings(std::vector<RuntimeSettingRow>& rows) {
    rows.clear();
    auto& rs = idasql::runtime_settings();
    // Shared common keys (live values) from the libxsql core.
    for (const auto& e : rs.common_settings().enumerate_common()) {
        rows.push_back({e.key, e.value, e.type, e.scope});
    }
    // idasql-only keys.
    rows.push_back({"enable_idapython",
                    rs.enable_idapython() ? "1" : "0", "bool", "idasql"});
    rows.push_back({"idapython_output_max",
                    std::to_string(rs.idapython_output_max()), "int", "idasql"});
}

CachedTableDef<RuntimeSettingRow> define_runtime_settings() {
    return cached_table<RuntimeSettingRow>("runtime_settings")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 10; })
        .cache_builder([](std::vector<RuntimeSettingRow>& rows) {
            collect_runtime_settings(rows);
        })
        .column_text("key", [](const RuntimeSettingRow& row) -> std::string {
            return row.key;
        })
        .column_text("value", [](const RuntimeSettingRow& row) -> std::string {
            return row.value;
        })
        .column_text("type", [](const RuntimeSettingRow& row) -> std::string {
            return row.type;
        })
        .column_text("scope", [](const RuntimeSettingRow& row) -> std::string {
            return row.scope;
        })
        .build();
}

} // namespace metadata
} // namespace idasql
