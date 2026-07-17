// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <string>

#include <idasql/vtable.hpp>

namespace idasql {
namespace metadata {

// One runtime setting row for the read-only `runtime_settings` discovery table.
// key/value/type mirrors the family-canonical metadata shape; `scope`
// distinguishes shared keys ("common"), dispatch-only PRAGMA verbs ("action"),
// and tool-specific keys ("idasql").
struct RuntimeSettingRow {
    std::string key;
    std::string value;
    std::string type;   // "int" | "bool"
    std::string scope;  // "common" | "action" | "idasql"
};

// runtime_settings — read-only live view over the PRAGMA idasql.* surface. The
// 8 shared keys come from the libxsql core (RuntimeSettingsCore::enumerate_common),
// plus the two idasql-only keys (enable_idapython, idapython_output_max).
CachedTableDef<RuntimeSettingRow> define_runtime_settings();

} // namespace metadata
} // namespace idasql
