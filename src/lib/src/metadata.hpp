// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "metadata_binary.hpp"
#include "metadata_config.hpp"
#include "metadata_notepad.hpp"
#include <idasql/runtime_settings.hpp>
#include <idasql/vtable.hpp>
#include <xsql/database.hpp>
#include <xsql/runtime_settings_table.hpp>

#include <string>

namespace idasql {
namespace metadata {

struct TrueBelieverRow {
    std::string handle;
    std::string name;
};

struct MetadataRegistry {
    CachedTableDef<MetadataItem> db_info;
    CachedTableDef<MetadataItem> ida_info;
    CachedTableDef<MetadataItem> binary;
    CachedTableDef<xsql::runtime::RuntimeSettingEntry> runtime_settings;
    CachedTableDef<TrueBelieverRow> true_believers;
    CachedTableDef<NotepadRow> notepad;
    CachedTableDef<ConfigRow> ida_config;

    MetadataRegistry();
    void register_all(xsql::Database& db);
};

}
}
