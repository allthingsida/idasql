// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * metadata.hpp - IDA database metadata as virtual tables
 *
 * Tables: db_info, ida_info, welcome
 */

#pragma once

#include "metadata_welcome.hpp"
#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include <string>

namespace idasql {
namespace metadata {

struct MetadataItem {
    std::string key;
    std::string value;
    std::string type;  // "string", "int", "hex", "bool"
};

struct MetadataRegistry {
    CachedTableDef<MetadataItem> db_info;
    CachedTableDef<MetadataItem> ida_info;
    CachedTableDef<WelcomeRow> welcome;

    MetadataRegistry();
    void register_all(xsql::Database& db);
};

} // namespace metadata
} // namespace idasql
