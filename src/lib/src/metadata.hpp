// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

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
