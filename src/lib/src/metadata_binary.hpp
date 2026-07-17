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

// One metadata fact: the shared row shape of the key/value/type metadata
// tables (binary, db_info, ida_info).
struct MetadataItem {
    std::string key;
    std::string value;
    std::string type;  // "string", "int", "hex", "bool"
};

// binary — orientation/metadata table, canonical key/value/type shape
// (one row per fact; family-canonical across idasql/bnsql/ghidrasql/r2sql).
CachedTableDef<MetadataItem> define_binary();

} // namespace metadata
} // namespace idasql
