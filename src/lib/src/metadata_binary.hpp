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

struct MetadataItem {
    std::string key;
    std::string value;
    std::string type;
};

CachedTableDef<MetadataItem> define_binary();

}
}
