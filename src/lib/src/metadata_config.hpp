// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <optional>
#include <string>

#include <idasql/vtable.hpp>

namespace idasql {
namespace metadata {

struct ConfigRow {
    std::string key;
    std::string file;
    std::optional<std::string> value;
    std::string value_source;
    int writable = 0;
    int persisted = 0;
    std::optional<std::string> message;

    std::optional<std::string> file_value;
    int inf_index = -1;
    bool is_bool = false;
    bool is_string = false;
    bool is_list = false;
    bool hex = false;
};

CachedTableDef<ConfigRow> define_ida_config();

}
}
