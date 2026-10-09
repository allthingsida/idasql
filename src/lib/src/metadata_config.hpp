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
    // Columns
    std::string key;
    std::string file;
    std::optional<std::string> value;
    std::string value_source;  // runtime | inf | session | file
    int writable = 0;
    int persisted = 0;
    std::optional<std::string> message;

    // How the key is read and written (not columns)
    std::optional<std::string> file_value;  // the value the files set, if any
    int inf_index = -1;     // entry in the inf-backed key map, or -1
    bool is_bool = false;   // YES/NO
    bool is_string = false; // a quoted string
    bool is_list = false;   // its statement ends with ';'
    bool hex = false;       // numbers shown in hex, as the file writes them
};

// ida_config — IDA's configuration keys, listed from the shipped option files
// (ida.cfg, hexrays.cfg, idagui.cfg in IDADIR/cfg then IDAUSR/cfg). UPDATE of
// value applies a `KEY=VALUE` directive (idacfg.hpp process_config_directive)
// and reads it back.
CachedTableDef<ConfigRow> define_ida_config();

} // namespace metadata
} // namespace idasql
