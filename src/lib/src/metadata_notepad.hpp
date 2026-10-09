// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <cstdint>
#include <string>

#include <idasql/vtable.hpp>

namespace idasql {
namespace metadata {

struct NotepadRow {
    std::string text;  // line ends shown as \n
    int64_t size = 0;  // bytes as stored (CRLF line ends), without the NUL
};

// notepad — the database notepad ("Database notepad" window): one row,
// UPDATE text writes it, DELETE clears it (nalt.hpp get/set_ida_notepad_text).
CachedTableDef<NotepadRow> define_notepad();

} // namespace metadata
} // namespace idasql
