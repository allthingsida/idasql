// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_strings.hpp - `strings` table and string-literal helpers.
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace memory {

// String helpers
int get_string_width(int strtype);
const char *get_string_width_name(int strtype);
const char *get_string_type_name(int strtype);
int get_string_layout(int strtype);
const char *get_string_layout_name(int strtype);
int get_string_encoding(int strtype);
std::string get_string_content(const string_info_t &si);

CachedTableDef<string_info_t> define_strings();

} // namespace memory
} // namespace idasql
