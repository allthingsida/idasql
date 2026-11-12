// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <cstdint>
#include <string>

#include <xsql/database.hpp>
#include <xsql/json.hpp>

namespace idasql {
namespace ui_context {

bool initialize_capture_helper(std::string* error = nullptr);
void shutdown_capture_helper();

xsql::json get_ui_context_json();

bool register_ui_context_sql_functions(xsql::Database& db);

}
}
