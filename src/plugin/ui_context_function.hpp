// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

#pragma once

#include <xsql/database.hpp>

namespace idasql {
namespace plugin_functions {

bool register_ui_context_sql_functions(xsql::Database& db);

} // namespace plugin_functions
} // namespace idasql
