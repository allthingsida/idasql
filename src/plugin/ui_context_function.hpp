// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <xsql/database.hpp>

namespace idasql {
namespace plugin_functions {

bool register_ui_context_sql_functions(xsql::Database& db);

} // namespace plugin_functions
} // namespace idasql
