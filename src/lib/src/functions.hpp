// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * functions.hpp - Custom SQL functions for IDA operations
 */

#pragma once

#include <xsql/database.hpp>

namespace idasql {
namespace functions {

void register_sql_functions(xsql::Database& db);

} // namespace functions
} // namespace idasql
