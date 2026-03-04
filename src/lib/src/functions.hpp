// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

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
