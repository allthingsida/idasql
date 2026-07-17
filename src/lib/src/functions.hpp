// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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
