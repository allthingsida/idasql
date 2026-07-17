// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * idasql.hpp - Main include header for IDASQL library
 *
 * Usage:
 *   #include <idasql/idasql.hpp>
 *
 *   init_library();
 *   idasql::Session session;
 *   session.open("database.i64");
 *   auto result = session.query("SELECT * FROM funcs LIMIT 10");
 *   session.close();
 */

#pragma once

// Core virtual table framework
#include <idasql/vtable.hpp>

// Database wrapper class (includes fwd.hpp for registry types)
#include <idasql/database.hpp>
