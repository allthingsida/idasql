// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * idasql.hpp - Main include header for IDASQL library
 *
 * Usage:
 *   #include <idasql/idasql.hpp>
 *
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
