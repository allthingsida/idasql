// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
