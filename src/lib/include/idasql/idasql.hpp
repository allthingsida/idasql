/**
 * idasql.hpp - Main include header for IDASQL library
 *
 * This is the convenience header that includes all IDASQL components.
 *
 * Usage:
 *   #include <idasql/idasql.hpp>
 *
 *   idasql::Database db;
 *   db.open("database.i64");
 *   db.exec("SELECT * FROM funcs", callback, nullptr);
 *   db.close();
 */

#pragma once

// Core virtual table framework
#include <idasql/vtable.hpp>

// Entity tables
#include <idasql/entities.hpp>
#include <idasql/entities_live.hpp>
#include <idasql/entities_ext.hpp>
#include <idasql/entities_types.hpp>

// Decompiler tables (requires Hex-Rays)
#include <idasql/decompiler.hpp>

// Metadata tables
#include <idasql/metadata.hpp>

// SQL functions
#include <idasql/functions.hpp>

// Database wrapper class
#include <idasql/database.hpp>
