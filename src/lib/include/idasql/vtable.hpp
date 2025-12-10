/**
 * vtable.hpp - SQLite Virtual Table framework for IDA
 *
 * This file re-exports the xsql virtual table framework types into the idasql
 * namespace for backwards compatibility and convenience.
 *
 * Features:
 *   - Declarative column definitions using lambdas
 *   - Lazy iteration (index-based, no pre-collection)
 *   - Type-safe column accessors
 *   - Minimal boilerplate for new tables
 *
 * Example usage:
 *
 *   auto funcs_table = idasql::table("funcs")
 *       .count([]() { return get_func_qty(); })
 *       .column_int64("address", [](size_t i) {
 *           return getn_func(i)->start_ea;
 *       })
 *       .column_text("name", [](size_t i) {
 *           qstring n; get_func_name(&n, getn_func(i)->start_ea);
 *           return std::string(n.c_str());
 *       })
 *       .build();
 *
 *   idasql::register_vtable(db, "ida_funcs", &funcs_table);
 *   idasql::create_vtable(db, "funcs", "ida_funcs");
 */

#pragma once

#include <xsql/xsql.hpp>

namespace idasql {

// ============================================================================
// Re-export xsql types into idasql namespace
// ============================================================================

// Column types
using xsql::ColumnType;
using xsql::column_type_sql;

// Column definition
using xsql::ColumnDef;

// Column factory helpers
using xsql::make_column_int64;
using xsql::make_column_int;
using xsql::make_column_text;
using xsql::make_column_double;

// Virtual table definition
using xsql::VTableDef;

// SQLite virtual table implementation
using xsql::GenericVtab;
using xsql::GenericCursor;

// Registration helpers
using xsql::register_vtable;
using xsql::create_vtable;

// Table builder (fluent API)
using xsql::VTableBuilder;
using xsql::table;

} // namespace idasql

// ============================================================================
// Convenience Macros (namespace-qualified for idasql)
// ============================================================================

#define COLUMN_INT64(name, getter) \
    idasql::make_column_int64(#name, getter)

#define COLUMN_INT(name, getter) \
    idasql::make_column_int(#name, getter)

#define COLUMN_TEXT(name, getter) \
    idasql::make_column_text(#name, getter)

#define COLUMN_DOUBLE(name, getter) \
    idasql::make_column_double(#name, getter)
