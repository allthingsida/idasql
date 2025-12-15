/**
 * vtable.hpp - SQLite Virtual Table framework for IDA
 *
 * This file re-exports the xsql virtual table framework types into the idasql
 * namespace for convenience.
 *
 * Two table patterns are available:
 *
 * 1. Index-based tables (for IDA's indexed access like getn_func):
 *
 *   auto funcs_table = idasql::table("funcs")
 *       .count([]() { return get_func_qty(); })
 *       .column_int64("address", [](size_t i) { return getn_func(i)->start_ea; })
 *       .build();
 *
 * 2. Cached tables (for enumeration-based data, cache freed after query):
 *
 *   auto xrefs_table = idasql::cached_table<XrefInfo>("xrefs")
 *       .estimate_rows([]() { return get_func_qty() * 10; })
 *       .cache_builder([](auto& cache) { /* populate */ })
 *       .column_int64("from_ea", [](const XrefInfo& r) { return r.from_ea; })
 *       .build();
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

// Column definition (index-based)
using xsql::ColumnDef;

// Virtual table definition (index-based)
using xsql::VTableDef;

// SQLite virtual table implementation
using xsql::Vtab;
using xsql::Cursor;

// Registration helpers
using xsql::register_vtable;
using xsql::create_vtable;

// Index-based table builder
using xsql::VTableBuilder;
using xsql::table;

// ============================================================================
// Cached Table API (query-scoped cache, freed after query)
// ============================================================================

// Row iterator for constraint pushdown
using xsql::RowIterator;
using xsql::FilterDef;
using xsql::FILTER_NONE;

// Cached column definition (row-typed)
template<typename RowData>
using CachedColumnDef = xsql::CachedColumnDef<RowData>;

// Cached table definition
template<typename RowData>
using CachedTableDef = xsql::CachedTableDef<RowData>;

// Cached cursor (owns cache)
template<typename RowData>
using CachedCursor = xsql::CachedCursor<RowData>;

// Cached table registration
template<typename RowData>
inline bool register_cached_vtable(sqlite3* db, const char* module_name,
                                   const CachedTableDef<RowData>* def) {
    return xsql::register_cached_vtable(db, module_name, def);
}

// Cached table builder
template<typename RowData>
using CachedTableBuilder = xsql::CachedTableBuilder<RowData>;

template<typename RowData>
inline CachedTableBuilder<RowData> cached_table(const char* name) {
    return xsql::cached_table<RowData>(name);
}

} // namespace idasql

// ============================================================================
// Convenience Macros (namespace-qualified for idasql)
// ============================================================================

#define COLUMN_INT64(name, getter) \
    .column_int64(#name, getter)

#define COLUMN_INT(name, getter) \
    .column_int(#name, getter)

#define COLUMN_TEXT(name, getter) \
    .column_text(#name, getter)

#define COLUMN_DOUBLE(name, getter) \
    .column_double(#name, getter)
