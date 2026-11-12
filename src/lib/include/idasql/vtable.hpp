// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <xsql/xsql.hpp>

namespace idasql {

using xsql::ColumnType;
using xsql::column_type_sql;

using xsql::ColumnDef;

using xsql::VTableDef;

using xsql::Vtab;
using xsql::Cursor;

using xsql::register_vtable;
using xsql::create_vtable;

using xsql::VTableBuilder;
using xsql::table;

using xsql::RowIterator;
using xsql::FilterDef;
using xsql::FILTER_NONE;

template<typename RowData>
using CachedColumnDef = xsql::CachedColumnDef<RowData>;

template<typename RowData>
using CachedTableDef = xsql::CachedTableDef<RowData>;

template<typename RowData>
using CachedCursor = xsql::CachedCursor<RowData>;

using xsql::register_cached_vtable;

template<typename RowData>
using CachedTableBuilder = xsql::CachedTableBuilder<RowData>;

template<typename RowData>
inline CachedTableBuilder<RowData> cached_table(const char* name) {
    return xsql::cached_table<RowData>(name);
}

template<typename RowData>
using Generator = xsql::Generator<RowData>;

template<typename RowData>
using GeneratorTableDef = xsql::GeneratorTableDef<RowData>;

template<typename RowData>
using GeneratorCursor = xsql::GeneratorCursor<RowData>;

using xsql::register_generator_vtable;

template<typename RowData>
using GeneratorTableBuilder = xsql::GeneratorTableBuilder<RowData>;

template<typename RowData>
inline GeneratorTableBuilder<RowData> generator_table(const char* name) {
    return xsql::generator_table<RowData>(name);
}

}

#define COLUMN_INT64(name, getter) \
    .column_int64(#name, getter)

#define COLUMN_INT(name, getter) \
    .column_int(#name, getter)

#define COLUMN_TEXT(name, getter) \
    .column_text(#name, getter)

#define COLUMN_DOUBLE(name, getter) \
    .column_double(#name, getter)
