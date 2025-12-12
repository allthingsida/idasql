/**
 * vtable_v2.hpp - IDA-specific writable virtual table helpers
 *
 * This file provides IDA-specific integration with the xsql writable vtable
 * framework, primarily for undo point management.
 *
 * Usage:
 *   auto def = idasql::writable_table("funcs_live")
 *       .on_modify(idasql::ida_undo_hook)  // Auto-create IDA undo points
 *       .count(...)
 *       .column_text_rw("name", getter, setter)
 *       .build();
 */

#pragma once

#include <idasql/vtable.hpp>

// IDA SDK for undo
#include <ida.hpp>
#include <undo.hpp>

namespace idasql {

// ============================================================================
// IDA Undo Integration
// ============================================================================

/**
 * Hook function for IDA undo point creation.
 * Pass this to WritableVTableBuilder::on_modify() to automatically create
 * undo points before any UPDATE or DELETE operation.
 *
 * Usage:
 *   auto def = idasql::writable_table("funcs_live")
 *       .on_modify(idasql::ida_undo_hook)
 *       ...
 */
inline void ida_undo_hook(const std::string& operation_desc) {
    std::string undo_desc = "IDASQL " + operation_desc;
    create_undo_point(reinterpret_cast<const uchar*>(undo_desc.c_str()), undo_desc.size());
}

/**
 * Helper to create a writable table with IDA undo integration.
 * Equivalent to writable_table(name).on_modify(ida_undo_hook)
 */
inline WritableVTableBuilder live_table(const char* name) {
    return writable_table(name).on_modify(ida_undo_hook);
}

// ============================================================================
// Backwards Compatibility (v2 namespace)
// ============================================================================

namespace v2 {

// Re-export types for backwards compatibility
using idasql::WritableColumnDef;
using LiveColumnDef = WritableColumnDef;

using idasql::WritableVTableDef;
using LiveVTableDef = WritableVTableDef;

using idasql::WritableVtab;
using LiveVtab = WritableVtab;

using idasql::WritableCursor;
using LiveCursor = WritableCursor;

using idasql::register_writable_vtable;
inline bool register_live_vtable(sqlite3* db, const char* module_name, const WritableVTableDef* def) {
    return register_writable_vtable(db, module_name, def);
}

using idasql::create_writable_vtable;
inline bool create_live_vtable(sqlite3* db, const char* table_name, const char* module_name) {
    return create_writable_vtable(db, table_name, module_name);
}

using idasql::WritableVTableBuilder;
using LiveVTableBuilder = WritableVTableBuilder;

// live_table in v2 namespace - same as idasql::live_table
using idasql::live_table;

} // namespace v2
} // namespace idasql
