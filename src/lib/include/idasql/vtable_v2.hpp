/**
 * vtable_v2.hpp - IDA-specific virtual table helpers
 *
 * This file provides IDA-specific integration with the xsql virtual table
 * framework, primarily for undo point management.
 *
 * Usage:
 *   auto def = idasql::live_table("funcs_live")  // Auto-registers IDA undo hook
 *       .count(...)
 *       .column_text_rw("name", getter, setter)
 *       .build();
 *
 * Or manually:
 *   auto def = idasql::table("funcs_live")
 *       .on_modify(idasql::ida_undo_hook)
 *       ...
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
 * Pass this to VTableBuilder::on_modify() to automatically create
 * undo points before any UPDATE or DELETE operation.
 */
inline void ida_undo_hook(const std::string& operation_desc) {
    std::string undo_desc = "IDASQL " + operation_desc;
    create_undo_point(reinterpret_cast<const uchar*>(undo_desc.c_str()), undo_desc.size());
}

/**
 * Helper to create a table with IDA undo integration.
 * Equivalent to table(name).on_modify(ida_undo_hook)
 */
inline VTableBuilder live_table(const char* name) {
    return table(name).on_modify(ida_undo_hook);
}

} // namespace idasql
