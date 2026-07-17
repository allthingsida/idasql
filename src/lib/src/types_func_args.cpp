// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_func_args.hpp"

namespace idasql {
namespace types {

// ============================================================================
// TYPES_FUNC_ARGS Table - Function prototype arguments
// ============================================================================

// Get pointer depth (int** -> 2, int* -> 1, int -> 0)
int get_ptr_depth(tinfo_t tif) {
    int depth = 0;
    while (tif.is_ptr()) {
        depth++;
        tif = tif.get_pointed_object();
    }
    return depth;
}

// Get base type name (strips pointers/arrays)
std::string get_base_type_name(tinfo_t tif) {
    // Strip pointers
    while (tif.is_ptr()) {
        tif = tif.get_pointed_object();
    }
    // Strip arrays
    while (tif.is_array()) {
        tif = tif.get_array_element();
    }
    qstring name;
    tif.print(&name);
    return name.c_str();
}

// Classify a single tinfo_t (surface or resolved)
void classify_tinfo(const tinfo_t& tif,
                    bool& is_ptr, bool& is_int, bool& is_integral,
                    bool& is_float, bool& is_void, bool& is_struct,
                    bool& is_array, int& ptr_depth, std::string& base_type) {
    is_ptr = tif.is_ptr();
    is_array = tif.is_array();
    is_struct = tif.is_struct() || tif.is_union();
    is_void = tif.is_void();
    is_float = tif.is_float() || tif.is_double() || tif.is_ldouble() ||
               tif.is_floating();

    // For int classification, we need to check the actual type
    // is_int = exactly "int" type
    // is_integral = int-like family
    is_integral = tif.is_integral();  // IDA SDK: int, char, short, long, bool, etc.
    is_int = tif.is_int();            // IDA SDK: exactly int32/int64

    ptr_depth = get_ptr_depth(tif);
    base_type = get_base_type_name(tif);
}

// Check if type is a typedef (type reference) at surface level
bool is_surface_typedef(const tinfo_t& tif) {
    return tif.is_typeref();
}

// Classify surface-level type (WITHOUT typedef resolution)
// If tif is a typedef, surface classification shows it as "other" not the underlying type
void classify_surface(const tinfo_t& tif,
                      bool& is_ptr, bool& is_int, bool& is_integral,
                      bool& is_float, bool& is_void, bool& is_struct,
                      bool& is_array, int& ptr_depth, std::string& base_type) {
    // If it's a typedef, surface level is NOT a ptr/int/etc - it's a typedef
    if (is_surface_typedef(tif)) {
        is_ptr = false;
        is_int = false;
        is_integral = false;
        is_float = false;
        is_void = false;
        is_struct = false;
        is_array = false;
        ptr_depth = 0;
        // Get the typedef name as base_type
        qstring name;
        if (tif.get_type_name(&name)) {
            base_type = name.c_str();
        } else {
            tif.print(&name);
            base_type = name.c_str();
        }
        return;
    }

    // Not a typedef - classify directly
    classify_tinfo(tif, is_ptr, is_int, is_integral, is_float,
                   is_void, is_struct, is_array, ptr_depth, base_type);
}

// Full type classification (surface + resolved)
TypeClassification classify_arg_type(const tinfo_t& tif) {
    TypeClassification tc;

    // Surface classification (without typedef resolution)
    classify_surface(tif,
        tc.is_ptr, tc.is_int, tc.is_integral, tc.is_float,
        tc.is_void, tc.is_struct, tc.is_array,
        tc.ptr_depth, tc.base_type);

    // Resolved classification (with typedef resolution)
    // IDA SDK's is_ptr(), is_integral(), etc. already resolve typedefs via get_realtype()
    classify_tinfo(tif,
        tc.is_ptr_resolved, tc.is_int_resolved, tc.is_integral_resolved,
        tc.is_float_resolved, tc.is_void_resolved,
        tc.is_struct, tc.is_array,  // Reuse - struct/array handled by classify_tinfo
        tc.ptr_depth_resolved, tc.base_type_resolved);

    return tc;
}

// ============================================================================
// Calling Convention
// ============================================================================

const char* get_calling_convention_name(cm_t cc) {
    // Extract calling convention from cm_t (using CM_CC_MASK)
    callcnv_t conv = cc & CM_CC_MASK;
    switch (conv) {
        case CM_CC_CDECL: return "cdecl";
        case CM_CC_STDCALL: return "stdcall";
        case CM_CC_FASTCALL: return "fastcall";
        case CM_CC_THISCALL: return "thiscall";
        case CM_CC_PASCAL: return "pascal";
        case CM_CC_ELLIPSIS: return "ellipsis";
        case CM_CC_SPECIAL: return "usercall";
        case CM_CC_SPECIALE: return "usercall_ellipsis";
        case CM_CC_SPECIALP: return "usercall_purged";
        case CM_CC_VOIDARG: return "voidarg";
        case CM_CC_UNKNOWN: return "unknown";
        case CM_CC_INVALID: return "invalid";
        default: return "other";
    }
}

// ============================================================================
// collect_func_args
// ============================================================================

void collect_func_args(std::vector<FuncArgEntry>& rows) {
    rows.clear();

    til_t* ti = get_idati();
    if (!ti) return;

    uint32_t max_ord = get_ordinal_limit(ti);
    if (max_ord == 0 || max_ord == uint32_t(-1)) return;

    for (uint32_t ord = 1; ord < max_ord; ++ord) {
        const char* name = get_numbered_type_name(ti, ord);
        if (!name) continue;  // Skip gaps in ordinal space

        tinfo_t tif;
        if (tif.get_numbered_type(ti, ord)) {
            if (tif.is_func()) {
                func_type_data_t fi;
                if (tif.get_func_details(&fi)) {
                    // Return type (arg_index = -1)
                    FuncArgEntry ret_entry;
                    ret_entry.type_ordinal = ord;
                    ret_entry.type_name = name;
                    ret_entry.arg_index = -1;
                    ret_entry.arg_name = "(return)";

                    qstring ret_str;
                    fi.rettype.print(&ret_str);
                    ret_entry.arg_type = ret_str.c_str();
                    ret_entry.calling_conv = get_calling_convention_name(fi.get_cc());
                    ret_entry.tc = classify_arg_type(fi.rettype);
                    rows.push_back(std::move(ret_entry));

                    // Arguments
                    for (size_t i = 0; i < fi.size(); i++) {
                        const funcarg_t& a = fi[i];
                        FuncArgEntry entry;
                        entry.type_ordinal = ord;
                        entry.type_name = name;
                        entry.arg_index = static_cast<int>(i);
                        entry.arg_name = a.name.empty() ? "" : a.name.c_str();

                        qstring type_str;
                        a.type.print(&type_str);
                        entry.arg_type = type_str.c_str();
                        entry.tc = classify_arg_type(a.type);
                        // calling_conv only on return type row
                        rows.push_back(std::move(entry));
                    }
                }
            }
        }
    }
}

// ============================================================================
// FuncArgsInTypeIterator
// ============================================================================

FuncArgsInTypeIterator::FuncArgsInTypeIterator(uint32_t ordinal) : type_ordinal_(ordinal) {
    til_t* ti = get_idati();
    if (!ti) return;

    const char* name = get_numbered_type_name(ti, type_ordinal_);
    if (!name) return;
    type_name_ = name;

    tinfo_t tif;
    if (tif.get_numbered_type(ti, type_ordinal_)) {
        if (tif.is_func()) {
            has_data_ = tif.get_func_details(&fi_);
        }
    }
}

bool FuncArgsInTypeIterator::next() {
    if (!has_data_) return false;
    ++idx_;
    // idx=-1 is return type, idx=0..fi_.size()-1 are arguments
    valid_ = (idx_ == -1) || (idx_ >= 0 && static_cast<size_t>(idx_) < fi_.size());
    return valid_;
}

bool FuncArgsInTypeIterator::eof() const {
    return idx_ >= -1 && !valid_;
}

void FuncArgsInTypeIterator::column(xsql::FunctionContext& ctx, int col) {
    if (!valid_) {
        ctx.result_null();
        return;
    }

    // Get the type for classification (computed on-the-fly for iterator)
    auto get_current_type = [&]() -> tinfo_t {
        if (idx_ == -1) return fi_.rettype;
        if (static_cast<size_t>(idx_) < fi_.size()) return fi_[idx_].type;
        return tinfo_t();
    };

    switch (col) {
        case 0: // type_ordinal
            ctx.result_int(type_ordinal_);
            break;
        case 1: // type_name
            ctx.result_text(type_name_.c_str());
            break;
        case 2: // arg_index
            ctx.result_int(idx_);
            break;
        case 3: // arg_name
            if (idx_ == -1) {
                ctx.result_text_static("(return)");
            } else if (static_cast<size_t>(idx_) < fi_.size()) {
                ctx.result_text(fi_[idx_].name.c_str());
            } else {
                ctx.result_null();
            }
            break;
        case 4: // arg_type
            if (idx_ == -1) {
                qstring ret_str;
                fi_.rettype.print(&ret_str);
                ctx.result_text(ret_str.c_str());
            } else if (static_cast<size_t>(idx_) < fi_.size()) {
                qstring type_str;
                fi_[idx_].type.print(&type_str);
                ctx.result_text(type_str.c_str());
            } else {
                ctx.result_null();
            }
            break;
        case 5: // calling_conv
            if (idx_ == -1) {
                ctx.result_text_static(get_calling_convention_name(fi_.get_cc()));
            } else {
                ctx.result_text_static("");
            }
            break;
        // Type classification columns (computed on-the-fly)
        case 6: case 7: case 8: case 9: case 10: case 11: case 12: case 13: case 14:
        case 15: case 16: case 17: case 18: case 19: case 20: case 21: {
            TypeClassification tc = classify_arg_type(get_current_type());
            switch (col) {
                case 6:  ctx.result_int(tc.is_ptr ? 1 : 0); break;
                case 7:  ctx.result_int(tc.is_int ? 1 : 0); break;
                case 8:  ctx.result_int(tc.is_integral ? 1 : 0); break;
                case 9:  ctx.result_int(tc.is_float ? 1 : 0); break;
                case 10: ctx.result_int(tc.is_void ? 1 : 0); break;
                case 11: ctx.result_int(tc.is_struct ? 1 : 0); break;
                case 12: ctx.result_int(tc.is_array ? 1 : 0); break;
                case 13: ctx.result_int(tc.ptr_depth); break;
                case 14: ctx.result_text(tc.base_type.c_str()); break;
                case 15: ctx.result_int(tc.is_ptr_resolved ? 1 : 0); break;
                case 16: ctx.result_int(tc.is_int_resolved ? 1 : 0); break;
                case 17: ctx.result_int(tc.is_integral_resolved ? 1 : 0); break;
                case 18: ctx.result_int(tc.is_float_resolved ? 1 : 0); break;
                case 19: ctx.result_int(tc.is_void_resolved ? 1 : 0); break;
                case 20: ctx.result_int(tc.ptr_depth_resolved); break;
                case 21: ctx.result_text(tc.base_type_resolved.c_str()); break;
            }
            break;
        }
        default:
            ctx.result_null();
            break;
    }
}

int64_t FuncArgsInTypeIterator::rowid() const {
    // Pack (type_ordinal, arg_index) with the shared helper so the pushdown
    // iterator and the full-scan cache rowid agree (see types_common.hpp). The
    // return-type row has arg_index == -1, so shift by +1 to keep the packed
    // index non-negative (return type -> 0, first arg -> 1, ...); the cache
    // .rowid() below shifts identically.
    return pack_type_rowid(type_ordinal_, static_cast<int>(idx_) + 1);
}

// ============================================================================
// TYPES_FUNC_ARGS Table Definition
// ============================================================================

CachedTableDef<FuncArgEntry> define_types_func_args() {
    return cached_table<FuncArgEntry>("types_func_args")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            til_t* ti = get_idati();
            return ti ? static_cast<size_t>(get_ordinal_limit(ti)) * 4 : 0;
        })
        .cache_builder([](std::vector<FuncArgEntry>& rows) {
            collect_func_args(rows);
        })
        // Stable rowid = pack_type_rowid(type_ordinal, arg_index + 1), matching the
        // FuncArgsInTypeIterator::rowid pushdown path above. Without this the
        // full-scan cursor used positional rowids while the filtered iterator used
        // the packed scheme, so the SAME (type_ordinal, arg_index) row got two
        // different rowids depending on access path. This table is read-only (no
        // by-rowid UPDATE/DELETE), so no row_lookup()/snapshot_mutations() is
        // needed -- SQLite resolves a rare `WHERE rowid=?` by full scan, correct now
        // that both paths agree. The +1 shift keeps the return-type row (arg_index
        // == -1) non-negative for packing.
        .rowid([](const FuncArgEntry& row) -> int64_t {
            return pack_type_rowid(row.type_ordinal, row.arg_index + 1);
        })
        .column_int("type_ordinal", [](const FuncArgEntry& row) -> int {
            return static_cast<int>(row.type_ordinal);
        })
        .column_text("type_name", [](const FuncArgEntry& row) -> std::string {
            return row.type_name;
        })
        .column_int("arg_index", [](const FuncArgEntry& row) -> int {
            return row.arg_index;
        })
        .column_text("arg_name", [](const FuncArgEntry& row) -> std::string {
            return row.arg_name;
        })
        .column_text("arg_type", [](const FuncArgEntry& row) -> std::string {
            return row.arg_type;
        })
        .column_text("calling_conv", [](const FuncArgEntry& row) -> std::string {
            return row.calling_conv;
        })
        .column_int("is_ptr", [](const FuncArgEntry& row) -> int {
            return row.tc.is_ptr ? 1 : 0;
        })
        .column_int("is_int", [](const FuncArgEntry& row) -> int {
            return row.tc.is_int ? 1 : 0;
        })
        .column_int("is_integral", [](const FuncArgEntry& row) -> int {
            return row.tc.is_integral ? 1 : 0;
        })
        .column_int("is_float", [](const FuncArgEntry& row) -> int {
            return row.tc.is_float ? 1 : 0;
        })
        .column_int("is_void", [](const FuncArgEntry& row) -> int {
            return row.tc.is_void ? 1 : 0;
        })
        .column_int("is_struct", [](const FuncArgEntry& row) -> int {
            return row.tc.is_struct ? 1 : 0;
        })
        .column_int("is_array", [](const FuncArgEntry& row) -> int {
            return row.tc.is_array ? 1 : 0;
        })
        .column_int("ptr_depth", [](const FuncArgEntry& row) -> int {
            return row.tc.ptr_depth;
        })
        .column_text("base_type", [](const FuncArgEntry& row) -> std::string {
            return row.tc.base_type;
        })
        .column_int("is_ptr_resolved", [](const FuncArgEntry& row) -> int {
            return row.tc.is_ptr_resolved ? 1 : 0;
        })
        .column_int("is_int_resolved", [](const FuncArgEntry& row) -> int {
            return row.tc.is_int_resolved ? 1 : 0;
        })
        .column_int("is_integral_resolved", [](const FuncArgEntry& row) -> int {
            return row.tc.is_integral_resolved ? 1 : 0;
        })
        .column_int("is_float_resolved", [](const FuncArgEntry& row) -> int {
            return row.tc.is_float_resolved ? 1 : 0;
        })
        .column_int("is_void_resolved", [](const FuncArgEntry& row) -> int {
            return row.tc.is_void_resolved ? 1 : 0;
        })
        .column_int("ptr_depth_resolved", [](const FuncArgEntry& row) -> int {
            return row.tc.ptr_depth_resolved;
        })
        .column_text("base_type_resolved", [](const FuncArgEntry& row) -> std::string {
            return row.tc.base_type_resolved;
        })
        .filter_eq("type_ordinal", [](int64_t ordinal) -> std::unique_ptr<xsql::RowIterator> {
            // Type ordinals are uint32; reject anything out of range rather than
            // truncating (e.g. 4294967297 -> 1 would return ordinal-1's args).
            // Ordinal 0 is always a gap, so the iterator yields no rows.
            if (ordinal <= 0 || ordinal > static_cast<int64_t>(UINT32_MAX))
                return std::make_unique<FuncArgsInTypeIterator>(0u);
            return std::make_unique<FuncArgsInTypeIterator>(static_cast<uint32_t>(ordinal));
        }, 10.0, 5.0)
        .build();
}

// ============================================================================
// Types Registry
// ============================================================================

} // namespace types
} // namespace idasql
