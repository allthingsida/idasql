// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * entities_types.hpp - IDA type system tables (types, members, enum values, func args)
 *
 * Provides SQL tables for querying IDA's type library:
 *   types             - All local types (structs, unions, enums, typedefs, funcs)
 *   types_members     - Struct/union member details
 *   types_enum_values - Enum constant values
 *   types_func_args   - Function prototype arguments
 *
 * Also provides views:
 *   types_v_structs   - Filter: structs only
 *   types_v_unions    - Filter: unions only
 *   types_v_enums     - Filter: enums only
 *   types_v_typedefs  - Filter: typedefs only
 *   types_v_funcs     - Filter: function types only
 */

#pragma once

#include <idasql/platform.hpp>

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include "ida_headers.hpp"

namespace idasql {
namespace types {

// ============================================================================
// Undo hook
// ============================================================================

void ida_undo_hook(const std::string&);

// ============================================================================
// Type Kind Classification
// ============================================================================

const char* get_type_kind(const tinfo_t& tif);

// ============================================================================
// Type Entry Cache
// ============================================================================

struct TypeEntry {
    uint32_t ordinal;
    std::string name;
    std::string kind;
    int64_t size;
    int alignment;
    bool is_struct;
    bool is_union;
    bool is_enum;
    bool is_typedef;
    bool is_func;
    bool is_ptr;
    bool is_array;
    std::string definition;
    std::string resolved;  // For typedefs: what it resolves to
};

void collect_types(std::vector<TypeEntry>& rows);

// ============================================================================
// Member Entry Cache
// ============================================================================

struct MemberEntry {
    uint32_t type_ordinal;
    std::string type_name;
    int member_index;
    std::string member_name;
    int64_t offset;
    int64_t offset_bits;
    int64_t size;
    int64_t size_bits;
    std::string member_type;
    bool is_bitfield;
    bool is_baseclass;
    std::string comment;
    // Member type classification (for efficient filtering)
    bool mt_is_struct;
    bool mt_is_union;
    bool mt_is_enum;
    bool mt_is_ptr;
    bool mt_is_array;
    int member_type_ordinal;  // -1 if member type not in local types
};

int get_type_ordinal_by_name(til_t* ti, const char* type_name);

void classify_member_type(const tinfo_t& mtype, til_t* ti,
                          bool& is_struct, bool& is_union, bool& is_enum,
                          bool& is_ptr, bool& is_array, int& type_ordinal);

void collect_members(std::vector<MemberEntry>& rows);

// ============================================================================
// Enum Value Entry Cache
// ============================================================================

struct EnumValueEntry {
    uint32_t type_ordinal;
    std::string type_name;
    int value_index;
    std::string value_name;
    int64_t value;
    uint64_t uvalue;
    std::string comment;
};

void collect_enum_values(std::vector<EnumValueEntry>& rows);

// ============================================================================
// Type Classification (for func args)
// ============================================================================

struct TypeClassification {
    // Surface-level classification (literal type as written)
    bool is_ptr = false;
    bool is_int = false;        // Exactly int type
    bool is_integral = false;   // Int-like family (int, long, short, char, bool)
    bool is_float = false;
    bool is_void = false;
    bool is_struct = false;
    bool is_array = false;
    int ptr_depth = 0;
    std::string base_type;      // Type name with pointers stripped

    // Resolved classification (after typedef resolution)
    bool is_ptr_resolved = false;
    bool is_int_resolved = false;
    bool is_integral_resolved = false;
    bool is_float_resolved = false;
    bool is_void_resolved = false;
    int ptr_depth_resolved = 0;
    std::string base_type_resolved;
};

int get_ptr_depth(tinfo_t tif);
std::string get_base_type_name(tinfo_t tif);

void classify_tinfo(const tinfo_t& tif,
                    bool& is_ptr, bool& is_int, bool& is_integral,
                    bool& is_float, bool& is_void, bool& is_struct,
                    bool& is_array, int& ptr_depth, std::string& base_type);

bool is_surface_typedef(const tinfo_t& tif);

void classify_surface(const tinfo_t& tif,
                      bool& is_ptr, bool& is_int, bool& is_integral,
                      bool& is_float, bool& is_void, bool& is_struct,
                      bool& is_array, int& ptr_depth, std::string& base_type);

TypeClassification classify_arg_type(const tinfo_t& tif);

// ============================================================================
// Func Arg Entry Cache
// ============================================================================

struct FuncArgEntry {
    uint32_t type_ordinal;
    std::string type_name;
    int arg_index;  // -1 for return type
    std::string arg_name;
    std::string arg_type;
    std::string calling_conv;  // Only set on arg_index=-1 row

    // Type classification
    TypeClassification tc;
};

const char* get_calling_convention_name(cm_t cc);

void collect_func_args(std::vector<FuncArgEntry>& rows);

// ============================================================================
// Helper structs for write operations
// ============================================================================

struct TypeMemberRef {
    tinfo_t tif;
    udt_type_data_t udt;
    bool valid;
    uint32_t ordinal;

    TypeMemberRef(uint32_t ord);
    bool save();
};

bool build_member_entry(uint32_t ordinal, int member_index, MemberEntry& entry);

struct EnumTypeRef {
    tinfo_t tif;
    enum_type_data_t ei;
    bool valid;
    uint32_t ordinal;

    EnumTypeRef(uint32_t ord);
    bool save();
};

bool build_enum_value_entry(uint32_t ordinal, int value_index, EnumValueEntry& entry);

// ============================================================================
// Iterators (for constraint pushdown: WHERE type_ordinal = X)
// ============================================================================

/**
 * Iterator for members of a specific type.
 * Used when query has: WHERE type_ordinal = X
 */
class MembersInTypeIterator : public xsql::RowIterator {
    uint32_t type_ordinal_;
    std::string type_name_;
    udt_type_data_t udt_;
    int idx_ = -1;
    bool valid_ = false;
    bool has_data_ = false;

public:
    explicit MembersInTypeIterator(uint32_t ordinal);
    bool next() override;
    bool eof() const override;
    void column(xsql::FunctionContext& ctx, int col) override;
    int64_t rowid() const override;
};

/**
 * Iterator for enum values of a specific enum type.
 * Used when query has: WHERE type_ordinal = X
 */
class EnumValuesInTypeIterator : public xsql::RowIterator {
    uint32_t type_ordinal_;
    std::string type_name_;
    enum_type_data_t ei_;
    int idx_ = -1;
    bool valid_ = false;
    bool has_data_ = false;

public:
    explicit EnumValuesInTypeIterator(uint32_t ordinal);
    bool next() override;
    bool eof() const override;
    void column(xsql::FunctionContext& ctx, int col) override;
    int64_t rowid() const override;
};

/**
 * Iterator for function args of a specific function type.
 * Used when query has: WHERE type_ordinal = X
 */
class FuncArgsInTypeIterator : public xsql::RowIterator {
    uint32_t type_ordinal_;
    std::string type_name_;
    func_type_data_t fi_;
    int idx_ = -2;  // Start at -2, first next() moves to -1 (return type)
    bool valid_ = false;
    bool has_data_ = false;

public:
    explicit FuncArgsInTypeIterator(uint32_t ordinal);
    bool next() override;
    bool eof() const override;
    void column(xsql::FunctionContext& ctx, int col) override;
    int64_t rowid() const override;
};

// ============================================================================
// Table Definitions
// ============================================================================

CachedTableDef<TypeEntry> define_types();
CachedTableDef<MemberEntry> define_types_members();
CachedTableDef<EnumValueEntry> define_types_enum_values();
CachedTableDef<FuncArgEntry> define_types_func_args();

// ============================================================================
// Types Registry
// ============================================================================

struct TypesRegistry {
    CachedTableDef<TypeEntry> types;
    CachedTableDef<MemberEntry> types_members;
    CachedTableDef<EnumValueEntry> types_enum_values;
    CachedTableDef<FuncArgEntry> types_func_args;

    TypesRegistry();
    void register_all(xsql::Database& db);

private:
    void create_views(xsql::Database& db);
};

} // namespace types
} // namespace idasql
