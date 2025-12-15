/**
 * entities_types.hpp - IDA type system tables
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
 *   local_types       - Backward compatibility alias
 */

#pragma once

#include <idasql/vtable.hpp>
#include <idasql/vtable_v2.hpp>

// IDA SDK headers
#include <ida.hpp>
#include <typeinf.hpp>

namespace idasql {
namespace types {

// ============================================================================
// Type Kind Classification
// ============================================================================

inline const char* get_type_kind(const tinfo_t& tif) {
    if (tif.is_struct()) return "struct";
    if (tif.is_union()) return "union";
    if (tif.is_enum()) return "enum";
    if (tif.is_typedef()) return "typedef";
    if (tif.is_func()) return "func";
    if (tif.is_ptr()) return "ptr";
    if (tif.is_array()) return "array";
    return "other";
}

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

inline std::vector<TypeEntry>& get_types_cache() {
    static std::vector<TypeEntry> cache;
    return cache;
}

inline void rebuild_types_cache() {
    auto& cache = get_types_cache();
    cache.clear();

    til_t* ti = get_idati();
    if (!ti) return;

    uint32_t ord = 1;
    while (true) {
        const char* name = get_numbered_type_name(ti, ord);
        if (!name) break;

        TypeEntry entry;
        entry.ordinal = ord;
        entry.name = name;

        tinfo_t tif;
        if (tif.get_numbered_type(ti, ord)) {
            entry.kind = get_type_kind(tif);
            entry.is_struct = tif.is_struct();
            entry.is_union = tif.is_union();
            entry.is_enum = tif.is_enum();
            entry.is_typedef = tif.is_typedef();
            entry.is_func = tif.is_func();
            entry.is_ptr = tif.is_ptr();
            entry.is_array = tif.is_array();

            // Get size
            size_t sz = tif.get_size();
            entry.size = (sz != BADSIZE) ? static_cast<int64_t>(sz) : -1;

            // Get alignment for structs/unions
            entry.alignment = 0;
            if (tif.is_struct() || tif.is_union()) {
                udt_type_data_t udt;
                if (tif.get_udt_details(&udt)) {
                    entry.alignment = static_cast<int>(udt.effalign);
                }
            }

            // Get definition string
            qstring def_str;
            tif.print(&def_str);
            entry.definition = def_str.c_str();

            // For typedefs, get the resolved type name
            if (tif.is_typedef()) {
                qstring res_name;
                if (tif.get_final_type_name(&res_name)) {
                    entry.resolved = res_name.c_str();
                }
            }
        } else {
            entry.kind = "unknown";
            entry.size = -1;
            entry.alignment = 0;
            entry.is_struct = false;
            entry.is_union = false;
            entry.is_enum = false;
            entry.is_typedef = false;
            entry.is_func = false;
            entry.is_ptr = false;
            entry.is_array = false;
        }

        cache.push_back(entry);
        ++ord;
    }
}

// ============================================================================
// TYPES Table - All local types (enhanced)
// ============================================================================

inline VTableDef define_types() {
    return table("types")
        .count([]() {
            rebuild_types_cache();
            return get_types_cache().size();
        })
        .column_int("ordinal", [](size_t i) -> int {
            auto& cache = get_types_cache();
            return i < cache.size() ? cache[i].ordinal : 0;
        })
        .column_text("name", [](size_t i) -> std::string {
            auto& cache = get_types_cache();
            return i < cache.size() ? cache[i].name : "";
        })
        .column_text("kind", [](size_t i) -> std::string {
            auto& cache = get_types_cache();
            return i < cache.size() ? cache[i].kind : "";
        })
        .column_int64("size", [](size_t i) -> int64_t {
            auto& cache = get_types_cache();
            return i < cache.size() ? cache[i].size : -1;
        })
        .column_int("alignment", [](size_t i) -> int {
            auto& cache = get_types_cache();
            return i < cache.size() ? cache[i].alignment : 0;
        })
        .column_int("is_struct", [](size_t i) -> int {
            auto& cache = get_types_cache();
            return i < cache.size() ? (cache[i].is_struct ? 1 : 0) : 0;
        })
        .column_int("is_union", [](size_t i) -> int {
            auto& cache = get_types_cache();
            return i < cache.size() ? (cache[i].is_union ? 1 : 0) : 0;
        })
        .column_int("is_enum", [](size_t i) -> int {
            auto& cache = get_types_cache();
            return i < cache.size() ? (cache[i].is_enum ? 1 : 0) : 0;
        })
        .column_int("is_typedef", [](size_t i) -> int {
            auto& cache = get_types_cache();
            return i < cache.size() ? (cache[i].is_typedef ? 1 : 0) : 0;
        })
        .column_int("is_func", [](size_t i) -> int {
            auto& cache = get_types_cache();
            return i < cache.size() ? (cache[i].is_func ? 1 : 0) : 0;
        })
        .column_int("is_ptr", [](size_t i) -> int {
            auto& cache = get_types_cache();
            return i < cache.size() ? (cache[i].is_ptr ? 1 : 0) : 0;
        })
        .column_int("is_array", [](size_t i) -> int {
            auto& cache = get_types_cache();
            return i < cache.size() ? (cache[i].is_array ? 1 : 0) : 0;
        })
        .column_text("definition", [](size_t i) -> std::string {
            auto& cache = get_types_cache();
            return i < cache.size() ? cache[i].definition : "";
        })
        .column_text("resolved", [](size_t i) -> std::string {
            auto& cache = get_types_cache();
            return i < cache.size() ? cache[i].resolved : "";
        })
        .build();
}

// ============================================================================
// TYPES_MEMBERS Table - Struct/union field details
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
};

inline std::vector<MemberEntry>& get_members_cache() {
    static std::vector<MemberEntry> cache;
    return cache;
}

inline void rebuild_members_cache() {
    auto& cache = get_members_cache();
    cache.clear();

    til_t* ti = get_idati();
    if (!ti) return;

    uint32_t ord = 1;
    while (true) {
        const char* name = get_numbered_type_name(ti, ord);
        if (!name) break;

        tinfo_t tif;
        if (tif.get_numbered_type(ti, ord)) {
            if (tif.is_struct() || tif.is_union()) {
                udt_type_data_t udt;
                if (tif.get_udt_details(&udt)) {
                    for (size_t i = 0; i < udt.size(); i++) {
                        const udm_t& m = udt[i];
                        MemberEntry entry;
                        entry.type_ordinal = ord;
                        entry.type_name = name;
                        entry.member_index = static_cast<int>(i);
                        entry.member_name = m.name.c_str();
                        entry.offset = static_cast<int64_t>(m.offset / 8);
                        entry.offset_bits = static_cast<int64_t>(m.offset);
                        entry.size = static_cast<int64_t>(m.size / 8);
                        entry.size_bits = static_cast<int64_t>(m.size);
                        entry.is_bitfield = m.is_bitfield();
                        entry.is_baseclass = m.is_baseclass();
                        entry.comment = m.cmt.c_str();

                        qstring type_str;
                        m.type.print(&type_str);
                        entry.member_type = type_str.c_str();

                        cache.push_back(entry);
                    }
                }
            }
        }
        ++ord;
    }
}

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
    explicit MembersInTypeIterator(uint32_t ordinal) : type_ordinal_(ordinal) {
        til_t* ti = get_idati();
        if (!ti) return;

        const char* name = get_numbered_type_name(ti, type_ordinal_);
        if (!name) return;
        type_name_ = name;

        tinfo_t tif;
        if (tif.get_numbered_type(ti, type_ordinal_)) {
            if (tif.is_struct() || tif.is_union()) {
                has_data_ = tif.get_udt_details(&udt_);
            }
        }
    }

    bool next() override {
        if (!has_data_) return false;
        ++idx_;
        valid_ = (idx_ >= 0 && static_cast<size_t>(idx_) < udt_.size());
        return valid_;
    }

    bool eof() const override {
        return idx_ >= 0 && !valid_;
    }

    void column(sqlite3_context* ctx, int col) override {
        if (!valid_ || idx_ < 0 || static_cast<size_t>(idx_) >= udt_.size()) {
            sqlite3_result_null(ctx);
            return;
        }
        const udm_t& m = udt_[idx_];
        switch (col) {
            case 0: sqlite3_result_int(ctx, type_ordinal_); break;
            case 1: sqlite3_result_text(ctx, type_name_.c_str(), -1, SQLITE_TRANSIENT); break;
            case 2: sqlite3_result_int(ctx, idx_); break;
            case 3: sqlite3_result_text(ctx, m.name.c_str(), -1, SQLITE_TRANSIENT); break;
            case 4: sqlite3_result_int64(ctx, static_cast<int64_t>(m.offset / 8)); break;
            case 5: sqlite3_result_int64(ctx, static_cast<int64_t>(m.offset)); break;
            case 6: sqlite3_result_int64(ctx, static_cast<int64_t>(m.size / 8)); break;
            case 7: sqlite3_result_int64(ctx, static_cast<int64_t>(m.size)); break;
            case 8: {
                qstring type_str;
                m.type.print(&type_str);
                sqlite3_result_text(ctx, type_str.c_str(), -1, SQLITE_TRANSIENT);
                break;
            }
            case 9: sqlite3_result_int(ctx, m.is_bitfield() ? 1 : 0); break;
            case 10: sqlite3_result_int(ctx, m.is_baseclass() ? 1 : 0); break;
            case 11: sqlite3_result_text(ctx, m.cmt.c_str(), -1, SQLITE_TRANSIENT); break;
            default: sqlite3_result_null(ctx); break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(type_ordinal_) * 10000 + idx_;
    }
};

inline VTableDef define_types_members() {
    return table("types_members")
        .count([]() {
            rebuild_members_cache();
            return get_members_cache().size();
        })
        .column_int("type_ordinal", [](size_t i) -> int {
            auto& cache = get_members_cache();
            return i < cache.size() ? cache[i].type_ordinal : 0;
        })
        .column_text("type_name", [](size_t i) -> std::string {
            auto& cache = get_members_cache();
            return i < cache.size() ? cache[i].type_name : "";
        })
        .column_int("member_index", [](size_t i) -> int {
            auto& cache = get_members_cache();
            return i < cache.size() ? cache[i].member_index : 0;
        })
        .column_text("member_name", [](size_t i) -> std::string {
            auto& cache = get_members_cache();
            return i < cache.size() ? cache[i].member_name : "";
        })
        .column_int64("offset", [](size_t i) -> int64_t {
            auto& cache = get_members_cache();
            return i < cache.size() ? cache[i].offset : 0;
        })
        .column_int64("offset_bits", [](size_t i) -> int64_t {
            auto& cache = get_members_cache();
            return i < cache.size() ? cache[i].offset_bits : 0;
        })
        .column_int64("size", [](size_t i) -> int64_t {
            auto& cache = get_members_cache();
            return i < cache.size() ? cache[i].size : 0;
        })
        .column_int64("size_bits", [](size_t i) -> int64_t {
            auto& cache = get_members_cache();
            return i < cache.size() ? cache[i].size_bits : 0;
        })
        .column_text("member_type", [](size_t i) -> std::string {
            auto& cache = get_members_cache();
            return i < cache.size() ? cache[i].member_type : "";
        })
        .column_int("is_bitfield", [](size_t i) -> int {
            auto& cache = get_members_cache();
            return i < cache.size() ? (cache[i].is_bitfield ? 1 : 0) : 0;
        })
        .column_int("is_baseclass", [](size_t i) -> int {
            auto& cache = get_members_cache();
            return i < cache.size() ? (cache[i].is_baseclass ? 1 : 0) : 0;
        })
        .column_text("comment", [](size_t i) -> std::string {
            auto& cache = get_members_cache();
            return i < cache.size() ? cache[i].comment : "";
        })
        // Constraint pushdown: type_ordinal = X
        .filter_eq("type_ordinal", [](int64_t ordinal) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<MembersInTypeIterator>(static_cast<uint32_t>(ordinal));
        }, 10.0, 5.0)
        .build();
}

// ============================================================================
// TYPES_ENUM_VALUES Table - Enum constants
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

inline std::vector<EnumValueEntry>& get_enum_values_cache() {
    static std::vector<EnumValueEntry> cache;
    return cache;
}

inline void rebuild_enum_values_cache() {
    auto& cache = get_enum_values_cache();
    cache.clear();

    til_t* ti = get_idati();
    if (!ti) return;

    uint32_t ord = 1;
    while (true) {
        const char* name = get_numbered_type_name(ti, ord);
        if (!name) break;

        tinfo_t tif;
        if (tif.get_numbered_type(ti, ord)) {
            if (tif.is_enum()) {
                enum_type_data_t ei;
                if (tif.get_enum_details(&ei)) {
                    for (size_t i = 0; i < ei.size(); i++) {
                        const edm_t& e = ei[i];
                        EnumValueEntry entry;
                        entry.type_ordinal = ord;
                        entry.type_name = name;
                        entry.value_index = static_cast<int>(i);
                        entry.value_name = e.name.c_str();
                        entry.value = static_cast<int64_t>(e.value);
                        entry.uvalue = e.value;
                        entry.comment = e.cmt.c_str();
                        cache.push_back(entry);
                    }
                }
            }
        }
        ++ord;
    }
}

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
    explicit EnumValuesInTypeIterator(uint32_t ordinal) : type_ordinal_(ordinal) {
        til_t* ti = get_idati();
        if (!ti) return;

        const char* name = get_numbered_type_name(ti, type_ordinal_);
        if (!name) return;
        type_name_ = name;

        tinfo_t tif;
        if (tif.get_numbered_type(ti, type_ordinal_)) {
            if (tif.is_enum()) {
                has_data_ = tif.get_enum_details(&ei_);
            }
        }
    }

    bool next() override {
        if (!has_data_) return false;
        ++idx_;
        valid_ = (idx_ >= 0 && static_cast<size_t>(idx_) < ei_.size());
        return valid_;
    }

    bool eof() const override {
        return idx_ >= 0 && !valid_;
    }

    void column(sqlite3_context* ctx, int col) override {
        if (!valid_ || idx_ < 0 || static_cast<size_t>(idx_) >= ei_.size()) {
            sqlite3_result_null(ctx);
            return;
        }
        const edm_t& e = ei_[idx_];
        switch (col) {
            case 0: sqlite3_result_int(ctx, type_ordinal_); break;
            case 1: sqlite3_result_text(ctx, type_name_.c_str(), -1, SQLITE_TRANSIENT); break;
            case 2: sqlite3_result_int(ctx, idx_); break;
            case 3: sqlite3_result_text(ctx, e.name.c_str(), -1, SQLITE_TRANSIENT); break;
            case 4: sqlite3_result_int64(ctx, static_cast<int64_t>(e.value)); break;
            case 5: sqlite3_result_int64(ctx, static_cast<int64_t>(e.value)); break;  // uvalue
            case 6: sqlite3_result_text(ctx, e.cmt.c_str(), -1, SQLITE_TRANSIENT); break;
            default: sqlite3_result_null(ctx); break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(type_ordinal_) * 10000 + idx_;
    }
};

inline VTableDef define_types_enum_values() {
    return table("types_enum_values")
        .count([]() {
            rebuild_enum_values_cache();
            return get_enum_values_cache().size();
        })
        .column_int("type_ordinal", [](size_t i) -> int {
            auto& cache = get_enum_values_cache();
            return i < cache.size() ? cache[i].type_ordinal : 0;
        })
        .column_text("type_name", [](size_t i) -> std::string {
            auto& cache = get_enum_values_cache();
            return i < cache.size() ? cache[i].type_name : "";
        })
        .column_int("value_index", [](size_t i) -> int {
            auto& cache = get_enum_values_cache();
            return i < cache.size() ? cache[i].value_index : 0;
        })
        .column_text("value_name", [](size_t i) -> std::string {
            auto& cache = get_enum_values_cache();
            return i < cache.size() ? cache[i].value_name : "";
        })
        .column_int64("value", [](size_t i) -> int64_t {
            auto& cache = get_enum_values_cache();
            return i < cache.size() ? cache[i].value : 0;
        })
        .column_int64("uvalue", [](size_t i) -> int64_t {
            auto& cache = get_enum_values_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].uvalue) : 0;
        })
        .column_text("comment", [](size_t i) -> std::string {
            auto& cache = get_enum_values_cache();
            return i < cache.size() ? cache[i].comment : "";
        })
        // Constraint pushdown: type_ordinal = X
        .filter_eq("type_ordinal", [](int64_t ordinal) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<EnumValuesInTypeIterator>(static_cast<uint32_t>(ordinal));
        }, 10.0, 10.0)
        .build();
}

// ============================================================================
// TYPES_FUNC_ARGS Table - Function prototype arguments
// ============================================================================

struct FuncArgEntry {
    uint32_t type_ordinal;
    std::string type_name;
    int arg_index;  // -1 for return type
    std::string arg_name;
    std::string arg_type;
    std::string calling_conv;  // Only set on arg_index=-1 row
};

inline std::vector<FuncArgEntry>& get_func_args_cache() {
    static std::vector<FuncArgEntry> cache;
    return cache;
}

inline const char* get_calling_convention_name(cm_t cc) {
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

inline void rebuild_func_args_cache() {
    auto& cache = get_func_args_cache();
    cache.clear();

    til_t* ti = get_idati();
    if (!ti) return;

    uint32_t ord = 1;
    while (true) {
        const char* name = get_numbered_type_name(ti, ord);
        if (!name) break;

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
                    cache.push_back(ret_entry);

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
                        // calling_conv only on return type row
                        cache.push_back(entry);
                    }
                }
            }
        }
        ++ord;
    }
}

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
    explicit FuncArgsInTypeIterator(uint32_t ordinal) : type_ordinal_(ordinal) {
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

    bool next() override {
        if (!has_data_) return false;
        ++idx_;
        // idx_=-1 is return type, then 0..n-1 are args
        valid_ = (idx_ >= -1 && static_cast<size_t>(idx_) < fi_.size() + 1);
        // Adjust: idx_=-1 is return, idx_=0 is first arg, etc.
        // Total items = 1 (return) + fi_.size() (args)
        valid_ = (idx_ >= -1 && idx_ < static_cast<int>(fi_.size()));
        // Correction: idx=-1 is return, idx=0..fi_.size()-1 are args
        // So valid when idx >= -1 and idx < fi_.size()
        // Actually: return type is one row, args are fi_.size() rows
        // Total rows = 1 + fi_.size()
        valid_ = (idx_ >= -1 && idx_ <= static_cast<int>(fi_.size()) - 1 + 1 - 1);
        // Simpler: idx=-1 valid, idx=0..fi_.size()-1 valid
        valid_ = (idx_ == -1) || (idx_ >= 0 && static_cast<size_t>(idx_) < fi_.size());
        return valid_;
    }

    bool eof() const override {
        return idx_ >= -1 && !valid_;
    }

    void column(sqlite3_context* ctx, int col) override {
        if (!valid_) {
            sqlite3_result_null(ctx);
            return;
        }

        switch (col) {
            case 0: // type_ordinal
                sqlite3_result_int(ctx, type_ordinal_);
                break;
            case 1: // type_name
                sqlite3_result_text(ctx, type_name_.c_str(), -1, SQLITE_TRANSIENT);
                break;
            case 2: // arg_index
                sqlite3_result_int(ctx, idx_);
                break;
            case 3: // arg_name
                if (idx_ == -1) {
                    sqlite3_result_text(ctx, "(return)", -1, SQLITE_STATIC);
                } else if (static_cast<size_t>(idx_) < fi_.size()) {
                    sqlite3_result_text(ctx, fi_[idx_].name.c_str(), -1, SQLITE_TRANSIENT);
                } else {
                    sqlite3_result_null(ctx);
                }
                break;
            case 4: // arg_type
                if (idx_ == -1) {
                    qstring ret_str;
                    fi_.rettype.print(&ret_str);
                    sqlite3_result_text(ctx, ret_str.c_str(), -1, SQLITE_TRANSIENT);
                } else if (static_cast<size_t>(idx_) < fi_.size()) {
                    qstring type_str;
                    fi_[idx_].type.print(&type_str);
                    sqlite3_result_text(ctx, type_str.c_str(), -1, SQLITE_TRANSIENT);
                } else {
                    sqlite3_result_null(ctx);
                }
                break;
            case 5: // calling_conv
                if (idx_ == -1) {
                    sqlite3_result_text(ctx, get_calling_convention_name(fi_.get_cc()), -1, SQLITE_STATIC);
                } else {
                    sqlite3_result_text(ctx, "", -1, SQLITE_STATIC);
                }
                break;
            default:
                sqlite3_result_null(ctx);
                break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(type_ordinal_) * 10000 + (idx_ + 1);
    }
};

inline VTableDef define_types_func_args() {
    return table("types_func_args")
        .count([]() {
            rebuild_func_args_cache();
            return get_func_args_cache().size();
        })
        .column_int("type_ordinal", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? cache[i].type_ordinal : 0;
        })
        .column_text("type_name", [](size_t i) -> std::string {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? cache[i].type_name : "";
        })
        .column_int("arg_index", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? cache[i].arg_index : 0;
        })
        .column_text("arg_name", [](size_t i) -> std::string {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? cache[i].arg_name : "";
        })
        .column_text("arg_type", [](size_t i) -> std::string {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? cache[i].arg_type : "";
        })
        .column_text("calling_conv", [](size_t i) -> std::string {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? cache[i].calling_conv : "";
        })
        // Constraint pushdown: type_ordinal = X
        .filter_eq("type_ordinal", [](int64_t ordinal) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<FuncArgsInTypeIterator>(static_cast<uint32_t>(ordinal));
        }, 10.0, 5.0)
        .build();
}

// ============================================================================
// Types Registry
// ============================================================================

struct TypesRegistry {
    VTableDef types;
    VTableDef types_members;
    VTableDef types_enum_values;
    VTableDef types_func_args;

    TypesRegistry()
        : types(define_types())
        , types_members(define_types_members())
        , types_enum_values(define_types_enum_values())
        , types_func_args(define_types_func_args())
    {}

    void register_all(sqlite3* db) {
        // Register tables
        register_vtable(db, "ida_types", &types);
        create_vtable(db, "types", "ida_types");

        register_vtable(db, "ida_types_members", &types_members);
        create_vtable(db, "types_members", "ida_types_members");

        register_vtable(db, "ida_types_enum_values", &types_enum_values);
        create_vtable(db, "types_enum_values", "ida_types_enum_values");

        register_vtable(db, "ida_types_func_args", &types_func_args);
        create_vtable(db, "types_func_args", "ida_types_func_args");

        // Create views
        create_views(db);
    }

private:
    void create_views(sqlite3* db) {
        // Filtering views
        exec_sql(db, "CREATE VIEW IF NOT EXISTS types_v_structs AS SELECT * FROM types WHERE is_struct = 1");
        exec_sql(db, "CREATE VIEW IF NOT EXISTS types_v_unions AS SELECT * FROM types WHERE is_union = 1");
        exec_sql(db, "CREATE VIEW IF NOT EXISTS types_v_enums AS SELECT * FROM types WHERE is_enum = 1");
        exec_sql(db, "CREATE VIEW IF NOT EXISTS types_v_typedefs AS SELECT * FROM types WHERE is_typedef = 1");
        exec_sql(db, "CREATE VIEW IF NOT EXISTS types_v_funcs AS SELECT * FROM types WHERE is_func = 1");

        // Backward compatibility - alias for old local_types table
        exec_sql(db, "CREATE VIEW IF NOT EXISTS local_types AS SELECT ordinal, name, definition AS type, "
                     "is_struct, is_enum, is_typedef FROM types");
    }

    void exec_sql(sqlite3* db, const char* sql) {
        char* err = nullptr;
        sqlite3_exec(db, sql, nullptr, nullptr, &err);
        if (err) sqlite3_free(err);
    }
};

} // namespace types
} // namespace idasql
