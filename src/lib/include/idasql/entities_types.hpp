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
 */

#pragma once

#include <idasql/platform.hpp>

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include <idasql/platform_undef.hpp>

// IDA SDK headers
#include <ida.hpp>
#include <typeinf.hpp>

namespace idasql {
namespace types {

inline void ida_undo_hook(const std::string&) {}

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

inline void collect_types(std::vector<TypeEntry>& rows) {
    rows.clear();

    til_t* ti = get_idati();
    if (!ti) return;

    uint32_t max_ord = get_ordinal_limit(ti);
    if (max_ord == 0 || max_ord == uint32_t(-1)) return;

    for (uint32_t ord = 1; ord < max_ord; ++ord) {
        const char* name = get_numbered_type_name(ti, ord);
        if (!name) continue;  // Skip gaps in ordinal space

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

        rows.push_back(std::move(entry));
    }
}

// ============================================================================
// TYPES Table - All local types (enhanced)
// ============================================================================

inline CachedTableDef<TypeEntry> define_types() {
    return cached_table<TypeEntry>("types")
        .no_shared_cache()
        .on_modify(ida_undo_hook)
        .estimate_rows([]() -> size_t {
            til_t* ti = get_idati();
            return ti ? static_cast<size_t>(get_ordinal_limit(ti)) : 0;
        })
        .cache_builder([](std::vector<TypeEntry>& rows) {
            collect_types(rows);
        })
        .column_int("ordinal", [](const TypeEntry& row) -> int {
            return static_cast<int>(row.ordinal);
        })
        .column_text_rw("name",
            [](const TypeEntry& row) -> std::string {
                return row.name;
            },
            [](TypeEntry& row, const char* new_name) -> bool {
                if (!new_name || !new_name[0]) return false;

                til_t* ti = get_idati();
                if (!ti) return false;

                tinfo_t tif;
                if (!tif.get_numbered_type(ti, row.ordinal)) return false;

                bool ok = tif.rename_type(new_name) == TERR_OK;
                if (ok) row.name = new_name;
                return ok;
            })
        .column_text("kind", [](const TypeEntry& row) -> std::string {
            return row.kind;
        })
        .column_int64("size", [](const TypeEntry& row) -> int64_t {
            return row.size;
        })
        .column_int("alignment", [](const TypeEntry& row) -> int {
            return row.alignment;
        })
        .column_int("is_struct", [](const TypeEntry& row) -> int {
            return row.is_struct ? 1 : 0;
        })
        .column_int("is_union", [](const TypeEntry& row) -> int {
            return row.is_union ? 1 : 0;
        })
        .column_int("is_enum", [](const TypeEntry& row) -> int {
            return row.is_enum ? 1 : 0;
        })
        .column_int("is_typedef", [](const TypeEntry& row) -> int {
            return row.is_typedef ? 1 : 0;
        })
        .column_int("is_func", [](const TypeEntry& row) -> int {
            return row.is_func ? 1 : 0;
        })
        .column_int("is_ptr", [](const TypeEntry& row) -> int {
            return row.is_ptr ? 1 : 0;
        })
        .column_int("is_array", [](const TypeEntry& row) -> int {
            return row.is_array ? 1 : 0;
        })
        .column_text("definition", [](const TypeEntry& row) -> std::string {
            return row.definition;
        })
        .column_text("resolved", [](const TypeEntry& row) -> std::string {
            return row.resolved;
        })
        .deletable([](TypeEntry& row) -> bool {
            til_t* ti = get_idati();
            if (!ti) return false;
            return del_numbered_type(ti, row.ordinal);
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            if (argc < 2 || argv[1].is_null())
                return false;

            const char* name = argv[1].as_c_str();
            if (!name || !name[0]) return false;

            // kind (col 2): defaults to "struct"
            std::string kind = "struct";
            if (argc > 2 && !argv[2].is_null()) {
                const char* k = argv[2].as_c_str();
                if (k && k[0]) kind = k;
            }

            til_t* ti = get_idati();
            if (!ti) return false;

            // Check if type with this name already exists
            if (get_type_ordinal(ti, name) != 0)
                return false;

            uint32_t ord = alloc_type_ordinal(ti);
            if (ord == 0) return false;

            tinfo_t tif;
            if (kind == "struct") {
                udt_type_data_t udt;
                udt.is_union = false;
                tif.create_udt(udt);
            } else if (kind == "union") {
                udt_type_data_t udt;
                udt.is_union = true;
                tif.create_udt(udt);
            } else if (kind == "enum") {
                enum_type_data_t ei;
                tif.create_enum(ei);
            } else {
                return false;
            }

            return tif.set_numbered_type(ti, ord, NTF_REPLACE, name) == TERR_OK;
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
    // Member type classification (for efficient filtering)
    bool mt_is_struct;
    bool mt_is_union;
    bool mt_is_enum;
    bool mt_is_ptr;
    bool mt_is_array;
    int member_type_ordinal;  // -1 if member type not in local types
};

// Helper to get ordinal of a type by name
inline int get_type_ordinal_by_name(til_t* ti, const char* type_name) {
    if (!ti || !type_name || !type_name[0]) return -1;
    uint32_t ord = get_type_ordinal(ti, type_name);
    return (ord != 0) ? static_cast<int>(ord) : -1;
}

// Helper to classify member type and get ordinal
inline void classify_member_type(const tinfo_t& mtype, til_t* ti,
                                  bool& is_struct, bool& is_union, bool& is_enum,
                                  bool& is_ptr, bool& is_array, int& type_ordinal) {
    is_struct = false;
    is_union = false;
    is_enum = false;
    is_ptr = mtype.is_ptr();
    is_array = mtype.is_array();
    type_ordinal = -1;

    // Get the base type (dereference pointers/arrays to find underlying type)
    tinfo_t base_type = mtype;
    if (mtype.is_ptr()) {
        base_type = mtype.get_pointed_object();
    } else if (mtype.is_array()) {
        base_type = mtype.get_array_element();
    }

    // Classify the base type
    is_struct = base_type.is_struct();
    is_union = base_type.is_union();
    is_enum = base_type.is_enum();

    // Try to get ordinal of the base type
    qstring type_name;
    if (base_type.get_type_name(&type_name) && !type_name.empty()) {
        type_ordinal = get_type_ordinal_by_name(ti, type_name.c_str());
    }
}

inline void collect_members(std::vector<MemberEntry>& rows) {
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

                        // Classify member type
                        classify_member_type(m.type, ti,
                            entry.mt_is_struct, entry.mt_is_union, entry.mt_is_enum,
                            entry.mt_is_ptr, entry.mt_is_array, entry.member_type_ordinal);

                        rows.push_back(std::move(entry));
                    }
                }
            }
        }
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

    void column(xsql::FunctionContext& ctx, int col) override {
        if (!valid_ || idx_ < 0 || static_cast<size_t>(idx_) >= udt_.size()) {
            ctx.result_null();
            return;
        }
        const udm_t& m = udt_[idx_];
        switch (col) {
            case 0: ctx.result_int(type_ordinal_); break;
            case 1: ctx.result_text(type_name_.c_str()); break;
            case 2: ctx.result_int(idx_); break;
            case 3: ctx.result_text(m.name.c_str()); break;
            case 4: ctx.result_int64(static_cast<int64_t>(m.offset / 8)); break;
            case 5: ctx.result_int64(static_cast<int64_t>(m.offset)); break;
            case 6: ctx.result_int64(static_cast<int64_t>(m.size / 8)); break;
            case 7: ctx.result_int64(static_cast<int64_t>(m.size)); break;
            case 8: {
                qstring type_str;
                m.type.print(&type_str);
                ctx.result_text(type_str.c_str());
                break;
            }
            case 9: ctx.result_int(m.is_bitfield() ? 1 : 0); break;
            case 10: ctx.result_int(m.is_baseclass() ? 1 : 0); break;
            case 11: ctx.result_text(m.cmt.c_str()); break;
            // Member type classification columns
            case 12: case 13: case 14: case 15: case 16: case 17: {
                // Classify the member type on-the-fly for iterator
                bool mt_is_struct, mt_is_union, mt_is_enum, mt_is_ptr, mt_is_array;
                int mt_ordinal;
                classify_member_type(m.type, get_idati(),
                    mt_is_struct, mt_is_union, mt_is_enum,
                    mt_is_ptr, mt_is_array, mt_ordinal);
                switch (col) {
                    case 12: ctx.result_int(mt_is_struct ? 1 : 0); break;
                    case 13: ctx.result_int(mt_is_union ? 1 : 0); break;
                    case 14: ctx.result_int(mt_is_enum ? 1 : 0); break;
                    case 15: ctx.result_int(mt_is_ptr ? 1 : 0); break;
                    case 16: ctx.result_int(mt_is_array ? 1 : 0); break;
                    case 17: ctx.result_int(mt_ordinal); break;
                }
                break;
            }
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(type_ordinal_) * 10000 + idx_;
    }
};

// Helper to get type and member by ordinal/index (for write operations)
struct TypeMemberRef {
    tinfo_t tif;
    udt_type_data_t udt;
    bool valid;
    uint32_t ordinal;

    TypeMemberRef(uint32_t ord) : valid(false), ordinal(ord) {
        til_t* ti = get_idati();
        if (!ti) return;
        if (tif.get_numbered_type(ti, ord)) {
            if (tif.is_struct() || tif.is_union()) {
                valid = tif.get_udt_details(&udt);
            }
        }
    }

    bool save() {
        if (!valid) return false;
        tinfo_t new_tif;
        new_tif.create_udt(udt, tif.is_union() ? BTF_UNION : BTF_STRUCT);
        return new_tif.set_numbered_type(get_idati(), ordinal, NTF_REPLACE, nullptr);
    }
};

inline bool build_member_entry(uint32_t ordinal, int member_index, MemberEntry& entry) {
    til_t* ti = get_idati();
    if (!ti) return false;

    const char* type_name = get_numbered_type_name(ti, ordinal);
    if (!type_name) return false;

    tinfo_t tif;
    if (!tif.get_numbered_type(ti, ordinal)) return false;
    if (!(tif.is_struct() || tif.is_union())) return false;

    udt_type_data_t udt;
    if (!tif.get_udt_details(&udt)) return false;
    if (member_index < 0 || static_cast<size_t>(member_index) >= udt.size()) return false;

    const udm_t& m = udt[member_index];
    entry.type_ordinal = ordinal;
    entry.type_name = type_name;
    entry.member_index = member_index;
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

    classify_member_type(m.type, ti,
        entry.mt_is_struct, entry.mt_is_union, entry.mt_is_enum,
        entry.mt_is_ptr, entry.mt_is_array, entry.member_type_ordinal);
    return true;
}

inline CachedTableDef<MemberEntry> define_types_members() {
    return cached_table<MemberEntry>("types_members")
        .no_shared_cache()
        .on_modify(ida_undo_hook)
        .estimate_rows([]() -> size_t {
            til_t* ti = get_idati();
            return ti ? static_cast<size_t>(get_ordinal_limit(ti)) * 8 : 0;
        })
        .cache_builder([](std::vector<MemberEntry>& rows) {
            collect_members(rows);
        })
        .row_populator([](MemberEntry& row, int argc, xsql::FunctionArg* argv) {
            if (argc > 2 && !argv[2].is_null()) row.type_ordinal = static_cast<uint32_t>(argv[2].as_int());
            if (argc > 4 && !argv[4].is_null()) row.member_index = argv[4].as_int();
        })
        .row_lookup([](MemberEntry& row, int64_t rowid) -> bool {
            if (rowid < 0) return false;
            uint32_t ordinal = static_cast<uint32_t>(rowid / 10000);
            int member_index = static_cast<int>(rowid % 10000);
            return build_member_entry(ordinal, member_index, row);
        })
        .column_int("type_ordinal", [](const MemberEntry& row) -> int {
            return static_cast<int>(row.type_ordinal);
        })
        .column_text("type_name", [](const MemberEntry& row) -> std::string {
            return row.type_name;
        })
        .column_int("member_index", [](const MemberEntry& row) -> int {
            return row.member_index;
        })
        .column_text_rw("member_name",
            [](const MemberEntry& row) -> std::string {
                return row.member_name;
            },
            [](MemberEntry& row, const char* new_name) -> bool {
                TypeMemberRef ref(row.type_ordinal);
                if (!ref.valid) return false;
                if (row.member_index < 0 || static_cast<size_t>(row.member_index) >= ref.udt.size()) return false;
                ref.udt[row.member_index].name = new_name ? new_name : "";
                bool ok = ref.save();
                if (ok) row.member_name = new_name ? new_name : "";
                return ok;
            })
        .column_int64("offset", [](const MemberEntry& row) -> int64_t {
            return row.offset;
        })
        .column_int64("offset_bits", [](const MemberEntry& row) -> int64_t {
            return row.offset_bits;
        })
        .column_int64("size", [](const MemberEntry& row) -> int64_t {
            return row.size;
        })
        .column_int64("size_bits", [](const MemberEntry& row) -> int64_t {
            return row.size_bits;
        })
        .column_text("member_type", [](const MemberEntry& row) -> std::string {
            return row.member_type;
        })
        .column_int("is_bitfield", [](const MemberEntry& row) -> int {
            return row.is_bitfield ? 1 : 0;
        })
        .column_int("is_baseclass", [](const MemberEntry& row) -> int {
            return row.is_baseclass ? 1 : 0;
        })
        .column_text_rw("comment",
            [](const MemberEntry& row) -> std::string {
                return row.comment;
            },
            [](MemberEntry& row, const char* new_comment) -> bool {
                TypeMemberRef ref(row.type_ordinal);
                if (!ref.valid) return false;
                if (row.member_index < 0 || static_cast<size_t>(row.member_index) >= ref.udt.size()) return false;
                ref.udt[row.member_index].cmt = new_comment ? new_comment : "";
                bool ok = ref.save();
                if (ok) row.comment = new_comment ? new_comment : "";
                return ok;
            })
        .column_int("mt_is_struct", [](const MemberEntry& row) -> int {
            return row.mt_is_struct ? 1 : 0;
        })
        .column_int("mt_is_union", [](const MemberEntry& row) -> int {
            return row.mt_is_union ? 1 : 0;
        })
        .column_int("mt_is_enum", [](const MemberEntry& row) -> int {
            return row.mt_is_enum ? 1 : 0;
        })
        .column_int("mt_is_ptr", [](const MemberEntry& row) -> int {
            return row.mt_is_ptr ? 1 : 0;
        })
        .column_int("mt_is_array", [](const MemberEntry& row) -> int {
            return row.mt_is_array ? 1 : 0;
        })
        .column_int("member_type_ordinal", [](const MemberEntry& row) -> int {
            return row.member_type_ordinal;
        })
        .deletable([](MemberEntry& row) -> bool {
            TypeMemberRef ref(row.type_ordinal);
            if (!ref.valid) return false;
            if (row.member_index < 0 || static_cast<size_t>(row.member_index) >= ref.udt.size()) return false;
            ref.udt.erase(ref.udt.begin() + row.member_index);
            return ref.save();
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            if (argc < 4
                || argv[0].is_null()
                || argv[3].is_null())
                return false;

            uint32_t ordinal = static_cast<uint32_t>(argv[0].as_int());
            const char* member_name = argv[3].as_c_str();
            if (!member_name || !member_name[0]) return false;

            TypeMemberRef ref(ordinal);
            if (!ref.valid) return false;

            udm_t new_member;
            new_member.name = member_name;
            std::string type_str = "int";
            if (argc > 8 && !argv[8].is_null()) {
                const char* mt = argv[8].as_c_str();
                if (mt && mt[0]) type_str = mt;
            }
            tinfo_t member_type;
            qstring parsed_name;
            if (parse_decl(&member_type, &parsed_name, nullptr,
                           (type_str + " x;").c_str(), PT_SIL)) {
                new_member.type = member_type;
                new_member.size = member_type.get_size() * 8;
            } else {
                new_member.type = tinfo_t(BT_INT32);
                new_member.size = 32;
            }
            if (argc > 11 && !argv[11].is_null()) {
                const char* cmt = argv[11].as_c_str();
                if (cmt) new_member.cmt = cmt;
            }
            if (!ref.udt.empty()) {
                const udm_t& last = ref.udt.back();
                new_member.offset = last.offset + last.size;
            } else {
                new_member.offset = 0;
            }

            ref.udt.push_back(new_member);
            return ref.save();
        })
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

inline void collect_enum_values(std::vector<EnumValueEntry>& rows) {
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
                        rows.push_back(std::move(entry));
                    }
                }
            }
        }
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

    void column(xsql::FunctionContext& ctx, int col) override {
        if (!valid_ || idx_ < 0 || static_cast<size_t>(idx_) >= ei_.size()) {
            ctx.result_null();
            return;
        }
        const edm_t& e = ei_[idx_];
        switch (col) {
            case 0: ctx.result_int(type_ordinal_); break;
            case 1: ctx.result_text(type_name_.c_str()); break;
            case 2: ctx.result_int(idx_); break;
            case 3: ctx.result_text(e.name.c_str()); break;
            case 4: ctx.result_int64(static_cast<int64_t>(e.value)); break;
            case 5: ctx.result_int64(static_cast<int64_t>(e.value)); break;  // uvalue
            case 6: ctx.result_text(e.cmt.c_str()); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(type_ordinal_) * 10000 + idx_;
    }
};

// Helper to get enum type by ordinal (for write operations)
struct EnumTypeRef {
    tinfo_t tif;
    enum_type_data_t ei;
    bool valid;
    uint32_t ordinal;

    EnumTypeRef(uint32_t ord) : valid(false), ordinal(ord) {
        til_t* ti = get_idati();
        if (!ti) return;
        if (tif.get_numbered_type(ti, ord)) {
            if (tif.is_enum()) {
                valid = tif.get_enum_details(&ei);
            }
        }
    }

    bool save() {
        if (!valid) return false;
        tinfo_t new_tif;
        new_tif.create_enum(ei);
        return new_tif.set_numbered_type(get_idati(), ordinal, NTF_REPLACE, nullptr);
    }
};

inline bool build_enum_value_entry(uint32_t ordinal, int value_index, EnumValueEntry& entry) {
    til_t* ti = get_idati();
    if (!ti) return false;
    const char* type_name = get_numbered_type_name(ti, ordinal);
    if (!type_name) return false;

    tinfo_t tif;
    if (!tif.get_numbered_type(ti, ordinal)) return false;
    if (!tif.is_enum()) return false;

    enum_type_data_t ei;
    if (!tif.get_enum_details(&ei)) return false;
    if (value_index < 0 || static_cast<size_t>(value_index) >= ei.size()) return false;

    const edm_t& e = ei[value_index];
    entry.type_ordinal = ordinal;
    entry.type_name = type_name;
    entry.value_index = value_index;
    entry.value_name = e.name.c_str();
    entry.value = static_cast<int64_t>(e.value);
    entry.uvalue = e.value;
    entry.comment = e.cmt.c_str();
    return true;
}

inline CachedTableDef<EnumValueEntry> define_types_enum_values() {
    return cached_table<EnumValueEntry>("types_enum_values")
        .no_shared_cache()
        .on_modify(ida_undo_hook)
        .estimate_rows([]() -> size_t {
            til_t* ti = get_idati();
            return ti ? static_cast<size_t>(get_ordinal_limit(ti)) * 8 : 0;
        })
        .cache_builder([](std::vector<EnumValueEntry>& rows) {
            collect_enum_values(rows);
        })
        .row_populator([](EnumValueEntry& row, int argc, xsql::FunctionArg* argv) {
            if (argc > 2 && !argv[2].is_null()) row.type_ordinal = static_cast<uint32_t>(argv[2].as_int());
            if (argc > 4 && !argv[4].is_null()) row.value_index = argv[4].as_int();
        })
        .row_lookup([](EnumValueEntry& row, int64_t rowid) -> bool {
            if (rowid < 0) return false;
            uint32_t ordinal = static_cast<uint32_t>(rowid / 10000);
            int value_index = static_cast<int>(rowid % 10000);
            return build_enum_value_entry(ordinal, value_index, row);
        })
        .column_int("type_ordinal", [](const EnumValueEntry& row) -> int {
            return static_cast<int>(row.type_ordinal);
        })
        .column_text("type_name", [](const EnumValueEntry& row) -> std::string {
            return row.type_name;
        })
        .column_int("value_index", [](const EnumValueEntry& row) -> int {
            return row.value_index;
        })
        .column_text_rw("value_name",
            [](const EnumValueEntry& row) -> std::string {
                return row.value_name;
            },
            [](EnumValueEntry& row, const char* new_name) -> bool {
                EnumTypeRef ref(row.type_ordinal);
                if (!ref.valid) return false;
                if (row.value_index < 0 || static_cast<size_t>(row.value_index) >= ref.ei.size()) return false;
                ref.ei[row.value_index].name = new_name ? new_name : "";
                bool ok = ref.save();
                if (ok) row.value_name = new_name ? new_name : "";
                return ok;
            })
        .column_int64_rw("value",
            [](const EnumValueEntry& row) -> int64_t {
                return row.value;
            },
            [](EnumValueEntry& row, int64_t new_value) -> bool {
                EnumTypeRef ref(row.type_ordinal);
                if (!ref.valid) return false;
                if (row.value_index < 0 || static_cast<size_t>(row.value_index) >= ref.ei.size()) return false;
                ref.ei[row.value_index].value = static_cast<uint64_t>(new_value);
                bool ok = ref.save();
                if (ok) {
                    row.value = new_value;
                    row.uvalue = static_cast<uint64_t>(new_value);
                }
                return ok;
            })
        .column_int64("uvalue", [](const EnumValueEntry& row) -> int64_t {
            return static_cast<int64_t>(row.uvalue);
        })
        .column_text_rw("comment",
            [](const EnumValueEntry& row) -> std::string {
                return row.comment;
            },
            [](EnumValueEntry& row, const char* new_comment) -> bool {
                EnumTypeRef ref(row.type_ordinal);
                if (!ref.valid) return false;
                if (row.value_index < 0 || static_cast<size_t>(row.value_index) >= ref.ei.size()) return false;
                ref.ei[row.value_index].cmt = new_comment ? new_comment : "";
                bool ok = ref.save();
                if (ok) row.comment = new_comment ? new_comment : "";
                return ok;
            })
        .deletable([](EnumValueEntry& row) -> bool {
            EnumTypeRef ref(row.type_ordinal);
            if (!ref.valid) return false;
            if (row.value_index < 0 || static_cast<size_t>(row.value_index) >= ref.ei.size()) return false;
            ref.ei.erase(ref.ei.begin() + row.value_index);
            return ref.save();
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            if (argc < 4
                || argv[0].is_null()
                || argv[3].is_null())
                return false;

            uint32_t ordinal = static_cast<uint32_t>(argv[0].as_int());
            const char* value_name = argv[3].as_c_str();
            if (!value_name || !value_name[0]) return false;

            EnumTypeRef ref(ordinal);
            if (!ref.valid) return false;

            edm_t new_edm;
            new_edm.name = value_name;
            if (argc > 4 && !argv[4].is_null()) {
                new_edm.value = static_cast<uint64_t>(argv[4].as_int64());
            } else {
                if (!ref.ei.empty()) {
                    new_edm.value = ref.ei.back().value + 1;
                } else {
                    new_edm.value = 0;
                }
            }
            if (argc > 6 && !argv[6].is_null()) {
                const char* cmt = argv[6].as_c_str();
                if (cmt) new_edm.cmt = cmt;
            }

            ref.ei.push_back(new_edm);
            return ref.save();
        })
        .filter_eq("type_ordinal", [](int64_t ordinal) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<EnumValuesInTypeIterator>(static_cast<uint32_t>(ordinal));
        }, 10.0, 10.0)
        .build();
}

// ============================================================================
// TYPES_FUNC_ARGS Table - Function prototype arguments
// ============================================================================

// Type classification info (surface + resolved)
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

// Get pointer depth (int** -> 2, int* -> 1, int -> 0)
inline int get_ptr_depth(tinfo_t tif) {
    int depth = 0;
    while (tif.is_ptr()) {
        depth++;
        tif = tif.get_pointed_object();
    }
    return depth;
}

// Get base type name (strips pointers/arrays)
inline std::string get_base_type_name(tinfo_t tif) {
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
inline void classify_tinfo(const tinfo_t& tif,
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
inline bool is_surface_typedef(const tinfo_t& tif) {
    return tif.is_typeref();
}

// Classify surface-level type (WITHOUT typedef resolution)
// If tif is a typedef, surface classification shows it as "other" not the underlying type
inline void classify_surface(const tinfo_t& tif,
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
inline TypeClassification classify_arg_type(const tinfo_t& tif) {
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

inline void collect_func_args(std::vector<FuncArgEntry>& rows) {
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
        // idx=-1 is return type, idx=0..fi_.size()-1 are arguments
        valid_ = (idx_ == -1) || (idx_ >= 0 && static_cast<size_t>(idx_) < fi_.size());
        return valid_;
    }

    bool eof() const override {
        return idx_ >= -1 && !valid_;
    }

    void column(xsql::FunctionContext& ctx, int col) override {
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

    int64_t rowid() const override {
        return static_cast<int64_t>(type_ordinal_) * 10000 + (idx_ + 1);
    }
};

inline CachedTableDef<FuncArgEntry> define_types_func_args() {
    return cached_table<FuncArgEntry>("types_func_args")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            til_t* ti = get_idati();
            return ti ? static_cast<size_t>(get_ordinal_limit(ti)) * 4 : 0;
        })
        .cache_builder([](std::vector<FuncArgEntry>& rows) {
            collect_func_args(rows);
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
            return std::make_unique<FuncArgsInTypeIterator>(static_cast<uint32_t>(ordinal));
        }, 10.0, 5.0)
        .build();
}

// ============================================================================
// Types Registry
// ============================================================================

struct TypesRegistry {
    CachedTableDef<TypeEntry> types;
    CachedTableDef<MemberEntry> types_members;
    CachedTableDef<EnumValueEntry> types_enum_values;
    CachedTableDef<FuncArgEntry> types_func_args;

    TypesRegistry()
        : types(define_types())
        , types_members(define_types_members())
        , types_enum_values(define_types_enum_values())
        , types_func_args(define_types_func_args())
    {}

    void register_all(xsql::Database& db) {
        db.register_cached_table("ida_types", &types);
        db.create_table("types", "ida_types");

        db.register_cached_table("ida_types_members", &types_members);
        db.create_table("types_members", "ida_types_members");

        db.register_cached_table("ida_types_enum_values", &types_enum_values);
        db.create_table("types_enum_values", "ida_types_enum_values");

        db.register_cached_table("ida_types_func_args", &types_func_args);
        db.create_table("types_func_args", "ida_types_func_args");

        // Create views
        create_views(db);
    }

private:
    void create_views(xsql::Database& db) {
        // Filtering views
        db.exec("CREATE VIEW IF NOT EXISTS types_v_structs AS SELECT * FROM types WHERE is_struct = 1");
        db.exec("CREATE VIEW IF NOT EXISTS types_v_unions AS SELECT * FROM types WHERE is_union = 1");
        db.exec("CREATE VIEW IF NOT EXISTS types_v_enums AS SELECT * FROM types WHERE is_enum = 1");
        db.exec("CREATE VIEW IF NOT EXISTS types_v_typedefs AS SELECT * FROM types WHERE is_typedef = 1");
        db.exec("CREATE VIEW IF NOT EXISTS types_v_funcs AS SELECT * FROM types WHERE is_func = 1");
    }
};

} // namespace types
} // namespace idasql


