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

inline std::vector<TypeEntry>& get_types_cache() {
    static std::vector<TypeEntry> cache;
    return cache;
}

inline void rebuild_types_cache() {
    auto& cache = get_types_cache();
    cache.clear();

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

        cache.push_back(entry);
    }
}

// ============================================================================
// TYPES Table - All local types (enhanced)
// ============================================================================

inline VTableDef define_types() {
    return table("types")
        .on_modify(ida_undo_hook)
        .count([]() {
            rebuild_types_cache();
            return get_types_cache().size();
        })
        .column_int("ordinal", [](size_t i) -> int {
            auto& cache = get_types_cache();
            return i < cache.size() ? cache[i].ordinal : 0;
        })
        .column_text_rw("name",
            // Getter
            [](size_t i) -> std::string {
                auto& cache = get_types_cache();
                return i < cache.size() ? cache[i].name : "";
            },
            // Setter - rename type
            [](size_t i, const char* new_name) -> bool {
                auto& cache = get_types_cache();
                if (i >= cache.size()) return false;

                til_t* ti = get_idati();
                if (!ti) return false;

                // Get the type
                tinfo_t tif;
                if (!tif.get_numbered_type(ti, cache[i].ordinal)) return false;

                // Rename it using tinfo_t::rename_type()
                return tif.rename_type(new_name) == TERR_OK;
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
        .deletable([](size_t i) -> bool {
            auto& cache = get_types_cache();
            if (i >= cache.size()) return false;

            til_t* ti = get_idati();
            if (!ti) return false;

            return del_numbered_type(ti, cache[i].ordinal);
        })
        .insertable([](int argc, sqlite3_value** argv) -> bool {
            // Column layout: ordinal(0), name(1), kind(2), ...
            // name (col 1) is required
            if (argc < 2 || sqlite3_value_type(argv[1]) == SQLITE_NULL)
                return false;

            const char* name = reinterpret_cast<const char*>(
                sqlite3_value_text(argv[1]));
            if (!name || !name[0]) return false;

            // kind (col 2): defaults to "struct"
            std::string kind = "struct";
            if (argc > 2 && sqlite3_value_type(argv[2]) != SQLITE_NULL) {
                const char* k = reinterpret_cast<const char*>(
                    sqlite3_value_text(argv[2]));
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

inline std::vector<MemberEntry>& get_members_cache() {
    static std::vector<MemberEntry> cache;
    return cache;
}

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

inline void rebuild_members_cache() {
    auto& cache = get_members_cache();
    cache.clear();

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

                        cache.push_back(entry);
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
            // Member type classification columns
            case 12: case 13: case 14: case 15: case 16: case 17: {
                // Classify the member type on-the-fly for iterator
                bool mt_is_struct, mt_is_union, mt_is_enum, mt_is_ptr, mt_is_array;
                int mt_ordinal;
                classify_member_type(m.type, get_idati(),
                    mt_is_struct, mt_is_union, mt_is_enum,
                    mt_is_ptr, mt_is_array, mt_ordinal);
                switch (col) {
                    case 12: sqlite3_result_int(ctx, mt_is_struct ? 1 : 0); break;
                    case 13: sqlite3_result_int(ctx, mt_is_union ? 1 : 0); break;
                    case 14: sqlite3_result_int(ctx, mt_is_enum ? 1 : 0); break;
                    case 15: sqlite3_result_int(ctx, mt_is_ptr ? 1 : 0); break;
                    case 16: sqlite3_result_int(ctx, mt_is_array ? 1 : 0); break;
                    case 17: sqlite3_result_int(ctx, mt_ordinal); break;
                }
                break;
            }
            default: sqlite3_result_null(ctx); break;
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

inline VTableDef define_types_members() {
    return table("types_members")
        .on_modify(ida_undo_hook)
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
        .column_text_rw("member_name",
            // Getter
            [](size_t i) -> std::string {
                auto& cache = get_members_cache();
                return i < cache.size() ? cache[i].member_name : "";
            },
            // Setter - rename member
            [](size_t i, const char* new_name) -> bool {
                auto& cache = get_members_cache();
                if (i >= cache.size()) return false;

                TypeMemberRef ref(cache[i].type_ordinal);
                if (!ref.valid) return false;

                int idx = cache[i].member_index;
                if (idx < 0 || static_cast<size_t>(idx) >= ref.udt.size()) return false;

                ref.udt[idx].name = new_name;
                return ref.save();
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
        .column_text_rw("comment",
            // Getter
            [](size_t i) -> std::string {
                auto& cache = get_members_cache();
                return i < cache.size() ? cache[i].comment : "";
            },
            // Setter - update member comment
            [](size_t i, const char* new_comment) -> bool {
                auto& cache = get_members_cache();
                if (i >= cache.size()) return false;

                TypeMemberRef ref(cache[i].type_ordinal);
                if (!ref.valid) return false;

                int idx = cache[i].member_index;
                if (idx < 0 || static_cast<size_t>(idx) >= ref.udt.size()) return false;

                ref.udt[idx].cmt = new_comment;
                return ref.save();
            })
        // Member type classification columns (for efficient filtering)
        .column_int("mt_is_struct", [](size_t i) -> int {
            auto& cache = get_members_cache();
            return i < cache.size() ? (cache[i].mt_is_struct ? 1 : 0) : 0;
        })
        .column_int("mt_is_union", [](size_t i) -> int {
            auto& cache = get_members_cache();
            return i < cache.size() ? (cache[i].mt_is_union ? 1 : 0) : 0;
        })
        .column_int("mt_is_enum", [](size_t i) -> int {
            auto& cache = get_members_cache();
            return i < cache.size() ? (cache[i].mt_is_enum ? 1 : 0) : 0;
        })
        .column_int("mt_is_ptr", [](size_t i) -> int {
            auto& cache = get_members_cache();
            return i < cache.size() ? (cache[i].mt_is_ptr ? 1 : 0) : 0;
        })
        .column_int("mt_is_array", [](size_t i) -> int {
            auto& cache = get_members_cache();
            return i < cache.size() ? (cache[i].mt_is_array ? 1 : 0) : 0;
        })
        .column_int("member_type_ordinal", [](size_t i) -> int {
            auto& cache = get_members_cache();
            return i < cache.size() ? cache[i].member_type_ordinal : -1;
        })
        .deletable([](size_t i) -> bool {
            auto& cache = get_members_cache();
            if (i >= cache.size()) return false;

            TypeMemberRef ref(cache[i].type_ordinal);
            if (!ref.valid) return false;

            int idx = cache[i].member_index;
            if (idx < 0 || static_cast<size_t>(idx) >= ref.udt.size()) return false;

            ref.udt.erase(ref.udt.begin() + idx);
            return ref.save();
        })
        .insertable([](int argc, sqlite3_value** argv) -> bool {
            // Column layout: type_ordinal(0), type_name(1), member_index(2),
            //                 member_name(3), offset(4), ..., member_type(8), ..., comment(11)
            // type_ordinal (col 0) and member_name (col 3) are required
            if (argc < 4
                || sqlite3_value_type(argv[0]) == SQLITE_NULL
                || sqlite3_value_type(argv[3]) == SQLITE_NULL)
                return false;

            uint32_t ordinal = static_cast<uint32_t>(sqlite3_value_int(argv[0]));
            const char* member_name = reinterpret_cast<const char*>(
                sqlite3_value_text(argv[3]));
            if (!member_name || !member_name[0]) return false;

            TypeMemberRef ref(ordinal);
            if (!ref.valid) return false;

            // Build the new member
            udm_t new_member;
            new_member.name = member_name;

            // member_type (col 8): parse type string, default to "int"
            std::string type_str = "int";
            if (argc > 8 && sqlite3_value_type(argv[8]) != SQLITE_NULL) {
                const char* mt = reinterpret_cast<const char*>(
                    sqlite3_value_text(argv[8]));
                if (mt && mt[0]) type_str = mt;
            }

            // Parse the type string into a tinfo_t
            tinfo_t member_type;
            qstring parsed_name;
            if (parse_decl(&member_type, &parsed_name, nullptr,
                           (type_str + " x;").c_str(), PT_SIL)) {
                new_member.type = member_type;
                new_member.size = member_type.get_size() * 8;  // size in bits
            } else {
                // Fallback: default to int (4 bytes)
                new_member.type = tinfo_t(BT_INT32);
                new_member.size = 32;
            }

            // comment (col 11)
            if (argc > 11 && sqlite3_value_type(argv[11]) != SQLITE_NULL) {
                const char* cmt = reinterpret_cast<const char*>(
                    sqlite3_value_text(argv[11]));
                if (cmt) new_member.cmt = cmt;
            }

            // Compute offset: append after last member
            if (!ref.udt.empty()) {
                const udm_t& last = ref.udt.back();
                new_member.offset = last.offset + last.size;
            } else {
                new_member.offset = 0;
            }

            ref.udt.push_back(new_member);
            return ref.save();
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
                        cache.push_back(entry);
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

inline VTableDef define_types_enum_values() {
    return table("types_enum_values")
        .on_modify(ida_undo_hook)
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
        .column_text_rw("value_name",
            // Getter
            [](size_t i) -> std::string {
                auto& cache = get_enum_values_cache();
                return i < cache.size() ? cache[i].value_name : "";
            },
            // Setter - rename enum value
            [](size_t i, const char* new_name) -> bool {
                auto& cache = get_enum_values_cache();
                if (i >= cache.size()) return false;

                EnumTypeRef ref(cache[i].type_ordinal);
                if (!ref.valid) return false;

                int idx = cache[i].value_index;
                if (idx < 0 || static_cast<size_t>(idx) >= ref.ei.size()) return false;

                ref.ei[idx].name = new_name;
                return ref.save();
            })
        .column_int64_rw("value",
            // Getter
            [](size_t i) -> int64_t {
                auto& cache = get_enum_values_cache();
                return i < cache.size() ? cache[i].value : 0;
            },
            // Setter - change enum value
            [](size_t i, int64_t new_value) -> bool {
                auto& cache = get_enum_values_cache();
                if (i >= cache.size()) return false;

                EnumTypeRef ref(cache[i].type_ordinal);
                if (!ref.valid) return false;

                int idx = cache[i].value_index;
                if (idx < 0 || static_cast<size_t>(idx) >= ref.ei.size()) return false;

                ref.ei[idx].value = static_cast<uint64_t>(new_value);
                return ref.save();
            })
        .column_int64("uvalue", [](size_t i) -> int64_t {
            auto& cache = get_enum_values_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].uvalue) : 0;
        })
        .column_text_rw("comment",
            // Getter
            [](size_t i) -> std::string {
                auto& cache = get_enum_values_cache();
                return i < cache.size() ? cache[i].comment : "";
            },
            // Setter - update enum value comment
            [](size_t i, const char* new_comment) -> bool {
                auto& cache = get_enum_values_cache();
                if (i >= cache.size()) return false;

                EnumTypeRef ref(cache[i].type_ordinal);
                if (!ref.valid) return false;

                int idx = cache[i].value_index;
                if (idx < 0 || static_cast<size_t>(idx) >= ref.ei.size()) return false;

                ref.ei[idx].cmt = new_comment;
                return ref.save();
            })
        .deletable([](size_t i) -> bool {
            auto& cache = get_enum_values_cache();
            if (i >= cache.size()) return false;

            EnumTypeRef ref(cache[i].type_ordinal);
            if (!ref.valid) return false;

            int idx = cache[i].value_index;
            if (idx < 0 || static_cast<size_t>(idx) >= ref.ei.size()) return false;

            ref.ei.erase(ref.ei.begin() + idx);
            return ref.save();
        })
        .insertable([](int argc, sqlite3_value** argv) -> bool {
            // Column layout: type_ordinal(0), type_name(1), value_index(2),
            //                 value_name(3), value(4), uvalue(5), comment(6)
            // type_ordinal (col 0) and value_name (col 3) are required
            if (argc < 4
                || sqlite3_value_type(argv[0]) == SQLITE_NULL
                || sqlite3_value_type(argv[3]) == SQLITE_NULL)
                return false;

            uint32_t ordinal = static_cast<uint32_t>(sqlite3_value_int(argv[0]));
            const char* value_name = reinterpret_cast<const char*>(
                sqlite3_value_text(argv[3]));
            if (!value_name || !value_name[0]) return false;

            EnumTypeRef ref(ordinal);
            if (!ref.valid) return false;

            // Build the new enum member
            edm_t new_edm;
            new_edm.name = value_name;

            // value (col 4): default to 0
            if (argc > 4 && sqlite3_value_type(argv[4]) != SQLITE_NULL) {
                new_edm.value = static_cast<uint64_t>(sqlite3_value_int64(argv[4]));
            } else {
                // Auto-assign: next value after last member
                if (!ref.ei.empty()) {
                    new_edm.value = ref.ei.back().value + 1;
                } else {
                    new_edm.value = 0;
                }
            }

            // comment (col 6)
            if (argc > 6 && sqlite3_value_type(argv[6]) != SQLITE_NULL) {
                const char* cmt = reinterpret_cast<const char*>(
                    sqlite3_value_text(argv[6]));
                if (cmt) new_edm.cmt = cmt;
            }

            ref.ei.push_back(new_edm);
            return ref.save();
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
                        entry.tc = classify_arg_type(a.type);
                        // calling_conv only on return type row
                        cache.push_back(entry);
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

        // Get the type for classification (computed on-the-fly for iterator)
        auto get_current_type = [&]() -> tinfo_t {
            if (idx_ == -1) return fi_.rettype;
            if (static_cast<size_t>(idx_) < fi_.size()) return fi_[idx_].type;
            return tinfo_t();
        };

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
            // Type classification columns (computed on-the-fly)
            case 6: case 7: case 8: case 9: case 10: case 11: case 12: case 13: case 14:
            case 15: case 16: case 17: case 18: case 19: case 20: case 21: {
                TypeClassification tc = classify_arg_type(get_current_type());
                switch (col) {
                    case 6:  sqlite3_result_int(ctx, tc.is_ptr ? 1 : 0); break;
                    case 7:  sqlite3_result_int(ctx, tc.is_int ? 1 : 0); break;
                    case 8:  sqlite3_result_int(ctx, tc.is_integral ? 1 : 0); break;
                    case 9:  sqlite3_result_int(ctx, tc.is_float ? 1 : 0); break;
                    case 10: sqlite3_result_int(ctx, tc.is_void ? 1 : 0); break;
                    case 11: sqlite3_result_int(ctx, tc.is_struct ? 1 : 0); break;
                    case 12: sqlite3_result_int(ctx, tc.is_array ? 1 : 0); break;
                    case 13: sqlite3_result_int(ctx, tc.ptr_depth); break;
                    case 14: sqlite3_result_text(ctx, tc.base_type.c_str(), -1, SQLITE_TRANSIENT); break;
                    case 15: sqlite3_result_int(ctx, tc.is_ptr_resolved ? 1 : 0); break;
                    case 16: sqlite3_result_int(ctx, tc.is_int_resolved ? 1 : 0); break;
                    case 17: sqlite3_result_int(ctx, tc.is_integral_resolved ? 1 : 0); break;
                    case 18: sqlite3_result_int(ctx, tc.is_float_resolved ? 1 : 0); break;
                    case 19: sqlite3_result_int(ctx, tc.is_void_resolved ? 1 : 0); break;
                    case 20: sqlite3_result_int(ctx, tc.ptr_depth_resolved); break;
                    case 21: sqlite3_result_text(ctx, tc.base_type_resolved.c_str(), -1, SQLITE_TRANSIENT); break;
                }
                break;
            }
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
        // Surface-level type classification
        .column_int("is_ptr", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? (cache[i].tc.is_ptr ? 1 : 0) : 0;
        })
        .column_int("is_int", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? (cache[i].tc.is_int ? 1 : 0) : 0;
        })
        .column_int("is_integral", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? (cache[i].tc.is_integral ? 1 : 0) : 0;
        })
        .column_int("is_float", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? (cache[i].tc.is_float ? 1 : 0) : 0;
        })
        .column_int("is_void", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? (cache[i].tc.is_void ? 1 : 0) : 0;
        })
        .column_int("is_struct", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? (cache[i].tc.is_struct ? 1 : 0) : 0;
        })
        .column_int("is_array", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? (cache[i].tc.is_array ? 1 : 0) : 0;
        })
        .column_int("ptr_depth", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? cache[i].tc.ptr_depth : 0;
        })
        .column_text("base_type", [](size_t i) -> std::string {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? cache[i].tc.base_type : "";
        })
        // Resolved type classification (after typedef resolution)
        .column_int("is_ptr_resolved", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? (cache[i].tc.is_ptr_resolved ? 1 : 0) : 0;
        })
        .column_int("is_int_resolved", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? (cache[i].tc.is_int_resolved ? 1 : 0) : 0;
        })
        .column_int("is_integral_resolved", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? (cache[i].tc.is_integral_resolved ? 1 : 0) : 0;
        })
        .column_int("is_float_resolved", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? (cache[i].tc.is_float_resolved ? 1 : 0) : 0;
        })
        .column_int("is_void_resolved", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? (cache[i].tc.is_void_resolved ? 1 : 0) : 0;
        })
        .column_int("ptr_depth_resolved", [](size_t i) -> int {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? cache[i].tc.ptr_depth_resolved : 0;
        })
        .column_text("base_type_resolved", [](size_t i) -> std::string {
            auto& cache = get_func_args_cache();
            return i < cache.size() ? cache[i].tc.base_type_resolved : "";
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

    void register_all(xsql::Database& db) {
        // Register tables
        db.register_table("ida_types", &types);
        db.create_table("types", "ida_types");

        db.register_table("ida_types_members", &types_members);
        db.create_table("types_members", "ida_types_members");

        db.register_table("ida_types_enum_values", &types_enum_values);
        db.create_table("types_enum_values", "ida_types_enum_values");

        db.register_table("ida_types_func_args", &types_func_args);
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
