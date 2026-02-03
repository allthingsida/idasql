/**
 * entities_search.hpp - Table-valued function for unified entity search
 *
 * Provides the `jump_entities` virtual table for "Jump to Anything" functionality.
 * This is an eponymous virtual table that acts like a table-valued function:
 *
 *   SELECT * FROM jump_entities('pattern', 'mode') LIMIT 10;
 *
 * Or equivalently:
 *
 *   SELECT * FROM jump_entities WHERE pattern = 'main' AND mode = 'prefix' LIMIT 10;
 *
 * Parameters:
 *   pattern - Search pattern (required)
 *   mode    - 'prefix' (LIKE 'x%') or 'contains' (LIKE '%x%')
 *
 * Columns returned:
 *   name        - Entity name
 *   kind        - 'function', 'label', 'segment', 'struct', 'union', 'enum', 'member', 'enum_member'
 *   address     - Address (for functions, labels, segments) or NULL
 *   ordinal     - Type ordinal (for types, members) or NULL
 *   parent_name - Parent type name (for members) or NULL
 *   full_name   - Fully qualified name (parent.member for members)
 *
 * The table lazily iterates through source tables, stopping when LIMIT is reached.
 */

#pragma once

#include <sqlite3.h>
#include <xsql/database.hpp>
#include <string>
#include <cstring>
#include <cctype>
#include <algorithm>

// macOS: Undefine Mach kernel types before IDA headers
// (system headers define processor_t and token_t as typedefs)
#ifdef __APPLE__
#undef processor_t
#undef token_t
#endif

// IDA SDK
#include <ida.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>

namespace idasql {
namespace search {

// ============================================================================
// Entity Sources - each represents one category of searchable entities
// ============================================================================

enum class EntitySource {
    Functions = 0,
    Labels,
    Segments,
    Structs,
    Unions,
    Enums,
    Members,
    EnumMembers,
    Done
};

// ============================================================================
// Entity Row - one result row
// ============================================================================

struct EntityRow {
    std::string name;
    std::string kind;
    ea_t address = BADADDR;
    uint32 ordinal = 0;
    std::string parent_name;
    std::string full_name;
    bool has_address = false;
    bool has_ordinal = false;
};

// ============================================================================
// Entity Generator - iterates through all matching entities
// ============================================================================

class EntityGenerator {
    std::string pattern_;
    bool contains_mode_;

    EntitySource current_source_ = EntitySource::Functions;
    size_t current_index_ = 0;
    EntityRow current_row_;
    bool has_current_ = false;

    // For type iteration
    uint32 type_ordinal_ = 0;
    size_t member_index_ = 0;
    tinfo_t current_type_;

public:
    EntityGenerator(const std::string& pattern, bool contains_mode)
        : pattern_(to_lower(pattern)), contains_mode_(contains_mode) {}

    bool next() {
        has_current_ = false;

        while (current_source_ != EntitySource::Done) {
            if (advance_current_source()) {
                has_current_ = true;
                return true;
            }
            // Move to next source
            current_source_ = static_cast<EntitySource>(static_cast<int>(current_source_) + 1);
            current_index_ = 0;
            type_ordinal_ = 0;
            member_index_ = 0;
        }
        return false;
    }

    const EntityRow& current() const { return current_row_; }
    bool eof() const { return !has_current_ && current_source_ == EntitySource::Done; }

private:
    static std::string to_lower(const std::string& s) {
        std::string result;
        result.reserve(s.size());
        for (char c : s) {
            result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return result;
    }

    bool matches(const std::string& name) const {
        std::string lower_name = to_lower(name);
        if (contains_mode_) {
            return lower_name.find(pattern_) != std::string::npos;
        } else {
            return lower_name.compare(0, pattern_.size(), pattern_) == 0;
        }
    }

    bool advance_current_source() {
        switch (current_source_) {
            case EntitySource::Functions:  return advance_functions();
            case EntitySource::Labels:     return advance_labels();
            case EntitySource::Segments:   return advance_segments();
            case EntitySource::Structs:    return advance_structs();
            case EntitySource::Unions:     return advance_unions();
            case EntitySource::Enums:      return advance_enums();
            case EntitySource::Members:    return advance_members();
            case EntitySource::EnumMembers: return advance_enum_members();
            case EntitySource::Done:       return false;
        }
        return false;
    }

    bool advance_functions() {
        size_t count = get_func_qty();
        while (current_index_ < count) {
            func_t* fn = getn_func(current_index_++);
            if (!fn) continue;

            qstring name;
            if (get_func_name(&name, fn->start_ea) <= 0) continue;

            std::string name_str(name.c_str());
            if (matches(name_str)) {
                current_row_.name = name_str;
                current_row_.kind = "function";
                current_row_.address = fn->start_ea;
                current_row_.has_address = true;
                current_row_.has_ordinal = false;
                current_row_.parent_name.clear();
                current_row_.full_name = name_str;
                return true;
            }
        }
        return false;
    }

    bool advance_labels() {
        // Iterate named locations that aren't function starts
        // Use get_nlist_size/get_nlist_ea/get_nlist_name
        size_t count = get_nlist_size();
        while (current_index_ < count) {
            ea_t ea = get_nlist_ea(current_index_);
            const char* name = get_nlist_name(current_index_);
            current_index_++;

            if (!name || !*name) continue;

            // Skip if it's a function start
            func_t* fn = get_func(ea);
            if (fn && fn->start_ea == ea) continue;

            std::string name_str(name);
            if (matches(name_str)) {
                current_row_.name = name_str;
                current_row_.kind = "label";
                current_row_.address = ea;
                current_row_.has_address = true;
                current_row_.has_ordinal = false;
                current_row_.parent_name.clear();
                current_row_.full_name = name_str;
                return true;
            }
        }
        return false;
    }

    bool advance_segments() {
        int count = get_segm_qty();
        while (static_cast<int>(current_index_) < count) {
            segment_t* seg = getnseg(static_cast<int>(current_index_++));
            if (!seg) continue;

            qstring name;
            if (get_segm_name(&name, seg) <= 0) continue;

            std::string name_str(name.c_str());
            if (matches(name_str)) {
                current_row_.name = name_str;
                current_row_.kind = "segment";
                current_row_.address = seg->start_ea;
                current_row_.has_address = true;
                current_row_.has_ordinal = false;
                current_row_.parent_name.clear();
                current_row_.full_name = name_str;
                return true;
            }
        }
        return false;
    }

    bool advance_types_of_kind(const char* kind, bool want_struct, bool want_union, bool want_enum) {
        uint32 count = get_ordinal_count(nullptr);
        while (type_ordinal_ < count) {
            uint32 ord = type_ordinal_++;
            tinfo_t tif;
            if (!tif.get_numbered_type(nullptr, ord)) continue;

            bool is_struct = tif.is_struct();
            bool is_union = tif.is_union();
            bool is_enum = tif.is_enum();

            if (want_struct && !is_struct) continue;
            if (want_union && !is_union) continue;
            if (want_enum && !is_enum) continue;

            qstring name;
            if (!tif.get_type_name(&name)) continue;

            std::string name_str(name.c_str());
            if (matches(name_str)) {
                current_row_.name = name_str;
                current_row_.kind = kind;
                current_row_.has_address = false;
                current_row_.ordinal = ord;
                current_row_.has_ordinal = true;
                current_row_.parent_name.clear();
                current_row_.full_name = name_str;
                return true;
            }
        }
        return false;
    }

    bool advance_structs() {
        return advance_types_of_kind("struct", true, false, false);
    }

    bool advance_unions() {
        return advance_types_of_kind("union", false, true, false);
    }

    bool advance_enums() {
        return advance_types_of_kind("enum", false, false, true);
    }

    bool advance_members() {
        // Iterate struct/union members
        uint32 count = get_ordinal_count(nullptr);

        while (type_ordinal_ < count) {
            // Get current type if not already loaded
            if (!current_type_.get_numbered_type(nullptr, type_ordinal_)) {
                type_ordinal_++;
                member_index_ = 0;
                continue;
            }

            if (!current_type_.is_struct() && !current_type_.is_union()) {
                type_ordinal_++;
                member_index_ = 0;
                continue;
            }

            udt_type_data_t udt;
            if (!current_type_.get_udt_details(&udt)) {
                type_ordinal_++;
                member_index_ = 0;
                continue;
            }

            while (member_index_ < udt.size()) {
                const udm_t& member = udt[member_index_++];
                std::string member_name(member.name.c_str());

                if (matches(member_name)) {
                    qstring type_name;
                    current_type_.get_type_name(&type_name);

                    current_row_.name = member_name;
                    current_row_.kind = "member";
                    current_row_.has_address = false;
                    current_row_.ordinal = type_ordinal_;
                    current_row_.has_ordinal = true;
                    current_row_.parent_name = type_name.c_str();
                    current_row_.full_name = std::string(type_name.c_str()) + "." + member_name;
                    return true;
                }
            }

            // Exhausted members of this type, move to next
            type_ordinal_++;
            member_index_ = 0;
        }
        return false;
    }

    bool advance_enum_members() {
        // Iterate enum values
        uint32 count = get_ordinal_count(nullptr);

        while (type_ordinal_ < count) {
            if (!current_type_.get_numbered_type(nullptr, type_ordinal_)) {
                type_ordinal_++;
                member_index_ = 0;
                continue;
            }

            if (!current_type_.is_enum()) {
                type_ordinal_++;
                member_index_ = 0;
                continue;
            }

            enum_type_data_t etd;
            if (!current_type_.get_enum_details(&etd)) {
                type_ordinal_++;
                member_index_ = 0;
                continue;
            }

            while (member_index_ < etd.size()) {
                const edm_t& em = etd[member_index_++];
                std::string value_name(em.name.c_str());

                if (matches(value_name)) {
                    qstring type_name;
                    current_type_.get_type_name(&type_name);

                    current_row_.name = value_name;
                    current_row_.kind = "enum_member";
                    current_row_.has_address = false;
                    current_row_.ordinal = type_ordinal_;
                    current_row_.has_ordinal = true;
                    current_row_.parent_name = type_name.c_str();
                    current_row_.full_name = std::string(type_name.c_str()) + "." + value_name;
                    return true;
                }
            }

            type_ordinal_++;
            member_index_ = 0;
        }
        return false;
    }
};

// ============================================================================
// SQLite Virtual Table Implementation
// ============================================================================

// Column indices
enum {
    COL_NAME = 0,
    COL_KIND,
    COL_ADDRESS,
    COL_ORDINAL,
    COL_PARENT_NAME,
    COL_FULL_NAME,
    COL_PATTERN,    // HIDDEN
    COL_MODE        // HIDDEN
};

struct JumpEntitiesVtab : sqlite3_vtab {
    // No extra data needed
};

struct JumpEntitiesCursor : sqlite3_vtab_cursor {
    std::unique_ptr<EntityGenerator> generator;
    int64_t rowid = 0;
};

inline int je_connect(sqlite3* db, void*, int, const char* const*,
                      sqlite3_vtab** ppVtab, char**) {
    int rc = sqlite3_declare_vtab(db,
        "CREATE TABLE x("
        "  name TEXT,"
        "  kind TEXT,"
        "  address INTEGER,"
        "  ordinal INTEGER,"
        "  parent_name TEXT,"
        "  full_name TEXT,"
        "  pattern TEXT HIDDEN,"
        "  mode TEXT HIDDEN"
        ")"
    );
    if (rc != SQLITE_OK) return rc;

    auto* vtab = new JumpEntitiesVtab();
    memset(static_cast<sqlite3_vtab*>(vtab), 0, sizeof(sqlite3_vtab));
    *ppVtab = vtab;
    return SQLITE_OK;
}

inline int je_disconnect(sqlite3_vtab* pVtab) {
    delete static_cast<JumpEntitiesVtab*>(pVtab);
    return SQLITE_OK;
}

inline int je_open(sqlite3_vtab*, sqlite3_vtab_cursor** ppCursor) {
    auto* cursor = new JumpEntitiesCursor();
    memset(static_cast<sqlite3_vtab_cursor*>(cursor), 0, sizeof(sqlite3_vtab_cursor));
    *ppCursor = cursor;
    return SQLITE_OK;
}

inline int je_close(sqlite3_vtab_cursor* pCursor) {
    delete static_cast<JumpEntitiesCursor*>(pCursor);
    return SQLITE_OK;
}

inline int je_best_index(sqlite3_vtab*, sqlite3_index_info* pInfo) {
    int pattern_idx = -1;
    int mode_idx = -1;

    // Look for constraints on the hidden columns
    for (int i = 0; i < pInfo->nConstraint; i++) {
        const auto& c = pInfo->aConstraint[i];
        if (!c.usable) continue;
        if (c.op != SQLITE_INDEX_CONSTRAINT_EQ) continue;

        if (c.iColumn == COL_PATTERN) pattern_idx = i;
        if (c.iColumn == COL_MODE) mode_idx = i;
    }

    if (pattern_idx >= 0) {
        // We have a pattern - this is usable
        pInfo->aConstraintUsage[pattern_idx].argvIndex = 1;
        pInfo->aConstraintUsage[pattern_idx].omit = 1;

        if (mode_idx >= 0) {
            pInfo->aConstraintUsage[mode_idx].argvIndex = 2;
            pInfo->aConstraintUsage[mode_idx].omit = 1;
            pInfo->idxNum = 2;  // Both pattern and mode
        } else {
            pInfo->idxNum = 1;  // Pattern only (default to prefix mode)
        }

        pInfo->estimatedCost = 1000.0;
        pInfo->estimatedRows = 100;
    } else {
        // No pattern constraint - discourage full table scan
        pInfo->estimatedCost = 1000000.0;
        pInfo->estimatedRows = 100000;
        pInfo->idxNum = 0;
    }

    return SQLITE_OK;
}

inline int je_filter(sqlite3_vtab_cursor* pCursor, int idxNum, const char*,
                     int argc, sqlite3_value** argv) {
    auto* cursor = static_cast<JumpEntitiesCursor*>(pCursor);
    cursor->generator.reset();
    cursor->rowid = 0;

    if (idxNum == 0 || argc < 1) {
        // No pattern - return empty result
        return SQLITE_OK;
    }

    const char* pattern = reinterpret_cast<const char*>(sqlite3_value_text(argv[0]));
    if (!pattern || !*pattern) {
        return SQLITE_OK;
    }

    bool contains_mode = false;
    if (argc >= 2 && idxNum >= 2) {
        const char* mode = reinterpret_cast<const char*>(sqlite3_value_text(argv[1]));
        if (mode && strcmp(mode, "contains") == 0) {
            contains_mode = true;
        }
    }

    cursor->generator = std::make_unique<EntityGenerator>(pattern, contains_mode);
    cursor->generator->next();  // Position to first row

    return SQLITE_OK;
}

inline int je_next(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = static_cast<JumpEntitiesCursor*>(pCursor);
    if (cursor->generator) {
        cursor->generator->next();
        cursor->rowid++;
    }
    return SQLITE_OK;
}

inline int je_eof(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = static_cast<JumpEntitiesCursor*>(pCursor);
    if (!cursor->generator) return 1;
    return cursor->generator->eof() ? 1 : 0;
}

inline int je_column(sqlite3_vtab_cursor* pCursor, sqlite3_context* ctx, int col) {
    auto* cursor = static_cast<JumpEntitiesCursor*>(pCursor);
    if (!cursor->generator || cursor->generator->eof()) {
        sqlite3_result_null(ctx);
        return SQLITE_OK;
    }

    const EntityRow& row = cursor->generator->current();

    switch (col) {
        case COL_NAME:
            sqlite3_result_text(ctx, row.name.c_str(), -1, SQLITE_TRANSIENT);
            break;
        case COL_KIND:
            sqlite3_result_text(ctx, row.kind.c_str(), -1, SQLITE_TRANSIENT);
            break;
        case COL_ADDRESS:
            if (row.has_address) {
                sqlite3_result_int64(ctx, static_cast<sqlite3_int64>(row.address));
            } else {
                sqlite3_result_null(ctx);
            }
            break;
        case COL_ORDINAL:
            if (row.has_ordinal) {
                sqlite3_result_int64(ctx, row.ordinal);
            } else {
                sqlite3_result_null(ctx);
            }
            break;
        case COL_PARENT_NAME:
            if (!row.parent_name.empty()) {
                sqlite3_result_text(ctx, row.parent_name.c_str(), -1, SQLITE_TRANSIENT);
            } else {
                sqlite3_result_null(ctx);
            }
            break;
        case COL_FULL_NAME:
            sqlite3_result_text(ctx, row.full_name.c_str(), -1, SQLITE_TRANSIENT);
            break;
        case COL_PATTERN:
        case COL_MODE:
            // Hidden columns - return null (they're inputs, not outputs)
            sqlite3_result_null(ctx);
            break;
        default:
            sqlite3_result_null(ctx);
            break;
    }
    return SQLITE_OK;
}

inline int je_rowid(sqlite3_vtab_cursor* pCursor, sqlite3_int64* pRowid) {
    auto* cursor = static_cast<JumpEntitiesCursor*>(pCursor);
    *pRowid = cursor->rowid;
    return SQLITE_OK;
}

// Module definition
inline sqlite3_module& get_jump_entities_module() {
    static sqlite3_module mod = {
        0,              // iVersion
        je_connect,     // xCreate
        je_connect,     // xConnect
        je_best_index,  // xBestIndex
        je_disconnect,  // xDisconnect
        je_disconnect,  // xDestroy
        je_open,        // xOpen
        je_close,       // xClose
        je_filter,      // xFilter
        je_next,        // xNext
        je_eof,         // xEof
        je_column,      // xColumn
        je_rowid,       // xRowid
        nullptr,        // xUpdate
        nullptr,        // xBegin
        nullptr,        // xSync
        nullptr,        // xCommit
        nullptr,        // xRollback
        nullptr,        // xFindFunction
        nullptr,        // xRename
        nullptr,        // xSavepoint
        nullptr,        // xRelease
        nullptr,        // xRollbackTo
        nullptr         // xShadowName
    };
    return mod;
}

/**
 * Register the jump_entities table-valued function.
 *
 * Usage after registration:
 *   SELECT * FROM jump_entities('pattern', 'prefix') LIMIT 10;
 *   SELECT * FROM jump_entities('main', 'contains');
 *   SELECT * FROM jump_entities WHERE pattern = 'sub' AND mode = 'prefix' LIMIT 20;
 */
inline bool register_jump_entities(xsql::Database& db) {
    int rc = sqlite3_create_module(db.handle(), "jump_entities", &get_jump_entities_module(), nullptr);
    return rc == SQLITE_OK;
}

} // namespace search
} // namespace idasql
