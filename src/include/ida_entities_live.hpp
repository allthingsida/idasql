/**
 * ida_entities_live.hpp - Live IDA entities with UPDATE/DELETE support
 *
 * Uses v2 framework for:
 *   - No caching - fresh data on every query
 *   - UPDATE support for writable columns
 *   - DELETE support where applicable
 *   - Automatic undo points for modifications
 *
 * Writable Tables:
 *   names_live     - Rename addresses (UPDATE name)
 *   comments_live  - Add/edit/delete comments (UPDATE/DELETE)
 *   funcs_live     - Rename functions (UPDATE name)
 *   bookmarks      - Full CRUD for bookmarks
 */

#pragma once

#include "ida_vtable_v2.hpp"

// IDA SDK headers
#include <ida.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <lines.hpp>
#include <segment.hpp>
#include <moves.hpp>
#include <kernwin.hpp>

namespace idasql {
namespace live {

using namespace v2;

// ============================================================================
// NAMES_LIVE Table - Named locations with UPDATE support
// ============================================================================

inline LiveVTableDef define_names_live() {
    return live_table("names_live")
        .count([]() {
            return get_nlist_size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            return get_nlist_ea(i);
        })
        .column_text_rw("name",
            // Getter
            [](size_t i) -> std::string {
                const char* n = get_nlist_name(i);
                return n ? n : "";
            },
            // Setter - rename the address
            [](size_t i, const char* new_name) -> bool {
                ea_t ea = get_nlist_ea(i);
                if (ea == BADADDR) return false;
                return set_name(ea, new_name, SN_CHECK) != 0;
            })
        .column_int("is_public", [](size_t i) -> int {
            return is_public_name(get_nlist_ea(i)) ? 1 : 0;
        })
        .column_int("is_weak", [](size_t i) -> int {
            return is_weak_name(get_nlist_ea(i)) ? 1 : 0;
        })
        .build();
}

// ============================================================================
// COMMENTS_LIVE Table - Comments with UPDATE/DELETE support
// ============================================================================

// Helper to iterate addresses with comments
struct CommentIterator {
    static std::vector<ea_t>& get_addresses() {
        static std::vector<ea_t> addrs;
        return addrs;
    }

    static void rebuild() {
        auto& addrs = get_addresses();
        addrs.clear();

        ea_t ea = inf_get_min_ea();
        ea_t max_ea = inf_get_max_ea();

        while (ea < max_ea) {
            qstring cmt, rpt;
            bool has_cmt = get_cmt(&cmt, ea, false) > 0;
            bool has_rpt = get_cmt(&rpt, ea, true) > 0;

            if (has_cmt || has_rpt) {
                addrs.push_back(ea);
            }

            ea = next_head(ea, max_ea);
            if (ea == BADADDR) break;
        }
    }
};

inline LiveVTableDef define_comments_live() {
    return live_table("comments_live")
        .count([]() {
            CommentIterator::rebuild();
            return CommentIterator::get_addresses().size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& addrs = CommentIterator::get_addresses();
            return i < addrs.size() ? addrs[i] : 0;
        })
        .column_text_rw("comment",
            // Getter
            [](size_t i) -> std::string {
                auto& addrs = CommentIterator::get_addresses();
                if (i >= addrs.size()) return "";
                qstring cmt;
                get_cmt(&cmt, addrs[i], false);
                return cmt.c_str();
            },
            // Setter
            [](size_t i, const char* new_cmt) -> bool {
                auto& addrs = CommentIterator::get_addresses();
                if (i >= addrs.size()) return false;
                return set_cmt(addrs[i], new_cmt, false);
            })
        .column_text_rw("rpt_comment",
            // Getter
            [](size_t i) -> std::string {
                auto& addrs = CommentIterator::get_addresses();
                if (i >= addrs.size()) return "";
                qstring cmt;
                get_cmt(&cmt, addrs[i], true);
                return cmt.c_str();
            },
            // Setter
            [](size_t i, const char* new_cmt) -> bool {
                auto& addrs = CommentIterator::get_addresses();
                if (i >= addrs.size()) return false;
                return set_cmt(addrs[i], new_cmt, true);
            })
        .deletable([](size_t i) -> bool {
            // Delete both comments at this address
            auto& addrs = CommentIterator::get_addresses();
            if (i >= addrs.size()) return false;
            ea_t ea = addrs[i];
            set_cmt(ea, "", false);  // Delete regular
            set_cmt(ea, "", true);   // Delete repeatable
            return true;
        })
        .build();
}

// ============================================================================
// FUNCS_LIVE Table - Functions with UPDATE support
// ============================================================================

inline LiveVTableDef define_funcs_live() {
    return live_table("funcs_live")
        .count([]() {
            return get_func_qty();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            func_t* f = getn_func(i);
            return f ? f->start_ea : 0;
        })
        .column_text_rw("name",
            // Getter
            [](size_t i) -> std::string {
                func_t* f = getn_func(i);
                if (!f) return "";
                qstring name;
                get_func_name(&name, f->start_ea);
                return name.c_str();
            },
            // Setter - rename function
            [](size_t i, const char* new_name) -> bool {
                func_t* f = getn_func(i);
                if (!f) return false;
                return set_name(f->start_ea, new_name, SN_CHECK) != 0;
            })
        .column_int64("size", [](size_t i) -> int64_t {
            func_t* f = getn_func(i);
            return f ? f->size() : 0;
        })
        .column_int("flags", [](size_t i) -> int {
            func_t* f = getn_func(i);
            return f ? f->flags : 0;
        })
        .column_int64("end_ea", [](size_t i) -> int64_t {
            func_t* f = getn_func(i);
            return f ? f->end_ea : 0;
        })
        .deletable([](size_t i) -> bool {
            // Delete the function definition
            func_t* f = getn_func(i);
            if (!f) return false;
            return del_func(f->start_ea);
        })
        .build();
}

// ============================================================================
// BOOKMARKS Table - Full CRUD support
// ============================================================================

// Helper for bookmark iteration
struct BookmarkIterator {
    struct Entry {
        uint32_t index;
        ea_t ea;
        std::string desc;
    };

    static std::vector<Entry>& get_entries() {
        static std::vector<Entry> entries;
        return entries;
    }

    static void rebuild() {
        auto& entries = get_entries();
        entries.clear();

        // Get bookmarks for IDA View (disassembly)
        // We need a place_t for the bookmark API
        idaplace_t idaplace(inf_get_min_ea(), 0);
        renderer_info_t rinfo;
        lochist_entry_t loc(&idaplace, rinfo);

        uint32_t count = bookmarks_t::size(loc, nullptr);

        for (uint32_t idx = 0; idx < count; ++idx) {
            idaplace_t place(0, 0);
            lochist_entry_t entry(&place, rinfo);
            qstring desc;
            uint32_t index = idx;

            if (bookmarks_t::get(&entry, &desc, &index, nullptr)) {
                Entry e;
                e.index = index;
                e.ea = ((idaplace_t*)entry.place())->ea;
                e.desc = desc.c_str();
                entries.push_back(e);
            }
        }
    }
};

inline LiveVTableDef define_bookmarks() {
    return live_table("bookmarks")
        .count([]() {
            BookmarkIterator::rebuild();
            return BookmarkIterator::get_entries().size();
        })
        .column_int("slot", [](size_t i) -> int {
            auto& entries = BookmarkIterator::get_entries();
            return i < entries.size() ? entries[i].index : 0;
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& entries = BookmarkIterator::get_entries();
            return i < entries.size() ? entries[i].ea : 0;
        })
        .column_text_rw("description",
            // Getter
            [](size_t i) -> std::string {
                auto& entries = BookmarkIterator::get_entries();
                return i < entries.size() ? entries[i].desc : "";
            },
            // Setter - update bookmark description
            [](size_t i, const char* new_desc) -> bool {
                auto& entries = BookmarkIterator::get_entries();
                if (i >= entries.size()) return false;

                idaplace_t place(entries[i].ea, 0);
                renderer_info_t rinfo;
                lochist_entry_t loc(&place, rinfo);
                return bookmarks_t_set_desc(qstring(new_desc), loc, entries[i].index, nullptr);
            })
        .deletable([](size_t i) -> bool {
            auto& entries = BookmarkIterator::get_entries();
            if (i >= entries.size()) return false;

            idaplace_t place(entries[i].ea, 0);
            renderer_info_t rinfo;
            lochist_entry_t loc(&place, rinfo);
            return bookmarks_t::erase(loc, entries[i].index, nullptr);
        })
        .build();
}

// ============================================================================
// HEADS Table - All defined items in the database
// ============================================================================

// Helper to collect all heads
struct HeadsIterator {
    static std::vector<ea_t>& get_addresses() {
        static std::vector<ea_t> addrs;
        return addrs;
    }

    static void rebuild() {
        auto& addrs = get_addresses();
        addrs.clear();

        ea_t ea = inf_get_min_ea();
        ea_t max_ea = inf_get_max_ea();

        while (ea < max_ea && ea != BADADDR) {
            addrs.push_back(ea);
            ea = next_head(ea, max_ea);
        }
    }
};

inline const char* get_item_type_str(ea_t ea) {
    flags64_t f = get_flags(ea);
    if (is_code(f)) return "code";
    if (is_strlit(f)) return "string";
    if (is_struct(f)) return "struct";
    if (is_align(f)) return "align";
    if (is_data(f)) return "data";
    if (is_unknown(f)) return "unknown";
    return "other";
}

inline LiveVTableDef define_heads() {
    return live_table("heads")
        .count([]() {
            HeadsIterator::rebuild();
            return HeadsIterator::get_addresses().size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& addrs = HeadsIterator::get_addresses();
            return i < addrs.size() ? addrs[i] : 0;
        })
        .column_int64("size", [](size_t i) -> int64_t {
            auto& addrs = HeadsIterator::get_addresses();
            if (i >= addrs.size()) return 0;
            return get_item_size(addrs[i]);
        })
        .column_text("type", [](size_t i) -> std::string {
            auto& addrs = HeadsIterator::get_addresses();
            if (i >= addrs.size()) return "";
            return get_item_type_str(addrs[i]);
        })
        .column_int64("flags", [](size_t i) -> int64_t {
            auto& addrs = HeadsIterator::get_addresses();
            if (i >= addrs.size()) return 0;
            return get_flags(addrs[i]);
        })
        .column_text("disasm", [](size_t i) -> std::string {
            auto& addrs = HeadsIterator::get_addresses();
            if (i >= addrs.size()) return "";
            qstring line;
            generate_disasm_line(&line, addrs[i], GENDSM_FORCE_CODE);
            tag_remove(&line);
            return line.c_str();
        })
        .build();
}

// ============================================================================
// INSTRUCTIONS Table - Optimized with func_addr constraint support
// ============================================================================
//
// This table supports constraint pushdown for func_addr:
//   SELECT * FROM instructions WHERE func_addr = 0x401000
//
// When func_addr constraint is detected, only iterates that function's range
// using func_item_iterator_t instead of scanning the entire database.
// ============================================================================

#include <ua.hpp>  // For insn_t, decode_insn

// Column indices for instructions table
enum InsnCol {
    INSN_COL_ADDRESS = 0,
    INSN_COL_ITYPE,
    INSN_COL_MNEMONIC,
    INSN_COL_SIZE,
    INSN_COL_OPERAND0,
    INSN_COL_OPERAND1,
    INSN_COL_OPERAND2,
    INSN_COL_DISASM,
    INSN_COL_FUNC_ADDR
};

// Schema for instructions table
static const char* INSN_SCHEMA =
    "CREATE TABLE instructions("
    "address INTEGER, "
    "itype INTEGER, "
    "mnemonic TEXT, "
    "size INTEGER, "
    "operand0 TEXT, "
    "operand1 TEXT, "
    "operand2 TEXT, "
    "disasm TEXT, "
    "func_addr INTEGER)";

// Virtual table structure
struct InsnVtab {
    sqlite3_vtab base;
};

// Cursor with filter state
struct InsnCursor {
    sqlite3_vtab_cursor base;

    // Iteration state
    std::vector<ea_t> addrs;   // Cached addresses to iterate
    size_t idx;                // Current index

    // Filter state
    ea_t filter_func_addr;     // If non-zero, filter by this function
    bool use_func_filter;
};

// Helper: Iterate all code in database
static void collect_all_code(std::vector<ea_t>& addrs) {
    addrs.clear();
    ea_t ea = inf_get_min_ea();
    ea_t max_ea = inf_get_max_ea();

    while (ea < max_ea && ea != BADADDR) {
        flags64_t f = get_flags(ea);
        if (is_code(f)) {
            addrs.push_back(ea);
        }
        ea = next_head(ea, max_ea);
    }
}

// Helper: Iterate code within a function (OPTIMIZED)
static void collect_func_code(std::vector<ea_t>& addrs, ea_t func_addr) {
    addrs.clear();
    func_t* f = get_func(func_addr);
    if (!f) return;

    // Use func_item_iterator_t for efficient function traversal
    func_item_iterator_t fii;
    for (bool ok = fii.set(f); ok; ok = fii.next_code()) {
        addrs.push_back(fii.current());
    }
}

// xConnect
static int insn_connect(sqlite3* db, void*, int, const char* const*,
                        sqlite3_vtab** ppVtab, char**) {
    int rc = sqlite3_declare_vtab(db, INSN_SCHEMA);
    if (rc != SQLITE_OK) return rc;

    auto* vtab = new InsnVtab();
    memset(&vtab->base, 0, sizeof(vtab->base));
    *ppVtab = &vtab->base;
    return SQLITE_OK;
}

// xDisconnect
static int insn_disconnect(sqlite3_vtab* pVtab) {
    delete reinterpret_cast<InsnVtab*>(pVtab);
    return SQLITE_OK;
}

// xOpen
static int insn_open(sqlite3_vtab*, sqlite3_vtab_cursor** ppCursor) {
    auto* cursor = new InsnCursor();
    memset(&cursor->base, 0, sizeof(cursor->base));
    cursor->idx = 0;
    cursor->filter_func_addr = 0;
    cursor->use_func_filter = false;
    *ppCursor = &cursor->base;
    return SQLITE_OK;
}

// xClose
static int insn_close(sqlite3_vtab_cursor* pCursor) {
    delete reinterpret_cast<InsnCursor*>(pCursor);
    return SQLITE_OK;
}

// xBestIndex - detect func_addr constraint
static int insn_best_index(sqlite3_vtab*, sqlite3_index_info* pInfo) {
    int func_addr_idx = -1;

    // Look for func_addr = ? constraint
    for (int i = 0; i < pInfo->nConstraint; i++) {
        const auto& c = pInfo->aConstraint[i];
        if (c.usable && c.iColumn == INSN_COL_FUNC_ADDR && c.op == SQLITE_INDEX_CONSTRAINT_EQ) {
            func_addr_idx = i;
            break;
        }
    }

    if (func_addr_idx >= 0) {
        // Tell SQLite to pass func_addr value to xFilter
        pInfo->aConstraintUsage[func_addr_idx].argvIndex = 1;
        pInfo->aConstraintUsage[func_addr_idx].omit = 1;  // We handle this constraint
        pInfo->idxNum = 1;  // Signal: use func_addr filter
        pInfo->estimatedCost = 100.0;  // Low cost - function is small
        pInfo->estimatedRows = 100;
    } else {
        pInfo->idxNum = 0;  // Signal: full scan
        pInfo->estimatedCost = 100000.0;  // High cost - full database
        pInfo->estimatedRows = 10000;
    }

    return SQLITE_OK;
}

// xFilter - setup iteration based on constraints
static int insn_filter(sqlite3_vtab_cursor* pCursor, int idxNum, const char*,
                       int argc, sqlite3_value** argv) {
    auto* cursor = reinterpret_cast<InsnCursor*>(pCursor);
    cursor->idx = 0;

    if (idxNum == 1 && argc >= 1) {
        // OPTIMIZED: Filter by func_addr
        cursor->filter_func_addr = sqlite3_value_int64(argv[0]);
        cursor->use_func_filter = true;
        collect_func_code(cursor->addrs, cursor->filter_func_addr);
    } else {
        // FULL SCAN: Iterate all code
        cursor->use_func_filter = false;
        cursor->filter_func_addr = 0;
        collect_all_code(cursor->addrs);
    }

    return SQLITE_OK;
}

// xNext
static int insn_next(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<InsnCursor*>(pCursor);
    cursor->idx++;
    return SQLITE_OK;
}

// xEof
static int insn_eof(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<InsnCursor*>(pCursor);
    return cursor->idx >= cursor->addrs.size();
}

// xRowid
static int insn_rowid(sqlite3_vtab_cursor* pCursor, sqlite3_int64* pRowid) {
    auto* cursor = reinterpret_cast<InsnCursor*>(pCursor);
    *pRowid = cursor->idx;
    return SQLITE_OK;
}

// xColumn - fetch data on demand
static int insn_column(sqlite3_vtab_cursor* pCursor, sqlite3_context* ctx, int col) {
    auto* cursor = reinterpret_cast<InsnCursor*>(pCursor);

    if (cursor->idx >= cursor->addrs.size()) {
        sqlite3_result_null(ctx);
        return SQLITE_OK;
    }

    ea_t ea = cursor->addrs[cursor->idx];

    switch (col) {
        case INSN_COL_ADDRESS:
            sqlite3_result_int64(ctx, ea);
            break;

        case INSN_COL_ITYPE: {
            insn_t insn;
            if (decode_insn(&insn, ea) > 0) {
                sqlite3_result_int(ctx, insn.itype);
            } else {
                sqlite3_result_int(ctx, 0);
            }
            break;
        }

        case INSN_COL_MNEMONIC: {
            qstring mnem;
            print_insn_mnem(&mnem, ea);
            sqlite3_result_text(ctx, mnem.c_str(), -1, SQLITE_TRANSIENT);
            break;
        }

        case INSN_COL_SIZE:
            sqlite3_result_int(ctx, get_item_size(ea));
            break;

        case INSN_COL_OPERAND0:
        case INSN_COL_OPERAND1:
        case INSN_COL_OPERAND2: {
            qstring op;
            print_operand(&op, ea, col - INSN_COL_OPERAND0);
            tag_remove(&op);
            sqlite3_result_text(ctx, op.c_str(), -1, SQLITE_TRANSIENT);
            break;
        }

        case INSN_COL_DISASM: {
            qstring line;
            generate_disasm_line(&line, ea, 0);
            tag_remove(&line);
            sqlite3_result_text(ctx, line.c_str(), -1, SQLITE_TRANSIENT);
            break;
        }

        case INSN_COL_FUNC_ADDR: {
            // If filtered by func_addr, return the filter value (optimization)
            if (cursor->use_func_filter) {
                sqlite3_result_int64(ctx, cursor->filter_func_addr);
            } else {
                func_t* f = get_func(ea);
                sqlite3_result_int64(ctx, f ? f->start_ea : 0);
            }
            break;
        }

        default:
            sqlite3_result_null(ctx);
    }

    return SQLITE_OK;
}

// SQLite module for instructions table
static sqlite3_module insn_module = {
    0,                    // iVersion
    insn_connect,         // xCreate
    insn_connect,         // xConnect
    insn_best_index,      // xBestIndex
    insn_disconnect,      // xDisconnect
    insn_disconnect,      // xDestroy
    insn_open,            // xOpen
    insn_close,           // xClose
    insn_filter,          // xFilter
    insn_next,            // xNext
    insn_eof,             // xEof
    insn_column,          // xColumn
    insn_rowid,           // xRowid
    nullptr,              // xUpdate
    nullptr,              // xBegin
    nullptr,              // xSync
    nullptr,              // xCommit
    nullptr,              // xRollback
    nullptr,              // xFindFunction
    nullptr,              // xRename
    nullptr,              // xSavepoint
    nullptr,              // xRelease
    nullptr,              // xRollbackTo
    nullptr               // xShadowName
};

// Register the optimized instructions table
inline bool register_instructions_table(sqlite3* db) {
    int rc = sqlite3_create_module(db, "ida_instructions", &insn_module, nullptr);
    if (rc != SQLITE_OK) return false;

    char* err = nullptr;
    rc = sqlite3_exec(db, "CREATE VIRTUAL TABLE instructions USING ida_instructions;",
                      nullptr, nullptr, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

// ============================================================================
// Live Entity Registry
// ============================================================================

struct LiveRegistry {
    LiveVTableDef names_live;
    LiveVTableDef comments_live;
    LiveVTableDef funcs_live;
    LiveVTableDef bookmarks;
    LiveVTableDef heads;
    // Note: instructions uses specialized implementation with constraint support

    LiveRegistry()
        : names_live(define_names_live())
        , comments_live(define_comments_live())
        , funcs_live(define_funcs_live())
        , bookmarks(define_bookmarks())
        , heads(define_heads())
    {}

    void register_all(sqlite3* db) {
        register_live_vtable(db, "ida_names_live", &names_live);
        create_live_vtable(db, "names_live", "ida_names_live");

        register_live_vtable(db, "ida_comments_live", &comments_live);
        create_live_vtable(db, "comments_live", "ida_comments_live");

        register_live_vtable(db, "ida_funcs_live", &funcs_live);
        create_live_vtable(db, "funcs_live", "ida_funcs_live");

        register_live_vtable(db, "ida_bookmarks", &bookmarks);
        create_live_vtable(db, "bookmarks", "ida_bookmarks");

        register_live_vtable(db, "ida_heads", &heads);
        create_live_vtable(db, "heads", "ida_heads");

        // Optimized instructions table with func_addr constraint support
        register_instructions_table(db);
    }
};

} // namespace live
} // namespace idasql
