/**
 * ida_decompiler.hpp - Hex-Rays Decompiler Virtual Tables
 *
 * Provides SQLite virtual tables for accessing decompiled function data:
 *   pseudocode  - Decompiled function pseudocode lines
 *   lvars       - Local variables from decompiled functions
 *
 * Both tables support constraint pushdown on func_addr for efficient queries:
 *   SELECT * FROM pseudocode WHERE func_addr = 0x401000;
 *   SELECT * FROM lvars WHERE func_addr = 0x401000;
 *
 * Requires Hex-Rays decompiler license.
 */

#pragma once

#include <sqlite3.h>
#include <string>
#include <vector>
#include <cstring>

// IDA SDK headers
#include <ida.hpp>
#include <funcs.hpp>
#include <name.hpp>

// Hex-Rays decompiler headers
#include <hexrays.hpp>

namespace idasql {
namespace decompiler {

// ============================================================================
// Decompiler Initialization
// ============================================================================

inline bool init_hexrays() {
    static bool initialized = false;
    static bool available = false;

    if (!initialized) {
        initialized = true;
        available = init_hexrays_plugin();
    }
    return available;
}

// ============================================================================
// PSEUDOCODE Table
// ============================================================================
//
// Schema: pseudocode(func_addr INTEGER, line_num INTEGER, line TEXT, ea INTEGER)
//
// Columns:
//   func_addr - Function start address
//   line_num  - Line number (0-indexed)
//   line      - Pseudocode text (color codes removed)
//   ea        - Associated disassembly address (if available)
//
// Supports func_addr constraint for efficient single-function queries.
// ============================================================================

enum PseudocodeCol {
    PCODE_COL_FUNC_ADDR = 0,
    PCODE_COL_LINE_NUM,
    PCODE_COL_LINE,
    PCODE_COL_EA
};

static const char* PSEUDOCODE_SCHEMA =
    "CREATE TABLE pseudocode("
    "func_addr INTEGER, "
    "line_num INTEGER, "
    "line TEXT, "
    "ea INTEGER)";

// Data for a single pseudocode line
struct PseudocodeLine {
    ea_t func_addr;
    int line_num;
    std::string text;
    ea_t ea;  // Associated address
};

// Virtual table structure
struct PseudocodeVtab {
    sqlite3_vtab base;
};

// Cursor with cached lines
struct PseudocodeCursor {
    sqlite3_vtab_cursor base;

    std::vector<PseudocodeLine> lines;
    size_t idx;

    ea_t filter_func_addr;
    bool use_func_filter;
};

// Helper: Decompile function and collect lines
static bool collect_pseudocode(std::vector<PseudocodeLine>& lines, ea_t func_addr) {
    lines.clear();

    if (!init_hexrays()) return false;

    func_t* f = get_func(func_addr);
    if (!f) return false;

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc) return false;

    // Get pseudocode lines
    const strvec_t& sv = cfunc->get_pseudocode();

    for (int i = 0; i < sv.size(); i++) {
        PseudocodeLine pl;
        pl.func_addr = func_addr;
        pl.line_num = i;

        // Get line text and remove color codes
        qstring clean;
        tag_remove(&clean, sv[i].line);
        pl.text = clean.c_str();

        // Try to get associated address from treeloc
        // Each line has a ctree_item_t with an address
        pl.ea = BADADDR;  // Default to no address

        lines.push_back(pl);
    }

    return true;
}

// Helper: Collect pseudocode for all functions
static void collect_all_pseudocode(std::vector<PseudocodeLine>& lines) {
    lines.clear();

    if (!init_hexrays()) return;

    size_t func_qty = get_func_qty();
    for (size_t i = 0; i < func_qty; i++) {
        func_t* f = getn_func(i);
        if (!f) continue;

        std::vector<PseudocodeLine> func_lines;
        if (collect_pseudocode(func_lines, f->start_ea)) {
            lines.insert(lines.end(), func_lines.begin(), func_lines.end());
        }
    }
}

// xConnect
static int pcode_connect(sqlite3* db, void*, int, const char* const*,
                         sqlite3_vtab** ppVtab, char**) {
    int rc = sqlite3_declare_vtab(db, PSEUDOCODE_SCHEMA);
    if (rc != SQLITE_OK) return rc;

    auto* vtab = new PseudocodeVtab();
    memset(&vtab->base, 0, sizeof(vtab->base));
    *ppVtab = &vtab->base;
    return SQLITE_OK;
}

// xDisconnect
static int pcode_disconnect(sqlite3_vtab* pVtab) {
    delete reinterpret_cast<PseudocodeVtab*>(pVtab);
    return SQLITE_OK;
}

// xOpen
static int pcode_open(sqlite3_vtab*, sqlite3_vtab_cursor** ppCursor) {
    auto* cursor = new PseudocodeCursor();
    memset(&cursor->base, 0, sizeof(cursor->base));
    cursor->idx = 0;
    cursor->filter_func_addr = 0;
    cursor->use_func_filter = false;
    *ppCursor = &cursor->base;
    return SQLITE_OK;
}

// xClose
static int pcode_close(sqlite3_vtab_cursor* pCursor) {
    delete reinterpret_cast<PseudocodeCursor*>(pCursor);
    return SQLITE_OK;
}

// xBestIndex - detect func_addr constraint
static int pcode_best_index(sqlite3_vtab*, sqlite3_index_info* pInfo) {
    int func_addr_idx = -1;

    for (int i = 0; i < pInfo->nConstraint; i++) {
        const auto& c = pInfo->aConstraint[i];
        if (c.usable && c.iColumn == PCODE_COL_FUNC_ADDR && c.op == SQLITE_INDEX_CONSTRAINT_EQ) {
            func_addr_idx = i;
            break;
        }
    }

    if (func_addr_idx >= 0) {
        pInfo->aConstraintUsage[func_addr_idx].argvIndex = 1;
        pInfo->aConstraintUsage[func_addr_idx].omit = 1;
        pInfo->idxNum = 1;  // Use func_addr filter
        pInfo->estimatedCost = 50.0;  // Low cost - single function
        pInfo->estimatedRows = 50;
    } else {
        pInfo->idxNum = 0;  // Full scan
        pInfo->estimatedCost = 100000.0;  // High cost - all functions
        pInfo->estimatedRows = 10000;
    }

    return SQLITE_OK;
}

// xFilter - setup iteration
static int pcode_filter(sqlite3_vtab_cursor* pCursor, int idxNum, const char*,
                        int argc, sqlite3_value** argv) {
    auto* cursor = reinterpret_cast<PseudocodeCursor*>(pCursor);
    cursor->idx = 0;

    if (idxNum == 1 && argc >= 1) {
        // Filter by func_addr
        cursor->filter_func_addr = sqlite3_value_int64(argv[0]);
        cursor->use_func_filter = true;
        collect_pseudocode(cursor->lines, cursor->filter_func_addr);
    } else {
        // Full scan
        cursor->use_func_filter = false;
        cursor->filter_func_addr = 0;
        collect_all_pseudocode(cursor->lines);
    }

    return SQLITE_OK;
}

// xNext
static int pcode_next(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<PseudocodeCursor*>(pCursor);
    cursor->idx++;
    return SQLITE_OK;
}

// xEof
static int pcode_eof(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<PseudocodeCursor*>(pCursor);
    return cursor->idx >= cursor->lines.size();
}

// xRowid
static int pcode_rowid(sqlite3_vtab_cursor* pCursor, sqlite3_int64* pRowid) {
    auto* cursor = reinterpret_cast<PseudocodeCursor*>(pCursor);
    *pRowid = cursor->idx;
    return SQLITE_OK;
}

// xColumn
static int pcode_column(sqlite3_vtab_cursor* pCursor, sqlite3_context* ctx, int col) {
    auto* cursor = reinterpret_cast<PseudocodeCursor*>(pCursor);

    if (cursor->idx >= cursor->lines.size()) {
        sqlite3_result_null(ctx);
        return SQLITE_OK;
    }

    const PseudocodeLine& line = cursor->lines[cursor->idx];

    switch (col) {
        case PCODE_COL_FUNC_ADDR:
            sqlite3_result_int64(ctx, line.func_addr);
            break;
        case PCODE_COL_LINE_NUM:
            sqlite3_result_int(ctx, line.line_num);
            break;
        case PCODE_COL_LINE:
            sqlite3_result_text(ctx, line.text.c_str(), -1, SQLITE_TRANSIENT);
            break;
        case PCODE_COL_EA:
            if (line.ea != BADADDR) {
                sqlite3_result_int64(ctx, line.ea);
            } else {
                sqlite3_result_null(ctx);
            }
            break;
        default:
            sqlite3_result_null(ctx);
    }

    return SQLITE_OK;
}

// Module definition
static sqlite3_module pcode_module = {
    0,                    // iVersion
    pcode_connect,        // xCreate
    pcode_connect,        // xConnect
    pcode_best_index,     // xBestIndex
    pcode_disconnect,     // xDisconnect
    pcode_disconnect,     // xDestroy
    pcode_open,           // xOpen
    pcode_close,          // xClose
    pcode_filter,         // xFilter
    pcode_next,           // xNext
    pcode_eof,            // xEof
    pcode_column,         // xColumn
    pcode_rowid,          // xRowid
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr
};

// ============================================================================
// LVARS Table (Local Variables)
// ============================================================================
//
// Schema: lvars(func_addr INTEGER, idx INTEGER, name TEXT, type TEXT,
//               size INTEGER, is_arg INTEGER, is_result INTEGER)
//
// Columns:
//   func_addr - Function start address
//   idx       - Variable index in lvars array
//   name      - Variable name
//   type      - Type string
//   size      - Size in bytes
//   is_arg    - 1 if function argument, 0 otherwise
//   is_result - 1 if return value, 0 otherwise
//
// Supports func_addr constraint for efficient queries.
// ============================================================================

enum LvarsCol {
    LVAR_COL_FUNC_ADDR = 0,
    LVAR_COL_IDX,
    LVAR_COL_NAME,
    LVAR_COL_TYPE,
    LVAR_COL_SIZE,
    LVAR_COL_IS_ARG,
    LVAR_COL_IS_RESULT
};

static const char* LVARS_SCHEMA =
    "CREATE TABLE lvars("
    "func_addr INTEGER, "
    "idx INTEGER, "
    "name TEXT, "
    "type TEXT, "
    "size INTEGER, "
    "is_arg INTEGER, "
    "is_result INTEGER)";

// Data for a single local variable
struct LvarInfo {
    ea_t func_addr;
    int idx;
    std::string name;
    std::string type;
    int size;
    bool is_arg;
    bool is_result;
};

// Virtual table structure
struct LvarsVtab {
    sqlite3_vtab base;
};

// Cursor with cached variables
struct LvarsCursor {
    sqlite3_vtab_cursor base;

    std::vector<LvarInfo> vars;
    size_t idx;

    ea_t filter_func_addr;
    bool use_func_filter;
};

// Helper: Collect lvars for a function
static bool collect_lvars(std::vector<LvarInfo>& vars, ea_t func_addr) {
    vars.clear();

    if (!init_hexrays()) return false;

    func_t* f = get_func(func_addr);
    if (!f) return false;

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc) return false;

    // Get local variables
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) return false;

    for (int i = 0; i < lvars->size(); i++) {
        const lvar_t& lv = (*lvars)[i];

        LvarInfo vi;
        vi.func_addr = func_addr;
        vi.idx = i;
        vi.name = lv.name.c_str();

        // Get type string
        qstring type_str;
        lv.type().print(&type_str);
        vi.type = type_str.c_str();

        vi.size = lv.width;
        vi.is_arg = lv.is_arg_var();
        vi.is_result = lv.is_result_var();

        vars.push_back(vi);
    }

    return true;
}

// Helper: Collect lvars for all functions
static void collect_all_lvars(std::vector<LvarInfo>& vars) {
    vars.clear();

    if (!init_hexrays()) return;

    size_t func_qty = get_func_qty();
    for (size_t i = 0; i < func_qty; i++) {
        func_t* f = getn_func(i);
        if (!f) continue;

        std::vector<LvarInfo> func_vars;
        if (collect_lvars(func_vars, f->start_ea)) {
            vars.insert(vars.end(), func_vars.begin(), func_vars.end());
        }
    }
}

// xConnect
static int lvars_connect(sqlite3* db, void*, int, const char* const*,
                         sqlite3_vtab** ppVtab, char**) {
    int rc = sqlite3_declare_vtab(db, LVARS_SCHEMA);
    if (rc != SQLITE_OK) return rc;

    auto* vtab = new LvarsVtab();
    memset(&vtab->base, 0, sizeof(vtab->base));
    *ppVtab = &vtab->base;
    return SQLITE_OK;
}

// xDisconnect
static int lvars_disconnect(sqlite3_vtab* pVtab) {
    delete reinterpret_cast<LvarsVtab*>(pVtab);
    return SQLITE_OK;
}

// xOpen
static int lvars_open(sqlite3_vtab*, sqlite3_vtab_cursor** ppCursor) {
    auto* cursor = new LvarsCursor();
    memset(&cursor->base, 0, sizeof(cursor->base));
    cursor->idx = 0;
    cursor->filter_func_addr = 0;
    cursor->use_func_filter = false;
    *ppCursor = &cursor->base;
    return SQLITE_OK;
}

// xClose
static int lvars_close(sqlite3_vtab_cursor* pCursor) {
    delete reinterpret_cast<LvarsCursor*>(pCursor);
    return SQLITE_OK;
}

// xBestIndex - detect func_addr constraint
static int lvars_best_index(sqlite3_vtab*, sqlite3_index_info* pInfo) {
    int func_addr_idx = -1;

    for (int i = 0; i < pInfo->nConstraint; i++) {
        const auto& c = pInfo->aConstraint[i];
        if (c.usable && c.iColumn == LVAR_COL_FUNC_ADDR && c.op == SQLITE_INDEX_CONSTRAINT_EQ) {
            func_addr_idx = i;
            break;
        }
    }

    if (func_addr_idx >= 0) {
        pInfo->aConstraintUsage[func_addr_idx].argvIndex = 1;
        pInfo->aConstraintUsage[func_addr_idx].omit = 1;
        pInfo->idxNum = 1;  // Use func_addr filter
        pInfo->estimatedCost = 10.0;  // Low cost - single function
        pInfo->estimatedRows = 10;
    } else {
        pInfo->idxNum = 0;  // Full scan
        pInfo->estimatedCost = 100000.0;  // High cost - all functions
        pInfo->estimatedRows = 5000;
    }

    return SQLITE_OK;
}

// xFilter - setup iteration
static int lvars_filter(sqlite3_vtab_cursor* pCursor, int idxNum, const char*,
                        int argc, sqlite3_value** argv) {
    auto* cursor = reinterpret_cast<LvarsCursor*>(pCursor);
    cursor->idx = 0;

    if (idxNum == 1 && argc >= 1) {
        // Filter by func_addr
        cursor->filter_func_addr = sqlite3_value_int64(argv[0]);
        cursor->use_func_filter = true;
        collect_lvars(cursor->vars, cursor->filter_func_addr);
    } else {
        // Full scan
        cursor->use_func_filter = false;
        cursor->filter_func_addr = 0;
        collect_all_lvars(cursor->vars);
    }

    return SQLITE_OK;
}

// xNext
static int lvars_next(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<LvarsCursor*>(pCursor);
    cursor->idx++;
    return SQLITE_OK;
}

// xEof
static int lvars_eof(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<LvarsCursor*>(pCursor);
    return cursor->idx >= cursor->vars.size();
}

// xRowid
static int lvars_rowid(sqlite3_vtab_cursor* pCursor, sqlite3_int64* pRowid) {
    auto* cursor = reinterpret_cast<LvarsCursor*>(pCursor);
    *pRowid = cursor->idx;
    return SQLITE_OK;
}

// xColumn
static int lvars_column(sqlite3_vtab_cursor* pCursor, sqlite3_context* ctx, int col) {
    auto* cursor = reinterpret_cast<LvarsCursor*>(pCursor);

    if (cursor->idx >= cursor->vars.size()) {
        sqlite3_result_null(ctx);
        return SQLITE_OK;
    }

    const LvarInfo& var = cursor->vars[cursor->idx];

    switch (col) {
        case LVAR_COL_FUNC_ADDR:
            sqlite3_result_int64(ctx, var.func_addr);
            break;
        case LVAR_COL_IDX:
            sqlite3_result_int(ctx, var.idx);
            break;
        case LVAR_COL_NAME:
            sqlite3_result_text(ctx, var.name.c_str(), -1, SQLITE_TRANSIENT);
            break;
        case LVAR_COL_TYPE:
            sqlite3_result_text(ctx, var.type.c_str(), -1, SQLITE_TRANSIENT);
            break;
        case LVAR_COL_SIZE:
            sqlite3_result_int(ctx, var.size);
            break;
        case LVAR_COL_IS_ARG:
            sqlite3_result_int(ctx, var.is_arg ? 1 : 0);
            break;
        case LVAR_COL_IS_RESULT:
            sqlite3_result_int(ctx, var.is_result ? 1 : 0);
            break;
        default:
            sqlite3_result_null(ctx);
    }

    return SQLITE_OK;
}

// Module definition
static sqlite3_module lvars_module = {
    0,                    // iVersion
    lvars_connect,        // xCreate
    lvars_connect,        // xConnect
    lvars_best_index,     // xBestIndex
    lvars_disconnect,     // xDisconnect
    lvars_disconnect,     // xDestroy
    lvars_open,           // xOpen
    lvars_close,          // xClose
    lvars_filter,         // xFilter
    lvars_next,           // xNext
    lvars_eof,            // xEof
    lvars_column,         // xColumn
    lvars_rowid,          // xRowid
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr
};

// ============================================================================
// Registration
// ============================================================================

inline bool register_pseudocode_table(sqlite3* db) {
    int rc = sqlite3_create_module(db, "ida_pseudocode", &pcode_module, nullptr);
    if (rc != SQLITE_OK) return false;

    char* err = nullptr;
    rc = sqlite3_exec(db, "CREATE VIRTUAL TABLE pseudocode USING ida_pseudocode;",
                      nullptr, nullptr, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

inline bool register_lvars_table(sqlite3* db) {
    int rc = sqlite3_create_module(db, "ida_lvars", &lvars_module, nullptr);
    if (rc != SQLITE_OK) return false;

    char* err = nullptr;
    rc = sqlite3_exec(db, "CREATE VIRTUAL TABLE lvars USING ida_lvars;",
                      nullptr, nullptr, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

// Registry for all decompiler tables
struct DecompilerRegistry {
    void register_all(sqlite3* db) {
        register_pseudocode_table(db);
        register_lvars_table(db);
    }
};

} // namespace decompiler
} // namespace idasql
