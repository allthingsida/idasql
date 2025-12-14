/**
 * ida_decompiler.hpp - Hex-Rays Decompiler Virtual Tables
 *
 * Provides SQLite virtual tables for accessing decompiled function data:
 *   pseudocode       - Decompiled function pseudocode lines
 *   ctree_lvars      - Local variables from decompiled functions
 *   ctree            - Full AST (expressions and statements)
 *   ctree_call_args  - Flattened call arguments
 *
 * All tables support constraint pushdown on func_addr for efficient queries:
 *   SELECT * FROM pseudocode WHERE func_addr = 0x401000;
 *   SELECT * FROM ctree_lvars WHERE func_addr = 0x401000;
 *
 * Requires Hex-Rays decompiler license.
 */

#pragma once

#include <sqlite3.h>
#include <string>
#include <vector>
#include <map>
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
// CTREE_LVARS Table (Local Variables)
// ============================================================================
//
// Schema: ctree_lvars(func_addr INTEGER, idx INTEGER, name TEXT, type TEXT,
//                     size INTEGER, is_arg INTEGER, is_result INTEGER,
//                     is_stk_var INTEGER, is_reg_var INTEGER, stkoff INTEGER, mreg INTEGER)
//
// Columns:
//   func_addr  - Function start address
//   idx        - Variable index in lvars array
//   name       - Variable name
//   type       - Type string
//   size       - Size in bytes
//   is_arg     - 1 if function argument, 0 otherwise
//   is_result  - 1 if return value, 0 otherwise
//   is_stk_var - 1 if stack variable, 0 otherwise
//   is_reg_var - 1 if register variable, 0 otherwise
//   stkoff     - Stack offset (for stack variables)
//   mreg       - Micro-register (for register variables)
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
    LVAR_COL_IS_RESULT,
    LVAR_COL_IS_STK_VAR,
    LVAR_COL_IS_REG_VAR,
    LVAR_COL_STKOFF,
    LVAR_COL_MREG
};

static const char* LVARS_SCHEMA =
    "CREATE TABLE ctree_lvars("
    "func_addr INTEGER, "
    "idx INTEGER, "
    "name TEXT, "
    "type TEXT, "
    "size INTEGER, "
    "is_arg INTEGER, "
    "is_result INTEGER, "
    "is_stk_var INTEGER, "
    "is_reg_var INTEGER, "
    "stkoff INTEGER, "
    "mreg INTEGER)";

// Data for a single local variable
struct LvarInfo {
    ea_t func_addr;
    int idx;
    std::string name;
    std::string type;
    int size;
    bool is_arg;
    bool is_result;
    bool is_stk_var;
    bool is_reg_var;
    sval_t stkoff;      // Stack offset (valid if is_stk_var)
    mreg_t mreg;        // Micro-register (valid if is_reg_var)
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

        // Extended fields
        vi.is_stk_var = lv.is_stk_var();
        vi.is_reg_var = lv.is_reg_var();
        vi.stkoff = vi.is_stk_var ? lv.get_stkoff() : 0;
        vi.mreg = vi.is_reg_var ? lv.location.reg1() : mr_none;

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
        case LVAR_COL_IS_STK_VAR:
            sqlite3_result_int(ctx, var.is_stk_var ? 1 : 0);
            break;
        case LVAR_COL_IS_REG_VAR:
            sqlite3_result_int(ctx, var.is_reg_var ? 1 : 0);
            break;
        case LVAR_COL_STKOFF:
            if (var.is_stk_var) {
                sqlite3_result_int64(ctx, var.stkoff);
            } else {
                sqlite3_result_null(ctx);
            }
            break;
        case LVAR_COL_MREG:
            if (var.is_reg_var) {
                sqlite3_result_int(ctx, var.mreg);
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

// Helper: Get full ctype name with cot_/cit_ prefix
static std::string get_full_ctype_name(ctype_t op) {
    const char* name = get_ctype_name(op);
    if (!name || !name[0]) return "";

    // Expressions use cot_ prefix, statements use cit_ prefix
    // cot_* opcodes: cot_comma (0) to cot_last (106)
    // cit_* opcodes: cit_empty (107) onwards
    if (op < cit_empty) {
        return std::string("cot_") + name;
    } else {
        return std::string("cit_") + name;
    }
}

// ============================================================================
// CTREE Table (AST)
// ============================================================================
//
// Schema: ctree(func_addr, item_id, is_expr, op, op_name, ea, parent_id, depth,
//               x_id, y_id, z_id, cond_id, then_id, else_id, body_id, init_id, step_id,
//               var_idx, obj_ea, num_value, str_value, helper_name, member_offset,
//               var_name, var_is_stk, var_is_reg, var_is_arg, obj_name)
//
// Provides access to the decompiled AST (ctree) of functions.
// Supports func_addr constraint for efficient single-function queries.
// ============================================================================

enum CtreeCol {
    CTREE_COL_FUNC_ADDR = 0,
    CTREE_COL_ITEM_ID,
    CTREE_COL_IS_EXPR,
    CTREE_COL_OP,
    CTREE_COL_OP_NAME,
    CTREE_COL_EA,
    CTREE_COL_PARENT_ID,
    CTREE_COL_DEPTH,
    CTREE_COL_X_ID,
    CTREE_COL_Y_ID,
    CTREE_COL_Z_ID,
    CTREE_COL_COND_ID,
    CTREE_COL_THEN_ID,
    CTREE_COL_ELSE_ID,
    CTREE_COL_BODY_ID,
    CTREE_COL_INIT_ID,
    CTREE_COL_STEP_ID,
    CTREE_COL_VAR_IDX,
    CTREE_COL_OBJ_EA,
    CTREE_COL_NUM_VALUE,
    CTREE_COL_STR_VALUE,
    CTREE_COL_HELPER_NAME,
    CTREE_COL_MEMBER_OFFSET,
    CTREE_COL_VAR_NAME,
    CTREE_COL_VAR_IS_STK,
    CTREE_COL_VAR_IS_REG,
    CTREE_COL_VAR_IS_ARG,
    CTREE_COL_OBJ_NAME
};

static const char* CTREE_SCHEMA =
    "CREATE TABLE ctree("
    "func_addr INTEGER, "
    "item_id INTEGER, "
    "is_expr INTEGER, "
    "op INTEGER, "
    "op_name TEXT, "
    "ea INTEGER, "
    "parent_id INTEGER, "
    "depth INTEGER, "
    "x_id INTEGER, "
    "y_id INTEGER, "
    "z_id INTEGER, "
    "cond_id INTEGER, "
    "then_id INTEGER, "
    "else_id INTEGER, "
    "body_id INTEGER, "
    "init_id INTEGER, "
    "step_id INTEGER, "
    "var_idx INTEGER, "
    "obj_ea INTEGER, "
    "num_value INTEGER, "
    "str_value TEXT, "
    "helper_name TEXT, "
    "member_offset INTEGER, "
    "var_name TEXT, "
    "var_is_stk INTEGER, "
    "var_is_reg INTEGER, "
    "var_is_arg INTEGER, "
    "obj_name TEXT)";

// Data for a single ctree item
struct CtreeItem {
    ea_t func_addr;
    int item_id;
    bool is_expr;
    int op;
    std::string op_name;
    ea_t ea;
    int parent_id;      // -1 if root
    int depth;
    int x_id, y_id, z_id;
    int cond_id, then_id, else_id;
    int body_id, init_id, step_id;
    int var_idx;
    ea_t obj_ea;
    int64_t num_value;
    std::string str_value;
    std::string helper_name;
    int member_offset;
    std::string var_name;
    bool var_is_stk, var_is_reg, var_is_arg;
    std::string obj_name;

    CtreeItem() : func_addr(0), item_id(-1), is_expr(false), op(0), ea(BADADDR),
                  parent_id(-1), depth(0),
                  x_id(-1), y_id(-1), z_id(-1),
                  cond_id(-1), then_id(-1), else_id(-1),
                  body_id(-1), init_id(-1), step_id(-1),
                  var_idx(-1), obj_ea(BADADDR), num_value(0), member_offset(0),
                  var_is_stk(false), var_is_reg(false), var_is_arg(false) {}
};

// Virtual table structure
struct CtreeVtab {
    sqlite3_vtab base;
};

// Cursor with cached items
struct CtreeCursor {
    sqlite3_vtab_cursor base;
    std::vector<CtreeItem> items;
    size_t idx;
    ea_t filter_func_addr;
    bool use_func_filter;
};

// Ctree collector visitor
struct ctree_collector_t : public ctree_parentee_t {
    std::vector<CtreeItem>& items;
    std::map<citem_t*, int> item_ids;
    cfunc_t* cfunc;
    ea_t func_addr;
    int next_id;

    ctree_collector_t(std::vector<CtreeItem>& items_, cfunc_t* cfunc_, ea_t func_addr_)
        : ctree_parentee_t(false), items(items_), cfunc(cfunc_), func_addr(func_addr_), next_id(0) {}

    int idaapi visit_insn(cinsn_t* insn) override {
        int my_id = next_id++;
        item_ids[insn] = my_id;

        CtreeItem ci;
        ci.func_addr = func_addr;
        ci.item_id = my_id;
        ci.is_expr = false;
        ci.op = insn->op;
        ci.op_name = get_full_ctype_name(insn->op);
        ci.ea = insn->ea;
        ci.depth = parents.size();

        // Parent ID
        citem_t* p = parent_item();
        if (p) {
            auto it = item_ids.find(p);
            if (it != item_ids.end()) ci.parent_id = it->second;
        }

        items.push_back(ci);
        return 0;  // Continue traversal
    }

    int idaapi visit_expr(cexpr_t* expr) override {
        int my_id = next_id++;
        item_ids[expr] = my_id;

        CtreeItem ci;
        ci.func_addr = func_addr;
        ci.item_id = my_id;
        ci.is_expr = true;
        ci.op = expr->op;
        ci.op_name = get_full_ctype_name(expr->op);
        ci.ea = expr->ea;
        ci.depth = parents.size();

        // Parent ID
        citem_t* p = parent_item();
        if (p) {
            auto it = item_ids.find(p);
            if (it != item_ids.end()) ci.parent_id = it->second;
        }

        // Leaf values based on op
        switch (expr->op) {
            case cot_var:
                ci.var_idx = expr->v.idx;
                if (cfunc && ci.var_idx >= 0 && ci.var_idx < cfunc->get_lvars()->size()) {
                    const lvar_t& lv = (*cfunc->get_lvars())[ci.var_idx];
                    ci.var_name = lv.name.c_str();
                    ci.var_is_stk = lv.is_stk_var();
                    ci.var_is_reg = lv.is_reg_var();
                    ci.var_is_arg = lv.is_arg_var();
                }
                break;
            case cot_obj:
                ci.obj_ea = expr->obj_ea;
                {
                    qstring name;
                    if (get_name(&name, expr->obj_ea) > 0) {
                        ci.obj_name = name.c_str();
                    }
                }
                break;
            case cot_num:
                ci.num_value = expr->numval();
                break;
            case cot_str:
                if (expr->string) ci.str_value = expr->string;
                break;
            case cot_helper:
                if (expr->helper) ci.helper_name = expr->helper;
                break;
            case cot_memref:
            case cot_memptr:
                ci.member_offset = expr->m;
                break;
            default:
                break;
        }

        items.push_back(ci);
        return 0;  // Continue traversal
    }

    // Post-process to fill in child IDs
    void resolve_child_ids() {
        for (auto& ci : items) {
            if (ci.item_id < 0) continue;

            // Find the original citem
            citem_t* item = nullptr;
            for (auto& kv : item_ids) {
                if (kv.second == ci.item_id) {
                    item = kv.first;
                    break;
                }
            }
            if (!item) continue;

            if (ci.is_expr) {
                cexpr_t* expr = static_cast<cexpr_t*>(item);

                // Expression children: x, y, z
                if (expr->x) {
                    auto it = item_ids.find(expr->x);
                    if (it != item_ids.end()) ci.x_id = it->second;
                }
                if (expr->y && expr->op != cot_call) {  // y is carglist for calls
                    auto it = item_ids.find(expr->y);
                    if (it != item_ids.end()) ci.y_id = it->second;
                }
                if (expr->z) {
                    auto it = item_ids.find(expr->z);
                    if (it != item_ids.end()) ci.z_id = it->second;
                }
            } else {
                cinsn_t* insn = static_cast<cinsn_t*>(item);

                // Statement children based on op
                switch (insn->op) {
                    case cit_if:
                        if (insn->cif) {
                            // Condition is in cif->expr (which is a cexpr_t)
                            auto cond_it = item_ids.find(&insn->cif->expr);
                            if (cond_it != item_ids.end()) ci.cond_id = cond_it->second;
                            if (insn->cif->ithen) {
                                auto it = item_ids.find(insn->cif->ithen);
                                if (it != item_ids.end()) ci.then_id = it->second;
                            }
                            if (insn->cif->ielse) {
                                auto it = item_ids.find(insn->cif->ielse);
                                if (it != item_ids.end()) ci.else_id = it->second;
                            }
                        }
                        break;
                    case cit_for:
                        if (insn->cfor) {
                            auto cond_it = item_ids.find(&insn->cfor->expr);
                            if (cond_it != item_ids.end()) ci.cond_id = cond_it->second;
                            auto init_it = item_ids.find(&insn->cfor->init);
                            if (init_it != item_ids.end()) ci.init_id = init_it->second;
                            auto step_it = item_ids.find(&insn->cfor->step);
                            if (step_it != item_ids.end()) ci.step_id = step_it->second;
                            if (insn->cfor->body) {
                                auto it = item_ids.find(insn->cfor->body);
                                if (it != item_ids.end()) ci.body_id = it->second;
                            }
                        }
                        break;
                    case cit_while:
                        if (insn->cwhile) {
                            auto cond_it = item_ids.find(&insn->cwhile->expr);
                            if (cond_it != item_ids.end()) ci.cond_id = cond_it->second;
                            if (insn->cwhile->body) {
                                auto it = item_ids.find(insn->cwhile->body);
                                if (it != item_ids.end()) ci.body_id = it->second;
                            }
                        }
                        break;
                    case cit_do:
                        if (insn->cdo) {
                            auto cond_it = item_ids.find(&insn->cdo->expr);
                            if (cond_it != item_ids.end()) ci.cond_id = cond_it->second;
                            if (insn->cdo->body) {
                                auto it = item_ids.find(insn->cdo->body);
                                if (it != item_ids.end()) ci.body_id = it->second;
                            }
                        }
                        break;
                    case cit_return:
                        if (insn->creturn) {
                            auto it = item_ids.find(&insn->creturn->expr);
                            if (it != item_ids.end()) ci.x_id = it->second;
                        }
                        break;
                    case cit_expr:
                        if (insn->cexpr) {
                            auto it = item_ids.find(insn->cexpr);
                            if (it != item_ids.end()) ci.x_id = it->second;
                        }
                        break;
                    default:
                        break;
                }
            }
        }
    }
};

// Helper: Collect ctree items for a function
static bool collect_ctree(std::vector<CtreeItem>& items, ea_t func_addr) {
    items.clear();

    if (!init_hexrays()) return false;

    func_t* f = get_func(func_addr);
    if (!f) return false;

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc) return false;

    ctree_collector_t collector(items, &*cfunc, func_addr);
    collector.apply_to(&cfunc->body, nullptr);
    collector.resolve_child_ids();

    return true;
}

// Helper: Collect ctree for all functions
static void collect_all_ctree(std::vector<CtreeItem>& items) {
    items.clear();

    if (!init_hexrays()) return;

    size_t func_qty = get_func_qty();
    for (size_t i = 0; i < func_qty; i++) {
        func_t* f = getn_func(i);
        if (!f) continue;

        std::vector<CtreeItem> func_items;
        if (collect_ctree(func_items, f->start_ea)) {
            items.insert(items.end(), func_items.begin(), func_items.end());
        }
    }
}

// xConnect
static int ctree_connect(sqlite3* db, void*, int, const char* const*,
                         sqlite3_vtab** ppVtab, char**) {
    int rc = sqlite3_declare_vtab(db, CTREE_SCHEMA);
    if (rc != SQLITE_OK) return rc;

    auto* vtab = new CtreeVtab();
    memset(&vtab->base, 0, sizeof(vtab->base));
    *ppVtab = &vtab->base;
    return SQLITE_OK;
}

// xDisconnect
static int ctree_disconnect(sqlite3_vtab* pVtab) {
    delete reinterpret_cast<CtreeVtab*>(pVtab);
    return SQLITE_OK;
}

// xOpen
static int ctree_open(sqlite3_vtab*, sqlite3_vtab_cursor** ppCursor) {
    auto* cursor = new CtreeCursor();
    memset(&cursor->base, 0, sizeof(cursor->base));
    cursor->idx = 0;
    cursor->filter_func_addr = 0;
    cursor->use_func_filter = false;
    *ppCursor = &cursor->base;
    return SQLITE_OK;
}

// xClose
static int ctree_close(sqlite3_vtab_cursor* pCursor) {
    delete reinterpret_cast<CtreeCursor*>(pCursor);
    return SQLITE_OK;
}

// xBestIndex
static int ctree_best_index(sqlite3_vtab*, sqlite3_index_info* pInfo) {
    int func_addr_idx = -1;

    for (int i = 0; i < pInfo->nConstraint; i++) {
        const auto& c = pInfo->aConstraint[i];
        if (c.usable && c.iColumn == CTREE_COL_FUNC_ADDR && c.op == SQLITE_INDEX_CONSTRAINT_EQ) {
            func_addr_idx = i;
            break;
        }
    }

    if (func_addr_idx >= 0) {
        pInfo->aConstraintUsage[func_addr_idx].argvIndex = 1;
        pInfo->aConstraintUsage[func_addr_idx].omit = 1;
        pInfo->idxNum = 1;  // Use func_addr filter
        pInfo->estimatedCost = 100.0;  // Medium cost - single function, decompilation
        pInfo->estimatedRows = 500;
    } else {
        pInfo->idxNum = 0;  // Full scan
        pInfo->estimatedCost = 1000000.0;  // Very high cost - all functions
        pInfo->estimatedRows = 100000;
    }

    return SQLITE_OK;
}

// xFilter
static int ctree_filter(sqlite3_vtab_cursor* pCursor, int idxNum, const char*,
                        int argc, sqlite3_value** argv) {
    auto* cursor = reinterpret_cast<CtreeCursor*>(pCursor);
    cursor->idx = 0;

    if (idxNum == 1 && argc >= 1) {
        cursor->filter_func_addr = sqlite3_value_int64(argv[0]);
        cursor->use_func_filter = true;
        collect_ctree(cursor->items, cursor->filter_func_addr);
    } else {
        cursor->use_func_filter = false;
        cursor->filter_func_addr = 0;
        collect_all_ctree(cursor->items);
    }

    return SQLITE_OK;
}

// xNext
static int ctree_next(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<CtreeCursor*>(pCursor);
    cursor->idx++;
    return SQLITE_OK;
}

// xEof
static int ctree_eof(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<CtreeCursor*>(pCursor);
    return cursor->idx >= cursor->items.size();
}

// xRowid
static int ctree_rowid(sqlite3_vtab_cursor* pCursor, sqlite3_int64* pRowid) {
    auto* cursor = reinterpret_cast<CtreeCursor*>(pCursor);
    *pRowid = cursor->idx;
    return SQLITE_OK;
}

// xColumn
static int ctree_column(sqlite3_vtab_cursor* pCursor, sqlite3_context* ctx, int col) {
    auto* cursor = reinterpret_cast<CtreeCursor*>(pCursor);

    if (cursor->idx >= cursor->items.size()) {
        sqlite3_result_null(ctx);
        return SQLITE_OK;
    }

    const CtreeItem& item = cursor->items[cursor->idx];

    switch (col) {
        case CTREE_COL_FUNC_ADDR:
            sqlite3_result_int64(ctx, item.func_addr);
            break;
        case CTREE_COL_ITEM_ID:
            sqlite3_result_int(ctx, item.item_id);
            break;
        case CTREE_COL_IS_EXPR:
            sqlite3_result_int(ctx, item.is_expr ? 1 : 0);
            break;
        case CTREE_COL_OP:
            sqlite3_result_int(ctx, item.op);
            break;
        case CTREE_COL_OP_NAME:
            sqlite3_result_text(ctx, item.op_name.c_str(), -1, SQLITE_TRANSIENT);
            break;
        case CTREE_COL_EA:
            if (item.ea != BADADDR) {
                sqlite3_result_int64(ctx, item.ea);
            } else {
                sqlite3_result_null(ctx);
            }
            break;
        case CTREE_COL_PARENT_ID:
            if (item.parent_id >= 0) {
                sqlite3_result_int(ctx, item.parent_id);
            } else {
                sqlite3_result_null(ctx);
            }
            break;
        case CTREE_COL_DEPTH:
            sqlite3_result_int(ctx, item.depth);
            break;
        case CTREE_COL_X_ID:
            if (item.x_id >= 0) sqlite3_result_int(ctx, item.x_id);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_Y_ID:
            if (item.y_id >= 0) sqlite3_result_int(ctx, item.y_id);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_Z_ID:
            if (item.z_id >= 0) sqlite3_result_int(ctx, item.z_id);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_COND_ID:
            if (item.cond_id >= 0) sqlite3_result_int(ctx, item.cond_id);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_THEN_ID:
            if (item.then_id >= 0) sqlite3_result_int(ctx, item.then_id);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_ELSE_ID:
            if (item.else_id >= 0) sqlite3_result_int(ctx, item.else_id);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_BODY_ID:
            if (item.body_id >= 0) sqlite3_result_int(ctx, item.body_id);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_INIT_ID:
            if (item.init_id >= 0) sqlite3_result_int(ctx, item.init_id);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_STEP_ID:
            if (item.step_id >= 0) sqlite3_result_int(ctx, item.step_id);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_VAR_IDX:
            if (item.var_idx >= 0) sqlite3_result_int(ctx, item.var_idx);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_OBJ_EA:
            if (item.obj_ea != BADADDR) sqlite3_result_int64(ctx, item.obj_ea);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_NUM_VALUE:
            if (item.op == cot_num) sqlite3_result_int64(ctx, item.num_value);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_STR_VALUE:
            if (!item.str_value.empty()) sqlite3_result_text(ctx, item.str_value.c_str(), -1, SQLITE_TRANSIENT);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_HELPER_NAME:
            if (!item.helper_name.empty()) sqlite3_result_text(ctx, item.helper_name.c_str(), -1, SQLITE_TRANSIENT);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_MEMBER_OFFSET:
            if (item.op == cot_memref || item.op == cot_memptr) sqlite3_result_int(ctx, item.member_offset);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_VAR_NAME:
            if (!item.var_name.empty()) sqlite3_result_text(ctx, item.var_name.c_str(), -1, SQLITE_TRANSIENT);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_VAR_IS_STK:
            if (item.op == cot_var) sqlite3_result_int(ctx, item.var_is_stk ? 1 : 0);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_VAR_IS_REG:
            if (item.op == cot_var) sqlite3_result_int(ctx, item.var_is_reg ? 1 : 0);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_VAR_IS_ARG:
            if (item.op == cot_var) sqlite3_result_int(ctx, item.var_is_arg ? 1 : 0);
            else sqlite3_result_null(ctx);
            break;
        case CTREE_COL_OBJ_NAME:
            if (!item.obj_name.empty()) sqlite3_result_text(ctx, item.obj_name.c_str(), -1, SQLITE_TRANSIENT);
            else sqlite3_result_null(ctx);
            break;
        default:
            sqlite3_result_null(ctx);
    }

    return SQLITE_OK;
}

// Module definition
static sqlite3_module ctree_module = {
    0,                    // iVersion
    ctree_connect,        // xCreate
    ctree_connect,        // xConnect
    ctree_best_index,     // xBestIndex
    ctree_disconnect,     // xDisconnect
    ctree_disconnect,     // xDestroy
    ctree_open,           // xOpen
    ctree_close,          // xClose
    ctree_filter,         // xFilter
    ctree_next,           // xNext
    ctree_eof,            // xEof
    ctree_column,         // xColumn
    ctree_rowid,          // xRowid
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr
};

// ============================================================================
// CTREE_CALL_ARGS Table
// ============================================================================
//
// Schema: ctree_call_args(func_addr, call_item_id, arg_idx, arg_item_id, arg_op,
//                         arg_var_idx, arg_var_name, arg_var_is_stk, arg_var_is_arg,
//                         arg_obj_ea, arg_obj_name, arg_num_value, arg_str_value)
//
// Flattened call arguments for easy queries.
// Supports func_addr constraint for efficient single-function queries.
// ============================================================================

enum CallArgsCol {
    CARGS_COL_FUNC_ADDR = 0,
    CARGS_COL_CALL_ITEM_ID,
    CARGS_COL_ARG_IDX,
    CARGS_COL_ARG_ITEM_ID,
    CARGS_COL_ARG_OP,
    CARGS_COL_ARG_VAR_IDX,
    CARGS_COL_ARG_VAR_NAME,
    CARGS_COL_ARG_VAR_IS_STK,
    CARGS_COL_ARG_VAR_IS_ARG,
    CARGS_COL_ARG_OBJ_EA,
    CARGS_COL_ARG_OBJ_NAME,
    CARGS_COL_ARG_NUM_VALUE,
    CARGS_COL_ARG_STR_VALUE
};

static const char* CALL_ARGS_SCHEMA =
    "CREATE TABLE ctree_call_args("
    "func_addr INTEGER, "
    "call_item_id INTEGER, "
    "arg_idx INTEGER, "
    "arg_item_id INTEGER, "
    "arg_op TEXT, "
    "arg_var_idx INTEGER, "
    "arg_var_name TEXT, "
    "arg_var_is_stk INTEGER, "
    "arg_var_is_arg INTEGER, "
    "arg_obj_ea INTEGER, "
    "arg_obj_name TEXT, "
    "arg_num_value INTEGER, "
    "arg_str_value TEXT)";

// Data for a single call argument
struct CallArgInfo {
    ea_t func_addr;
    int call_item_id;
    int arg_idx;
    int arg_item_id;
    std::string arg_op;
    int arg_var_idx;
    std::string arg_var_name;
    bool arg_var_is_stk;
    bool arg_var_is_arg;
    ea_t arg_obj_ea;
    std::string arg_obj_name;
    int64_t arg_num_value;
    std::string arg_str_value;

    CallArgInfo() : func_addr(0), call_item_id(-1), arg_idx(-1), arg_item_id(-1),
                    arg_var_idx(-1), arg_var_is_stk(false), arg_var_is_arg(false),
                    arg_obj_ea(BADADDR), arg_num_value(0) {}
};

// Virtual table structure
struct CallArgsVtab {
    sqlite3_vtab base;
};

// Cursor with cached args
struct CallArgsCursor {
    sqlite3_vtab_cursor base;
    std::vector<CallArgInfo> args;
    size_t idx;
    ea_t filter_func_addr;
    bool use_func_filter;
};

// Collector for call arguments - integrates with ctree traversal
struct call_args_collector_t : public ctree_parentee_t {
    std::vector<CallArgInfo>& args;
    std::map<citem_t*, int> item_ids;
    cfunc_t* cfunc;
    ea_t func_addr;
    int next_id;

    call_args_collector_t(std::vector<CallArgInfo>& args_, cfunc_t* cfunc_, ea_t func_addr_)
        : ctree_parentee_t(false), args(args_), cfunc(cfunc_), func_addr(func_addr_), next_id(0) {}

    int idaapi visit_insn(cinsn_t* insn) override {
        item_ids[insn] = next_id++;
        return 0;
    }

    int idaapi visit_expr(cexpr_t* expr) override {
        int my_id = next_id++;
        item_ids[expr] = my_id;

        // If this is a call, collect its arguments
        if (expr->op == cot_call && expr->a) {
            carglist_t& arglist = *expr->a;
            for (size_t i = 0; i < arglist.size(); i++) {
                const carg_t& arg = arglist[i];

                CallArgInfo ai;
                ai.func_addr = func_addr;
                ai.call_item_id = my_id;
                ai.arg_idx = i;
                ai.arg_op = get_full_ctype_name(arg.op);

                // Find or assign item_id for argument expression
                // Note: carg_t extends cexpr_t but may not be in main tree
                auto it = item_ids.find((citem_t*)&arg);
                if (it != item_ids.end()) {
                    ai.arg_item_id = it->second;
                } else {
                    ai.arg_item_id = next_id++;
                    item_ids[(citem_t*)&arg] = ai.arg_item_id;
                }

                // Denormalize argument data
                switch (arg.op) {
                    case cot_var:
                        ai.arg_var_idx = arg.v.idx;
                        if (cfunc && ai.arg_var_idx >= 0 && ai.arg_var_idx < cfunc->get_lvars()->size()) {
                            const lvar_t& lv = (*cfunc->get_lvars())[ai.arg_var_idx];
                            ai.arg_var_name = lv.name.c_str();
                            ai.arg_var_is_stk = lv.is_stk_var();
                            ai.arg_var_is_arg = lv.is_arg_var();
                        }
                        break;
                    case cot_obj:
                        ai.arg_obj_ea = arg.obj_ea;
                        {
                            qstring name;
                            if (get_name(&name, arg.obj_ea) > 0) {
                                ai.arg_obj_name = name.c_str();
                            }
                        }
                        break;
                    case cot_num:
                        ai.arg_num_value = arg.numval();
                        break;
                    case cot_str:
                        if (arg.string) ai.arg_str_value = arg.string;
                        break;
                    default:
                        break;
                }

                args.push_back(ai);
            }
        }

        return 0;
    }
};

// Helper: Collect call args for a function
static bool collect_call_args(std::vector<CallArgInfo>& args, ea_t func_addr) {
    args.clear();

    if (!init_hexrays()) return false;

    func_t* f = get_func(func_addr);
    if (!f) return false;

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc) return false;

    call_args_collector_t collector(args, &*cfunc, func_addr);
    collector.apply_to(&cfunc->body, nullptr);

    return true;
}

// Helper: Collect call args for all functions
static void collect_all_call_args(std::vector<CallArgInfo>& args) {
    args.clear();

    if (!init_hexrays()) return;

    size_t func_qty = get_func_qty();
    for (size_t i = 0; i < func_qty; i++) {
        func_t* f = getn_func(i);
        if (!f) continue;

        std::vector<CallArgInfo> func_args;
        if (collect_call_args(func_args, f->start_ea)) {
            args.insert(args.end(), func_args.begin(), func_args.end());
        }
    }
}

// xConnect
static int cargs_connect(sqlite3* db, void*, int, const char* const*,
                         sqlite3_vtab** ppVtab, char**) {
    int rc = sqlite3_declare_vtab(db, CALL_ARGS_SCHEMA);
    if (rc != SQLITE_OK) return rc;

    auto* vtab = new CallArgsVtab();
    memset(&vtab->base, 0, sizeof(vtab->base));
    *ppVtab = &vtab->base;
    return SQLITE_OK;
}

// xDisconnect
static int cargs_disconnect(sqlite3_vtab* pVtab) {
    delete reinterpret_cast<CallArgsVtab*>(pVtab);
    return SQLITE_OK;
}

// xOpen
static int cargs_open(sqlite3_vtab*, sqlite3_vtab_cursor** ppCursor) {
    auto* cursor = new CallArgsCursor();
    memset(&cursor->base, 0, sizeof(cursor->base));
    cursor->idx = 0;
    cursor->filter_func_addr = 0;
    cursor->use_func_filter = false;
    *ppCursor = &cursor->base;
    return SQLITE_OK;
}

// xClose
static int cargs_close(sqlite3_vtab_cursor* pCursor) {
    delete reinterpret_cast<CallArgsCursor*>(pCursor);
    return SQLITE_OK;
}

// xBestIndex
static int cargs_best_index(sqlite3_vtab*, sqlite3_index_info* pInfo) {
    int func_addr_idx = -1;

    for (int i = 0; i < pInfo->nConstraint; i++) {
        const auto& c = pInfo->aConstraint[i];
        if (c.usable && c.iColumn == CARGS_COL_FUNC_ADDR && c.op == SQLITE_INDEX_CONSTRAINT_EQ) {
            func_addr_idx = i;
            break;
        }
    }

    if (func_addr_idx >= 0) {
        pInfo->aConstraintUsage[func_addr_idx].argvIndex = 1;
        pInfo->aConstraintUsage[func_addr_idx].omit = 1;
        pInfo->idxNum = 1;
        pInfo->estimatedCost = 100.0;
        pInfo->estimatedRows = 200;
    } else {
        pInfo->idxNum = 0;
        pInfo->estimatedCost = 1000000.0;
        pInfo->estimatedRows = 50000;
    }

    return SQLITE_OK;
}

// xFilter
static int cargs_filter(sqlite3_vtab_cursor* pCursor, int idxNum, const char*,
                        int argc, sqlite3_value** argv) {
    auto* cursor = reinterpret_cast<CallArgsCursor*>(pCursor);
    cursor->idx = 0;

    if (idxNum == 1 && argc >= 1) {
        cursor->filter_func_addr = sqlite3_value_int64(argv[0]);
        cursor->use_func_filter = true;
        collect_call_args(cursor->args, cursor->filter_func_addr);
    } else {
        cursor->use_func_filter = false;
        cursor->filter_func_addr = 0;
        collect_all_call_args(cursor->args);
    }

    return SQLITE_OK;
}

// xNext
static int cargs_next(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<CallArgsCursor*>(pCursor);
    cursor->idx++;
    return SQLITE_OK;
}

// xEof
static int cargs_eof(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<CallArgsCursor*>(pCursor);
    return cursor->idx >= cursor->args.size();
}

// xRowid
static int cargs_rowid(sqlite3_vtab_cursor* pCursor, sqlite3_int64* pRowid) {
    auto* cursor = reinterpret_cast<CallArgsCursor*>(pCursor);
    *pRowid = cursor->idx;
    return SQLITE_OK;
}

// xColumn
static int cargs_column(sqlite3_vtab_cursor* pCursor, sqlite3_context* ctx, int col) {
    auto* cursor = reinterpret_cast<CallArgsCursor*>(pCursor);

    if (cursor->idx >= cursor->args.size()) {
        sqlite3_result_null(ctx);
        return SQLITE_OK;
    }

    const CallArgInfo& ai = cursor->args[cursor->idx];

    switch (col) {
        case CARGS_COL_FUNC_ADDR:
            sqlite3_result_int64(ctx, ai.func_addr);
            break;
        case CARGS_COL_CALL_ITEM_ID:
            sqlite3_result_int(ctx, ai.call_item_id);
            break;
        case CARGS_COL_ARG_IDX:
            sqlite3_result_int(ctx, ai.arg_idx);
            break;
        case CARGS_COL_ARG_ITEM_ID:
            if (ai.arg_item_id >= 0) sqlite3_result_int(ctx, ai.arg_item_id);
            else sqlite3_result_null(ctx);
            break;
        case CARGS_COL_ARG_OP:
            sqlite3_result_text(ctx, ai.arg_op.c_str(), -1, SQLITE_TRANSIENT);
            break;
        case CARGS_COL_ARG_VAR_IDX:
            if (ai.arg_var_idx >= 0) sqlite3_result_int(ctx, ai.arg_var_idx);
            else sqlite3_result_null(ctx);
            break;
        case CARGS_COL_ARG_VAR_NAME:
            if (!ai.arg_var_name.empty()) sqlite3_result_text(ctx, ai.arg_var_name.c_str(), -1, SQLITE_TRANSIENT);
            else sqlite3_result_null(ctx);
            break;
        case CARGS_COL_ARG_VAR_IS_STK:
            if (ai.arg_var_idx >= 0) sqlite3_result_int(ctx, ai.arg_var_is_stk ? 1 : 0);
            else sqlite3_result_null(ctx);
            break;
        case CARGS_COL_ARG_VAR_IS_ARG:
            if (ai.arg_var_idx >= 0) sqlite3_result_int(ctx, ai.arg_var_is_arg ? 1 : 0);
            else sqlite3_result_null(ctx);
            break;
        case CARGS_COL_ARG_OBJ_EA:
            if (ai.arg_obj_ea != BADADDR) sqlite3_result_int64(ctx, ai.arg_obj_ea);
            else sqlite3_result_null(ctx);
            break;
        case CARGS_COL_ARG_OBJ_NAME:
            if (!ai.arg_obj_name.empty()) sqlite3_result_text(ctx, ai.arg_obj_name.c_str(), -1, SQLITE_TRANSIENT);
            else sqlite3_result_null(ctx);
            break;
        case CARGS_COL_ARG_NUM_VALUE:
            if (ai.arg_op == "cot_num") sqlite3_result_int64(ctx, ai.arg_num_value);
            else sqlite3_result_null(ctx);
            break;
        case CARGS_COL_ARG_STR_VALUE:
            if (!ai.arg_str_value.empty()) sqlite3_result_text(ctx, ai.arg_str_value.c_str(), -1, SQLITE_TRANSIENT);
            else sqlite3_result_null(ctx);
            break;
        default:
            sqlite3_result_null(ctx);
    }

    return SQLITE_OK;
}

// Module definition
static sqlite3_module cargs_module = {
    0,                    // iVersion
    cargs_connect,        // xCreate
    cargs_connect,        // xConnect
    cargs_best_index,     // xBestIndex
    cargs_disconnect,     // xDisconnect
    cargs_disconnect,     // xDestroy
    cargs_open,           // xOpen
    cargs_close,          // xClose
    cargs_filter,         // xFilter
    cargs_next,           // xNext
    cargs_eof,            // xEof
    cargs_column,         // xColumn
    cargs_rowid,          // xRowid
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
    int rc = sqlite3_create_module(db, "ida_ctree_lvars", &lvars_module, nullptr);
    if (rc != SQLITE_OK) return false;

    char* err = nullptr;
    rc = sqlite3_exec(db, "CREATE VIRTUAL TABLE ctree_lvars USING ida_ctree_lvars;",
                      nullptr, nullptr, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

inline bool register_ctree_table(sqlite3* db) {
    int rc = sqlite3_create_module(db, "ida_ctree", &ctree_module, nullptr);
    if (rc != SQLITE_OK) return false;

    char* err = nullptr;
    rc = sqlite3_exec(db, "CREATE VIRTUAL TABLE ctree USING ida_ctree;",
                      nullptr, nullptr, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

inline bool register_ctree_call_args_table(sqlite3* db) {
    int rc = sqlite3_create_module(db, "ida_ctree_call_args", &cargs_module, nullptr);
    if (rc != SQLITE_OK) return false;

    char* err = nullptr;
    rc = sqlite3_exec(db, "CREATE VIRTUAL TABLE ctree_call_args USING ida_ctree_call_args;",
                      nullptr, nullptr, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

inline bool register_ctree_views(sqlite3* db) {
    char* err = nullptr;

    // ctree_v_calls - All function calls with callee info
    const char* v_calls = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_calls AS
        SELECT
            c.func_addr, c.item_id, c.ea,
            x.op_name AS callee_op,
            x.obj_ea AS callee_addr,
            x.obj_name AS callee_name,
            x.helper_name,
            (SELECT COUNT(*) FROM ctree_call_args a
             WHERE a.func_addr = c.func_addr AND a.call_item_id = c.item_id) AS arg_count
        FROM ctree c
        LEFT JOIN ctree x ON x.func_addr = c.func_addr AND x.item_id = c.x_id
        WHERE c.op_name = 'cot_call'
    )";
    sqlite3_exec(db, v_calls, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    // ctree_v_loops - All loops (for, while, do)
    const char* v_loops = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_loops AS
        SELECT * FROM ctree
        WHERE op_name IN ('cit_for', 'cit_while', 'cit_do')
    )";
    sqlite3_exec(db, v_loops, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    // ctree_v_ifs - All if statements
    const char* v_ifs = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_ifs AS
        SELECT * FROM ctree WHERE op_name = 'cit_if'
    )";
    sqlite3_exec(db, v_ifs, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    // ctree_v_signed_ops - Signed operations (vulnerability pattern)
    const char* v_signed = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_signed_ops AS
        SELECT * FROM ctree WHERE op_name IN (
            'cot_sge', 'cot_sle', 'cot_sgt', 'cot_slt',
            'cot_sshr', 'cot_sdiv', 'cot_smod',
            'cot_asgsshr', 'cot_asgsdiv', 'cot_asgsmod'
        )
    )";
    sqlite3_exec(db, v_signed, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    // ctree_v_comparisons - All comparison expressions
    const char* v_cmp = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_comparisons AS
        SELECT
            c.func_addr, c.item_id, c.ea, c.op_name,
            lhs.op_name AS lhs_op, lhs.var_idx AS lhs_var_idx, lhs.num_value AS lhs_num,
            rhs.op_name AS rhs_op, rhs.var_idx AS rhs_var_idx, rhs.num_value AS rhs_num
        FROM ctree c
        LEFT JOIN ctree lhs ON lhs.func_addr = c.func_addr AND lhs.item_id = c.x_id
        LEFT JOIN ctree rhs ON rhs.func_addr = c.func_addr AND rhs.item_id = c.y_id
        WHERE c.op_name IN (
            'cot_eq', 'cot_ne',
            'cot_sge', 'cot_uge', 'cot_sle', 'cot_ule',
            'cot_sgt', 'cot_ugt', 'cot_slt', 'cot_ult'
        )
    )";
    sqlite3_exec(db, v_cmp, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    // ctree_v_assignments - All assignments with lhs/rhs info
    const char* v_asg = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_assignments AS
        SELECT
            c.func_addr, c.item_id, c.ea, c.op_name,
            lhs.op_name AS lhs_op, lhs.var_idx AS lhs_var_idx,
            lhs.var_is_stk AS lhs_is_stk, lhs.obj_ea AS lhs_obj,
            rhs.op_name AS rhs_op, rhs.var_idx AS rhs_var_idx, rhs.num_value AS rhs_num
        FROM ctree c
        LEFT JOIN ctree lhs ON lhs.func_addr = c.func_addr AND lhs.item_id = c.x_id
        LEFT JOIN ctree rhs ON rhs.func_addr = c.func_addr AND rhs.item_id = c.y_id
        WHERE c.op_name LIKE 'cot_asg%'
    )";
    sqlite3_exec(db, v_asg, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    // ctree_v_derefs - Pointer dereferences
    const char* v_deref = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_derefs AS
        SELECT
            c.func_addr, c.item_id, c.ea,
            x.op_name AS ptr_op, x.var_idx AS ptr_var_idx,
            x.var_is_stk AS ptr_is_stk, x.var_is_arg AS ptr_is_arg
        FROM ctree c
        LEFT JOIN ctree x ON x.func_addr = c.func_addr AND x.item_id = c.x_id
        WHERE c.op_name IN ('cot_ptr', 'cot_memptr')
    )";
    sqlite3_exec(db, v_deref, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    // ctree_v_calls_in_loops - All calls inside loop constructs (recursive CTE)
    const char* v_calls_in_loops = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_calls_in_loops AS
        WITH RECURSIVE loop_contents(func_addr, item_id, loop_id, loop_op, depth) AS (
            -- Base: all loops
            SELECT func_addr, item_id, item_id, op_name, 0
            FROM ctree
            WHERE op_name IN ('cit_for', 'cit_while', 'cit_do')

            UNION ALL

            -- Recursive: all children of loop contents
            SELECT c.func_addr, c.item_id, lc.loop_id, lc.loop_op, lc.depth + 1
            FROM ctree c
            JOIN loop_contents lc ON c.func_addr = lc.func_addr AND c.parent_id = lc.item_id
            WHERE lc.depth < 50
        )
        SELECT DISTINCT
            c.func_addr,
            c.item_id,
            c.ea,
            c.depth AS call_depth,
            lc.loop_id,
            lc.loop_op,
            x.obj_ea AS callee_addr,
            x.obj_name AS callee_name,
            x.helper_name
        FROM loop_contents lc
        JOIN ctree c ON c.func_addr = lc.func_addr AND c.item_id = lc.item_id
        LEFT JOIN ctree x ON x.func_addr = c.func_addr AND x.item_id = c.x_id
        WHERE c.op_name = 'cot_call'
    )";
    sqlite3_exec(db, v_calls_in_loops, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    // ctree_v_calls_in_ifs - All calls inside if branches (recursive CTE)
    const char* v_calls_in_ifs = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_calls_in_ifs AS
        WITH RECURSIVE if_contents(func_addr, item_id, if_id, branch, depth) AS (
            -- Base: 'then' branches (ithen is child of if with then_id)
            SELECT c.func_addr, c.item_id, p.item_id, 'then', 0
            FROM ctree c
            JOIN ctree p ON c.func_addr = p.func_addr AND c.item_id = p.then_id
            WHERE p.op_name = 'cit_if'

            UNION ALL

            -- Base: 'else' branches
            SELECT c.func_addr, c.item_id, p.item_id, 'else', 0
            FROM ctree c
            JOIN ctree p ON c.func_addr = p.func_addr AND c.item_id = p.else_id
            WHERE p.op_name = 'cit_if'

            UNION ALL

            -- Recursive: all children
            SELECT c.func_addr, c.item_id, ic.if_id, ic.branch, ic.depth + 1
            FROM ctree c
            JOIN if_contents ic ON c.func_addr = ic.func_addr AND c.parent_id = ic.item_id
            WHERE ic.depth < 50
        )
        SELECT DISTINCT
            c.func_addr,
            c.item_id,
            c.ea,
            c.depth AS call_depth,
            ic.if_id,
            ic.branch,
            x.obj_ea AS callee_addr,
            x.obj_name AS callee_name,
            x.helper_name
        FROM if_contents ic
        JOIN ctree c ON c.func_addr = ic.func_addr AND c.item_id = ic.item_id
        LEFT JOIN ctree x ON x.func_addr = c.func_addr AND x.item_id = c.x_id
        WHERE c.op_name = 'cot_call'
    )";
    sqlite3_exec(db, v_calls_in_ifs, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    return true;
}

// Registry for all decompiler tables
struct DecompilerRegistry {
    void register_all(sqlite3* db) {
        register_pseudocode_table(db);
        register_lvars_table(db);
        register_ctree_table(db);
        register_ctree_call_args_table(db);
        register_ctree_views(db);
    }
};

} // namespace decompiler
} // namespace idasql
