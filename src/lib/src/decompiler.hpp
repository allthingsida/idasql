// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * decompiler.hpp - Hex-Rays decompiler virtual tables (pseudocode, ctree, lvars, call args)
 *
 * Provides SQLite virtual tables for accessing decompiled function data:
 *   pseudocode       - Decompiled function pseudocode lines
 *   ctree_lvars      - Local variables from decompiled functions
 *   ctree_labels     - User/default labels for decompiled control flow
 *   ctree            - Full AST (expressions and statements)
 *   ctree_call_args  - Flattened call arguments
 *
 * All tables support constraint pushdown on func_addr via filter_eq framework:
 *   SELECT * FROM pseudocode WHERE func_addr = 0x401000;
 *   SELECT * FROM ctree_lvars WHERE func_addr = 0x401000;
 *
 * Requires Hex-Rays decompiler license.
 */

#pragma once

#include <idasql/platform.hpp>

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include <string>
#include <vector>
#include <map>

#include "ida_headers.hpp"

namespace idasql {
namespace decompiler {

// ============================================================================
// Decompiler Initialization
// ============================================================================

// Global flag tracking if Hex-Rays is available.
// Set once during DecompilerRegistry::register_all().
// Must remain inline with static bool -- called from multiple TUs
// (functions.hpp, database.hpp, decompiler.cpp).
inline bool& hexrays_available() {
    static bool available = false;
    return available;
}

// Initialize Hex-Rays decompiler - call ONCE at startup.
// Returns true if decompiler is available.
bool init_hexrays();

// Invalidate decompiler cache for the function containing ea.
// Safe to call even if Hex-Rays is unavailable or ea is not in a function.
void invalidate_decompiler_cache(ea_t ea);

// ============================================================================
// Data Structures
// ============================================================================

// ITP name / enum helpers
const char* itp_to_name(item_preciser_t itp);
item_preciser_t name_to_itp(const char* name);

// Pseudocode line data
struct PseudocodeLine {
    ea_t func_addr;
    int line_num;
    std::string text;
    ea_t ea;              // Associated address (from COLOR_ADDR anchor)
    std::string comment;  // User comment at this ea (from restore_user_cmts)
    item_preciser_t comment_placement = ITP_SEMI;  // Comment placement type
};

// Local variable data
struct LvarInfo {
    ea_t func_addr;
    int idx;
    std::string name;
    std::string type;
    std::string comment;
    int size;
    bool is_arg;
    bool is_result;
    bool is_stk_var;
    bool is_reg_var;
    sval_t stkoff;
    mreg_t mreg;
};

// Local variable rename result with explicit post-apply observability.
struct LvarRenameResult {
    bool success = false;         // Operation executed without internal API failure
    bool applied = false;         // Observed name changed to requested target
    ea_t func_addr = BADADDR;
    int lvar_idx = -1;
    std::string target_name;      // Original name selector (for by-name API)
    std::string requested_name;   // Requested new name
    std::string before_name;      // Name before mutation
    std::string after_name;       // Name after mutation/readback
    std::string reason;           // not_found, ambiguous_name, unchanged, not_nameable, etc.
    std::vector<std::string> warnings;
};

// Ctree item data
struct CtreeItem {
    ea_t func_addr;
    int item_id;
    bool is_expr;
    int op;
    std::string op_name;
    ea_t ea;
    int parent_id;
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
    int label_num;
    int goto_label_num;

    CtreeItem() : func_addr(0), item_id(-1), is_expr(false), op(0), ea(BADADDR),
                  parent_id(-1), depth(0),
                  x_id(-1), y_id(-1), z_id(-1),
                  cond_id(-1), then_id(-1), else_id(-1),
                  body_id(-1), init_id(-1), step_id(-1),
                  var_idx(-1), obj_ea(BADADDR), num_value(0), member_offset(0),
                  var_is_stk(false), var_is_reg(false), var_is_arg(false),
                  label_num(-1), goto_label_num(-1) {}
};

// Ctree label data
struct CtreeLabelInfo {
    ea_t func_addr;
    int label_num;
    std::string name;
    int item_id;
    ea_t item_ea;
    bool is_user_defined;

    CtreeLabelInfo() : func_addr(0), label_num(-1), item_id(-1), item_ea(BADADDR),
                       is_user_defined(false) {}
};

// Label rename result with explicit post-apply observability.
struct LabelRenameResult {
    bool success = false;
    bool applied = false;
    ea_t func_addr = BADADDR;
    int label_num = -1;
    std::string requested_name;
    std::string before_name;
    std::string after_name;
    std::string reason;
    std::vector<std::string> warnings;
};

// Call argument data
struct CallArgInfo {
    ea_t func_addr;
    int call_item_id;
    ea_t call_ea;
    std::string call_obj_name;
    std::string call_helper_name;
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

    CallArgInfo() : func_addr(0), call_item_id(-1), call_ea(BADADDR), arg_idx(-1), arg_item_id(-1),
                    arg_var_idx(-1), arg_var_is_stk(false), arg_var_is_arg(false),
                    arg_obj_ea(BADADDR), arg_num_value(0) {}
};

// ============================================================================
// Helper Functions
// ============================================================================

// Get full ctype name with cot_/cit_ prefix
std::string get_full_ctype_name(ctype_t op);

// Extract the first COLOR_ADDR anchor ea from a raw pseudocode line.
// Returns BADADDR if no anchor found.
ea_t extract_line_ea(cfunc_t* cfunc, const qstring& raw_line);

// ============================================================================
// Collect Functions
// ============================================================================

// Collect pseudocode for a single function
bool collect_pseudocode(std::vector<PseudocodeLine>& lines, ea_t func_addr);

// Collect pseudocode for all functions
void collect_all_pseudocode(std::vector<PseudocodeLine>& lines);

// Collect lvars for a single function
bool collect_lvars(std::vector<LvarInfo>& vars, ea_t func_addr);

// Collect lvars for all functions
void collect_all_lvars(std::vector<LvarInfo>& vars);

// Collect ctree items for a single function
bool collect_ctree(std::vector<CtreeItem>& items, ea_t func_addr);

// Collect ctree for all functions
void collect_all_ctree(std::vector<CtreeItem>& items);

// Collect ctree labels for a single function
bool collect_ctree_labels(std::vector<CtreeLabelInfo>& rows, ea_t func_addr);

// Collect ctree labels for all functions
void collect_all_ctree_labels(std::vector<CtreeLabelInfo>& rows);

// Collect call args for a single function
bool collect_call_args(std::vector<CallArgInfo>& args, ea_t func_addr);

// Collect call args for all functions
void collect_all_call_args(std::vector<CallArgInfo>& args);

// ============================================================================
// Collector Visitors
// ============================================================================

// Ctree collector visitor
struct ctree_collector_t : public ctree_parentee_t {
    std::vector<CtreeItem>& items;
    std::map<citem_t*, int> item_ids;
    cfunc_t* cfunc;
    ea_t func_addr;
    int next_id;

    ctree_collector_t(std::vector<CtreeItem>& items_, cfunc_t* cfunc_, ea_t func_addr_);

    int idaapi visit_insn(cinsn_t* insn) override;
    int idaapi visit_expr(cexpr_t* expr) override;
    void resolve_child_ids();
};

// Call args collector visitor
struct call_args_collector_t : public ctree_parentee_t {
    std::vector<CallArgInfo>& args;
    std::map<citem_t*, int> item_ids;
    cfunc_t* cfunc;
    ea_t func_addr;
    int next_id;

    call_args_collector_t(std::vector<CallArgInfo>& args_, cfunc_t* cfunc_, ea_t func_addr_);

    int idaapi visit_insn(cinsn_t* insn) override;
    int idaapi visit_expr(cexpr_t* expr) override;
};

// ============================================================================
// Iterators for constraint pushdown
// ============================================================================

// Pseudocode iterator for single function
class PseudocodeInFuncIterator : public xsql::RowIterator {
    std::vector<PseudocodeLine> lines_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit PseudocodeInFuncIterator(ea_t func_addr);
    bool next() override;
    bool eof() const override;
    void column(xsql::FunctionContext& ctx, int col) override;
    int64_t rowid() const override;
};

// Pseudocode iterator for a single mapped address
class PseudocodeAtEaIterator : public xsql::RowIterator {
    std::vector<PseudocodeLine> lines_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit PseudocodeAtEaIterator(ea_t ea);
    bool next() override;
    bool eof() const override;
    void column(xsql::FunctionContext& ctx, int col) override;
    int64_t rowid() const override;
};

// Pseudocode iterator for line number across all functions
class PseudocodeLineNumIterator : public xsql::RowIterator {
    std::vector<PseudocodeLine> lines_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit PseudocodeLineNumIterator(int line_num);
    bool next() override;
    bool eof() const override;
    void column(xsql::FunctionContext& ctx, int col) override;
    int64_t rowid() const override;
};

// Lvars iterator for single function
class LvarsInFuncIterator : public xsql::RowIterator {
    std::vector<LvarInfo> vars_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit LvarsInFuncIterator(ea_t func_addr);
    bool next() override;
    bool eof() const override;
    void column(xsql::FunctionContext& ctx, int col) override;
    int64_t rowid() const override;
};

// Ctree iterator for single function
class CtreeInFuncIterator : public xsql::RowIterator {
    std::vector<CtreeItem> items_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit CtreeInFuncIterator(ea_t func_addr);
    bool next() override;
    bool eof() const override;
    void column(xsql::FunctionContext& ctx, int col) override;
    int64_t rowid() const override;
};

// Call args iterator for single function
class CallArgsInFuncIterator : public xsql::RowIterator {
    std::vector<CallArgInfo> args_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit CallArgsInFuncIterator(ea_t func_addr);
    bool next() override;
    bool eof() const override;
    void column(xsql::FunctionContext& ctx, int col) override;
    int64_t rowid() const override;
};

// ============================================================================
// Generators for full scans (lazy, one function at a time)
// ============================================================================

class CtreeGenerator : public xsql::Generator<CtreeItem> {
    size_t func_idx_ = 0;
    std::vector<CtreeItem> items_;
    size_t idx_ = 0;
    int64_t rowid_ = -1;
    bool started_ = false;

    bool load_next_func();

public:
    bool next() override;
    const CtreeItem& current() const override;
    int64_t rowid() const override;
};

class CallArgsGenerator : public xsql::Generator<CallArgInfo> {
    size_t func_idx_ = 0;
    std::vector<CallArgInfo> args_;
    size_t idx_ = 0;
    int64_t rowid_ = -1;
    bool started_ = false;

    bool load_next_func();

public:
    bool next() override;
    const CallArgInfo& current() const override;
    int64_t rowid() const override;
};

// ============================================================================
// Comment / Union Helpers
// ============================================================================

// Set or delete a decompiler comment at an ea within a function
bool set_decompiler_comment(ea_t func_addr, ea_t target_ea, const char* comment, item_preciser_t itp = ITP_SEMI);

// Clear any existing comment regardless of placement
bool clear_decompiler_comment_all_placements(ea_t func_addr, ea_t target_ea);

// Resolve an EA for a ctree item within a function
bool get_ctree_item_ea(ea_t func_addr, int item_id, ea_t& out_ea);

// Persist user union selection path for an EA. Empty path clears selection.
bool set_union_selection_at_ea(ea_t func_addr, ea_t target_ea, const intvec_t& path);

// Persist user union selection path by ctree item id.
bool set_union_selection_at_item(ea_t func_addr, int item_id, const intvec_t& path);

// Read user union selection path for an EA. Returns false when not found.
bool get_union_selection_at_ea(ea_t func_addr, ea_t target_ea, intvec_t& out_path);

// ============================================================================
// Lvar Helpers
// ============================================================================

// Snapshot one lvar from a function by index.
bool get_lvar_snapshot(ea_t func_addr, int lvar_idx, LvarInfo& out);

// Rename lvar by func_addr and lvar index with explicit readback validation.
LvarRenameResult rename_lvar_at_ex(ea_t func_addr, int lvar_idx, const char* new_name);

// Rename lvar by idx preserving legacy bool return.
// Returns true on a successful mutation or a no-op unchanged rename.
bool rename_lvar_at(ea_t func_addr, int lvar_idx, const char* new_name);

// Rename lvar by old name (exact match).
LvarRenameResult rename_lvar_by_name_ex(ea_t func_addr, const char* old_name, const char* new_name);

// Set lvar type by func_addr and lvar index
bool set_lvar_type_at(ea_t func_addr, int lvar_idx, const char* type_str);

// Set lvar comment by func_addr and lvar index
bool set_lvar_comment_at(ea_t func_addr, int lvar_idx, const char* comment);

// Snapshot one label from a function by label number.
bool get_label_snapshot(ea_t func_addr, int label_num, CtreeLabelInfo& out);

// Rename label by func_addr and label number with explicit readback validation.
LabelRenameResult rename_label_ex(ea_t func_addr, int label_num, const char* new_name);

// Rename label preserving legacy bool return semantics.
bool rename_label(ea_t func_addr, int label_num, const char* new_name);

// ============================================================================
// Table Definitions
// ============================================================================

CachedTableDef<PseudocodeLine> define_pseudocode();
CachedTableDef<LvarInfo> define_ctree_lvars();
CachedTableDef<CtreeLabelInfo> define_ctree_labels();
GeneratorTableDef<CtreeItem> define_ctree();
GeneratorTableDef<CallArgInfo> define_ctree_call_args();

// ============================================================================
// Views Registration
// ============================================================================

bool register_ctree_views(xsql::Database& db);

// ============================================================================
// Registry
// ============================================================================

struct DecompilerRegistry {
    // Cached tables (query-scoped cache, write support)
    CachedTableDef<PseudocodeLine> pseudocode;
    CachedTableDef<LvarInfo> ctree_lvars;
    CachedTableDef<CtreeLabelInfo> ctree_labels;
    // Generator tables (lazy full scans)
    GeneratorTableDef<CtreeItem> ctree;
    GeneratorTableDef<CallArgInfo> ctree_call_args;

    DecompilerRegistry();
    void register_all(xsql::Database& db);
};

} // namespace decompiler
} // namespace idasql
