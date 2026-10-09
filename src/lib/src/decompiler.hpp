// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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
#include <optional>

#include "ida_headers.hpp"

namespace idasql {
namespace decompiler {

// ============================================================================
// Decompiler Initialization
// ============================================================================

// Global flag tracking if Hex-Rays is available.
// Set once during DecompilerRegistry::register_all().
// Must remain inline with static bool -- called from multiple TUs
// (functions.hpp, database.hpp, decompiler_ctree.cpp, decompiler_mc.cpp).
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

// Every idasql decompilation goes through this one wrapper around
// idasql_decompile(). Hex-Rays stores a guessed prototype the first time it
// decompiles a function (an IDB change); here that is a side effect of reading,
// so it is not counted as a write by the checkpoint redo guard or
// auto_checkpoint. The caller's own edits after it are counted as usual.
cfuncptr_t decompile_for_read(ea_t ea, hexrays_failure_t* hf = nullptr, int decomp_flags = 0);

// Apply an explicit callee type to one call site. `name` is the user-defined call's
// display name (must be non-empty; defaults to a safe placeholder when not supplied).
bool apply_callee_tinfo_at(ea_t call_ea, const tinfo_t& tif, const char* name = nullptr);

// Clear an explicit callee type at one call site.
bool clear_callee_tinfo_at(ea_t call_ea);

// Read explicit operand/call-site type info from a call instruction.
bool get_callee_tinfo_at(ea_t call_ea, tinfo_t& out_tif);

// Parse a callee declaration into a function tinfo. If `out_name` is non-null it
// receives the parsed function name (used as the user-defined call's display name).
bool parse_callee_decl(const char* decl_text, tinfo_t& out_tif, qstring* out_name = nullptr);

// Read stored argument-loader addresses for a call site.
bool get_call_arg_addrs(ea_t call_ea, eavec_t& out_addrs);

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

// Persisted decompiler comments that no longer map to the current ctree/pseudocode.
struct OrphanCommentInfo {
    uint32_t ordinal = 0;  // position among the function's orphans (rowid local index)
    ea_t func_addr;
    std::string func_name;
    ea_t ea;
    item_preciser_t comment_placement = ITP_SEMI;
    std::string orphan_comment;
};

// One grouped orphan summary row per function.
struct OrphanCommentGroupInfo {
    ea_t func_addr;
    std::string func_name;
    int orphan_count = 0;
    std::string orphan_comments_json;
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
    int after_idx = -1;           // The lvar's index after the rename (Hex-Rays may re-order)
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

// Collect orphan comments for a single function
bool collect_orphan_comments(std::vector<OrphanCommentInfo>& rows, ea_t func_addr);

// Collect orphan comments for all functions
void collect_all_orphan_comments(std::vector<OrphanCommentInfo>& rows);

// Collect grouped orphan comment summary for a single function.
bool collect_orphan_comment_group(OrphanCommentGroupInfo& row, ea_t func_addr);

// Collect grouped orphan comment summaries for all functions.
void collect_all_orphan_comment_groups(std::vector<OrphanCommentGroupInfo>& rows);

// Collect lvars for a single function
bool collect_lvars(std::vector<LvarInfo>& vars, ea_t func_addr);

// Collect lvars for all functions
void collect_all_lvars(std::vector<LvarInfo>& vars);

// Collect ctree items for a single function
bool collect_ctree(std::vector<CtreeItem>& items, ea_t func_addr);

// Collect ctree labels for a single function
bool collect_ctree_labels(std::vector<CtreeLabelInfo>& rows, ea_t func_addr);

// Collect ctree labels for all functions
void collect_all_ctree_labels(std::vector<CtreeLabelInfo>& rows);

// Collect call args for a single function
bool collect_call_args(std::vector<CallArgInfo>& args, ea_t func_addr);

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

// Call args collector visitor.
//
// Two-pass: ids are assigned ONLY at visit time (single pass over the ctree,
// identical to ctree_collector_t's scheme), so call_item_id / arg_item_id match
// the corresponding ctree.item_id. During the walk we record each call site and
// its argument expr pointers WITHOUT resolving ids (an arg's cexpr_t is visited
// -- and numbered -- only after its parent cot_call). After apply_to() completes,
// finalize() emits the CallArgInfo rows, resolving ids from the completed
// item_ids map.
struct call_args_collector_t : public ctree_parentee_t {
    // One captured call site awaiting id resolution in finalize().
    struct PendingCall {
        cexpr_t* call = nullptr;        // the cot_call expr (its id -> call_item_id)
        ea_t call_ea = BADADDR;
        std::string call_obj_name;
        std::string call_helper_name;
        std::vector<const carg_t*> arg_ptrs;  // per-arg expr pointer (its id -> arg_item_id)
    };

    std::vector<CallArgInfo>& args;
    std::map<citem_t*, int> item_ids;
    std::vector<PendingCall> pending_calls;
    cfunc_t* cfunc;
    ea_t func_addr;
    int next_id;

    call_args_collector_t(std::vector<CallArgInfo>& args_, cfunc_t* cfunc_, ea_t func_addr_);

    int idaapi visit_insn(cinsn_t* insn) override;
    int idaapi visit_expr(cexpr_t* expr) override;

    // Resolve captured call sites into CallArgInfo rows. Call after apply_to().
    void finalize();
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

// Orphan comment iterator for single function
class OrphanCommentsInFuncIterator : public xsql::RowIterator {
    std::vector<OrphanCommentInfo> rows_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit OrphanCommentsInFuncIterator(ea_t func_addr);
    bool next() override;
    bool eof() const override;
    void column(xsql::FunctionContext& ctx, int col) override;
    int64_t rowid() const override;
};

// Orphan comment iterator for a single mapped address
class OrphanCommentsAtEaIterator : public xsql::RowIterator {
    std::vector<OrphanCommentInfo> rows_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit OrphanCommentsAtEaIterator(ea_t ea);
    bool next() override;
    bool eof() const override;
    void column(xsql::FunctionContext& ctx, int col) override;
    int64_t rowid() const override;
};

// Grouped orphan comment iterator for a single function.
class OrphanCommentGroupsInFuncIterator : public xsql::RowIterator {
    std::vector<OrphanCommentGroupInfo> rows_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit OrphanCommentGroupsInFuncIterator(ea_t func_addr);
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

// Ctree label iterator for single function
class CtreeLabelsInFuncIterator : public xsql::RowIterator {
    std::vector<CtreeLabelInfo> labels_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit CtreeLabelsInFuncIterator(ea_t func_addr);
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

// Delete one orphan comment by exact treeloc.
bool delete_orphan_comment(ea_t func_addr, ea_t target_ea, item_preciser_t itp);

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
CachedTableDef<OrphanCommentInfo> define_pseudocode_orphan_comments();
CachedTableDef<OrphanCommentGroupInfo> define_pseudocode_orphan_comment_groups();
CachedTableDef<LvarInfo> define_ctree_lvars();
CachedTableDef<CtreeLabelInfo> define_ctree_labels();
GeneratorTableDef<CtreeItem> define_ctree();
GeneratorTableDef<CallArgInfo> define_ctree_call_args();

// One "Split expression" setting (hexrays.hpp: vdui_t::split_item): the
// decompiler keeps the operation at addr in pieces of piece_size bytes instead
// of merging them (decompiler_splits.cpp).
struct SplitRow {
    ea_t func_addr = BADADDR;
    ea_t addr = BADADDR;
    int piece_size = 0;  // 1, 2, 4 or 8
};

// The split settings of one function (func_addr pushdown).
class SplitsInFuncIterator : public xsql::RowIterator {
    std::vector<SplitRow> rows_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit SplitsInFuncIterator(ea_t func_addr);
    bool next() override;
    bool eof() const override;
    void column(xsql::FunctionContext& ctx, int col) override;
    int64_t rowid() const override;
};

CachedTableDef<SplitRow> define_decompiler_splits();

// Whether decompiler_splits reads and writes on this IDA ("9.4", from
// get_kernel_version): the versions its stored form was verified on.
bool splits_version_supported(const char* kernel_version);

// ============================================================================
// Views Registration
// ============================================================================

bool register_ctree_views(xsql::Database& db);       // ctree/pseudocode (decompiler_ctree.cpp)
bool register_microcode_views(xsql::Database& db);   // ir_ops family (decompiler_mc.cpp)

// ============================================================================
// Registry
// ============================================================================

// One Hex-Rays microcode instruction (minsn_t) at a requested maturity
// (MMAT_LVARS by default) — the native idasql leg of the cross-tool low-level IR.
// `opcode` is the raw mcode_t; `l_text`/
// `r_text`/`d_text` are the rendered operands (empty when the slot is void/mop_z);
// `text` is the full rendered microcode instruction. Per-function; filter by `func_addr`.
struct MicrocodeRow {
    ea_t func_addr = BADADDR;
    int block_num = 0;
    int seq = 0;
    ea_t ea = BADADDR;
    int opcode = 0;
    std::string text;
    std::string l_text;
    std::string r_text;
    std::string d_text;
    std::string canonical_op;  // cross-tool low-IR canonical (P-code-style) op; "" if none
    std::string maturity;      // returned mba_maturity_t rung name (generated..lvars)
    std::string stage;         // canonical cross-tool stage (raw/optimized/final)
};

// One row per microcode operand (minsn l/r/d) — the 5-kind operand model.
struct MicrocodeOperandRow {
    ea_t func_addr = BADADDR;
    int op_seq = 0;            // owning minsn seq (joins microcode.seq)
    int operand_index = 0;     // 0=l, 1=r, 2=d
    std::string role;          // "in" (l/r) | "out" (d)
    std::string kind;          // reg|imm|mem|var|result, or "" if outside the 5-kind model
    std::string text;          // rendered operand
    int64_t value = 0;         // immediate value (kind='imm')
    bool has_value = false;
    int size = 0;              // operand size in bytes
    std::string maturity;
    std::string stage;
};

GeneratorTableDef<MicrocodeRow> define_microcode();
GeneratorTableDef<MicrocodeOperandRow> define_microcode_operands();

// Why Hex-Rays cannot lift the function starting at `func_addr` to `maturity`
// ("" = lvars), or nullopt when it can. The microcode tables skip such a function;
// this says why. A bad argument (no function starts there, an unknown maturity)
// is reported through `bad_argument` with nullopt.
std::optional<std::string> microcode_error(ea_t func_addr, const std::string& maturity,
                                           std::string* bad_argument);

struct DecompilerRegistry {
    // Cached tables (query-scoped cache, write support)
    CachedTableDef<PseudocodeLine> pseudocode;
    CachedTableDef<OrphanCommentInfo> pseudocode_orphan_comments;
    CachedTableDef<OrphanCommentGroupInfo> pseudocode_orphan_comment_groups;
    CachedTableDef<LvarInfo> ctree_lvars;
    CachedTableDef<CtreeLabelInfo> ctree_labels;
    CachedTableDef<SplitRow> decompiler_splits;
    // Generator tables (lazy full scans)
    GeneratorTableDef<CtreeItem> ctree;
    GeneratorTableDef<CallArgInfo> ctree_call_args;
    GeneratorTableDef<MicrocodeRow> microcode;
    GeneratorTableDef<MicrocodeOperandRow> microcode_operands;

    DecompilerRegistry();
    void register_all(xsql::Database& db);
};

} // namespace decompiler
} // namespace idasql
