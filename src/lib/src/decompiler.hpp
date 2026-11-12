// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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

inline bool& hexrays_available() {
    static bool available = false;
    return available;
}

bool init_hexrays();

void invalidate_decompiler_cache(ea_t ea);

cfuncptr_t decompile_for_read(ea_t ea, hexrays_failure_t* hf = nullptr, int decomp_flags = 0);

bool apply_callee_tinfo_at(ea_t call_ea, const tinfo_t& tif, const char* name = nullptr);

bool clear_callee_tinfo_at(ea_t call_ea);

bool get_callee_tinfo_at(ea_t call_ea, tinfo_t& out_tif);

bool parse_callee_decl(const char* decl_text, tinfo_t& out_tif, qstring* out_name = nullptr);

bool get_call_arg_addrs(ea_t call_ea, eavec_t& out_addrs);

const char* itp_to_name(item_preciser_t itp);
item_preciser_t name_to_itp(const char* name);

struct PseudocodeLine {
    ea_t func_addr;
    int line_num;
    std::string text;
    ea_t ea;
    std::string comment;
    item_preciser_t comment_placement = ITP_SEMI;
};

struct OrphanCommentInfo {
    uint32_t ordinal = 0;
    ea_t func_addr;
    std::string func_name;
    ea_t ea;
    item_preciser_t comment_placement = ITP_SEMI;
    std::string orphan_comment;
};

struct OrphanCommentGroupInfo {
    ea_t func_addr;
    std::string func_name;
    int orphan_count = 0;
    std::string orphan_comments_json;
};

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

struct LvarRenameResult {
    bool success = false;
    bool applied = false;
    ea_t func_addr = BADADDR;
    int lvar_idx = -1;
    int after_idx = -1;
    std::string target_name;
    std::string requested_name;
    std::string before_name;
    std::string after_name;
    std::string reason;
    std::vector<std::string> warnings;
};

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
    uint64_t member_offset;
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

std::string get_full_ctype_name(ctype_t op);

ea_t extract_line_ea(cfunc_t* cfunc, const qstring& raw_line);

bool collect_pseudocode(std::vector<PseudocodeLine>& lines, ea_t func_addr);

void collect_all_pseudocode(std::vector<PseudocodeLine>& lines);

bool collect_orphan_comments(std::vector<OrphanCommentInfo>& rows, ea_t func_addr);

void collect_all_orphan_comments(std::vector<OrphanCommentInfo>& rows);

bool collect_orphan_comment_group(OrphanCommentGroupInfo& row, ea_t func_addr);

void collect_all_orphan_comment_groups(std::vector<OrphanCommentGroupInfo>& rows);

bool collect_lvars(std::vector<LvarInfo>& vars, ea_t func_addr);

void collect_all_lvars(std::vector<LvarInfo>& vars);

bool collect_ctree(std::vector<CtreeItem>& items, ea_t func_addr);

bool collect_ctree_labels(std::vector<CtreeLabelInfo>& rows, ea_t func_addr);

void collect_all_ctree_labels(std::vector<CtreeLabelInfo>& rows);

bool collect_call_args(std::vector<CallArgInfo>& args, ea_t func_addr);

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

struct call_args_collector_t : public ctree_parentee_t {
    struct PendingCall {
        cexpr_t* call = nullptr;
        ea_t call_ea = BADADDR;
        std::string call_obj_name;
        std::string call_helper_name;
        std::vector<const carg_t*> arg_ptrs;
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

    void finalize();
};

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

bool set_decompiler_comment(ea_t func_addr, ea_t target_ea, const char* comment, item_preciser_t itp = ITP_SEMI);

bool clear_decompiler_comment_all_placements(ea_t func_addr, ea_t target_ea);

bool delete_orphan_comment(ea_t func_addr, ea_t target_ea, item_preciser_t itp);

bool get_ctree_item_ea(ea_t func_addr, int item_id, ea_t& out_ea);

bool set_union_selection_at_ea(ea_t func_addr, ea_t target_ea, const intvec_t& path);

bool set_union_selection_at_item(ea_t func_addr, int item_id, const intvec_t& path);

bool get_union_selection_at_ea(ea_t func_addr, ea_t target_ea, intvec_t& out_path);

bool get_lvar_snapshot(ea_t func_addr, int lvar_idx, LvarInfo& out);

LvarRenameResult rename_lvar_at_ex(ea_t func_addr, int lvar_idx, const char* new_name);

bool rename_lvar_at(ea_t func_addr, int lvar_idx, const char* new_name);

LvarRenameResult rename_lvar_by_name_ex(ea_t func_addr, const char* old_name, const char* new_name);

bool set_lvar_type_at(ea_t func_addr, int lvar_idx, const char* type_str);

bool set_lvar_comment_at(ea_t func_addr, int lvar_idx, const char* comment);

bool get_label_snapshot(ea_t func_addr, int label_num, CtreeLabelInfo& out);

LabelRenameResult rename_label_ex(ea_t func_addr, int label_num, const char* new_name);

bool rename_label(ea_t func_addr, int label_num, const char* new_name);

CachedTableDef<PseudocodeLine> define_pseudocode();
CachedTableDef<OrphanCommentInfo> define_pseudocode_orphan_comments();
CachedTableDef<OrphanCommentGroupInfo> define_pseudocode_orphan_comment_groups();
CachedTableDef<LvarInfo> define_ctree_lvars();
CachedTableDef<CtreeLabelInfo> define_ctree_labels();
GeneratorTableDef<CtreeItem> define_ctree();
GeneratorTableDef<CallArgInfo> define_ctree_call_args();

struct SplitRow {
    ea_t func_addr = BADADDR;
    ea_t addr = BADADDR;
    int piece_size = 0;
};

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

bool splits_version_supported(const char* kernel_version);

bool register_ctree_views(xsql::Database& db);
bool register_microcode_views(xsql::Database& db);

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
    std::string canonical_op;
    std::string maturity;
    std::string stage;
};

struct MicrocodeOperandRow {
    ea_t func_addr = BADADDR;
    int op_seq = 0;
    int operand_index = 0;
    std::string role;
    std::string kind;
    std::string text;
    int64_t value = 0;
    bool has_value = false;
    int size = 0;
    std::string maturity;
    std::string stage;
};

GeneratorTableDef<MicrocodeRow> define_microcode();
GeneratorTableDef<MicrocodeOperandRow> define_microcode_operands();

std::optional<std::string> microcode_error(ea_t func_addr, const std::string& maturity,
                                           std::string* bad_argument);

struct DecompilerRegistry {
    CachedTableDef<PseudocodeLine> pseudocode;
    CachedTableDef<OrphanCommentInfo> pseudocode_orphan_comments;
    CachedTableDef<OrphanCommentGroupInfo> pseudocode_orphan_comment_groups;
    CachedTableDef<LvarInfo> ctree_lvars;
    CachedTableDef<CtreeLabelInfo> ctree_labels;
    CachedTableDef<SplitRow> decompiler_splits;
    GeneratorTableDef<CtreeItem> ctree;
    GeneratorTableDef<CallArgInfo> ctree_call_args;
    GeneratorTableDef<MicrocodeRow> microcode;
    GeneratorTableDef<MicrocodeOperandRow> microcode_operands;

    DecompilerRegistry();
    void register_all(xsql::Database& db);
};

}
}
