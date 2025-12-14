/**
 * ida_decompiler.hpp - Hex-Rays Decompiler Virtual Tables
 *
 * Provides SQLite virtual tables for accessing decompiled function data:
 *   pseudocode       - Decompiled function pseudocode lines
 *   ctree_lvars      - Local variables from decompiled functions
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

#include <idasql/vtable.hpp>

#include <string>
#include <vector>
#include <map>

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
// Data Structures
// ============================================================================

// Pseudocode line data
struct PseudocodeLine {
    ea_t func_addr;
    int line_num;
    std::string text;
    ea_t ea;  // Associated address
};

// Local variable data
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
    sval_t stkoff;
    mreg_t mreg;
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

    CtreeItem() : func_addr(0), item_id(-1), is_expr(false), op(0), ea(BADADDR),
                  parent_id(-1), depth(0),
                  x_id(-1), y_id(-1), z_id(-1),
                  cond_id(-1), then_id(-1), else_id(-1),
                  body_id(-1), init_id(-1), step_id(-1),
                  var_idx(-1), obj_ea(BADADDR), num_value(0), member_offset(0),
                  var_is_stk(false), var_is_reg(false), var_is_arg(false) {}
};

// Call argument data
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

// ============================================================================
// Helper Functions
// ============================================================================

// Get full ctype name with cot_/cit_ prefix
inline std::string get_full_ctype_name(ctype_t op) {
    const char* name = get_ctype_name(op);
    if (!name || !name[0]) return "";
    if (op < cit_empty) {
        return std::string("cot_") + name;
    } else {
        return std::string("cit_") + name;
    }
}

// Collect pseudocode for a single function
inline bool collect_pseudocode(std::vector<PseudocodeLine>& lines, ea_t func_addr) {
    lines.clear();

    if (!init_hexrays()) return false;

    func_t* f = get_func(func_addr);
    if (!f) return false;

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc) return false;

    const strvec_t& sv = cfunc->get_pseudocode();

    for (int i = 0; i < sv.size(); i++) {
        PseudocodeLine pl;
        pl.func_addr = func_addr;
        pl.line_num = i;

        qstring clean;
        tag_remove(&clean, sv[i].line);
        pl.text = clean.c_str();
        pl.ea = BADADDR;

        lines.push_back(pl);
    }

    return true;
}

// Collect pseudocode for all functions
inline void collect_all_pseudocode(std::vector<PseudocodeLine>& lines) {
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

// Collect lvars for a single function
inline bool collect_lvars(std::vector<LvarInfo>& vars, ea_t func_addr) {
    vars.clear();

    if (!init_hexrays()) return false;

    func_t* f = get_func(func_addr);
    if (!f) return false;

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc) return false;

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) return false;

    for (int i = 0; i < lvars->size(); i++) {
        const lvar_t& lv = (*lvars)[i];

        LvarInfo vi;
        vi.func_addr = func_addr;
        vi.idx = i;
        vi.name = lv.name.c_str();

        qstring type_str;
        lv.type().print(&type_str);
        vi.type = type_str.c_str();

        vi.size = lv.width;
        vi.is_arg = lv.is_arg_var();
        vi.is_result = lv.is_result_var();
        vi.is_stk_var = lv.is_stk_var();
        vi.is_reg_var = lv.is_reg_var();
        vi.stkoff = vi.is_stk_var ? lv.get_stkoff() : 0;
        vi.mreg = vi.is_reg_var ? lv.location.reg1() : mr_none;

        vars.push_back(vi);
    }

    return true;
}

// Collect lvars for all functions
inline void collect_all_lvars(std::vector<LvarInfo>& vars) {
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

        citem_t* p = parent_item();
        if (p) {
            auto it = item_ids.find(p);
            if (it != item_ids.end()) ci.parent_id = it->second;
        }

        items.push_back(ci);
        return 0;
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

        citem_t* p = parent_item();
        if (p) {
            auto it = item_ids.find(p);
            if (it != item_ids.end()) ci.parent_id = it->second;
        }

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
        return 0;
    }

    void resolve_child_ids() {
        for (auto& ci : items) {
            if (ci.item_id < 0) continue;

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

                if (expr->x) {
                    auto it = item_ids.find(expr->x);
                    if (it != item_ids.end()) ci.x_id = it->second;
                }
                if (expr->y && expr->op != cot_call) {
                    auto it = item_ids.find(expr->y);
                    if (it != item_ids.end()) ci.y_id = it->second;
                }
                if (expr->z) {
                    auto it = item_ids.find(expr->z);
                    if (it != item_ids.end()) ci.z_id = it->second;
                }
            } else {
                cinsn_t* insn = static_cast<cinsn_t*>(item);

                switch (insn->op) {
                    case cit_if:
                        if (insn->cif) {
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

// Collect ctree items for a single function
inline bool collect_ctree(std::vector<CtreeItem>& items, ea_t func_addr) {
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

// Collect ctree for all functions
inline void collect_all_ctree(std::vector<CtreeItem>& items) {
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

// Call args collector visitor
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

        if (expr->op == cot_call && expr->a) {
            carglist_t& arglist = *expr->a;
            for (size_t i = 0; i < arglist.size(); i++) {
                const carg_t& arg = arglist[i];

                CallArgInfo ai;
                ai.func_addr = func_addr;
                ai.call_item_id = my_id;
                ai.arg_idx = i;
                ai.arg_op = get_full_ctype_name(arg.op);

                auto it = item_ids.find((citem_t*)&arg);
                if (it != item_ids.end()) {
                    ai.arg_item_id = it->second;
                } else {
                    ai.arg_item_id = next_id++;
                    item_ids[(citem_t*)&arg] = ai.arg_item_id;
                }

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

// Collect call args for a single function
inline bool collect_call_args(std::vector<CallArgInfo>& args, ea_t func_addr) {
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

// Collect call args for all functions
inline void collect_all_call_args(std::vector<CallArgInfo>& args) {
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

// ============================================================================
// Caches for full scans
// ============================================================================

struct PseudocodeCache {
    static std::vector<PseudocodeLine>& get() {
        static std::vector<PseudocodeLine> cache;
        return cache;
    }
    static void rebuild() { collect_all_pseudocode(get()); }
};

struct LvarsCache {
    static std::vector<LvarInfo>& get() {
        static std::vector<LvarInfo> cache;
        return cache;
    }
    static void rebuild() { collect_all_lvars(get()); }
};

struct CtreeCache {
    static std::vector<CtreeItem>& get() {
        static std::vector<CtreeItem> cache;
        return cache;
    }
    static void rebuild() { collect_all_ctree(get()); }
};

struct CallArgsCache {
    static std::vector<CallArgInfo>& get() {
        static std::vector<CallArgInfo> cache;
        return cache;
    }
    static void rebuild() { collect_all_call_args(get()); }
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
    explicit PseudocodeInFuncIterator(ea_t func_addr) {
        collect_pseudocode(lines_, func_addr);
    }

    bool next() override {
        if (!started_) { started_ = true; return !lines_.empty(); }
        if (idx_ + 1 < lines_.size()) { ++idx_; return true; }
        return false;
    }

    bool eof() const override { return started_ && idx_ >= lines_.size(); }

    void column(sqlite3_context* ctx, int col) override {
        if (idx_ >= lines_.size()) { sqlite3_result_null(ctx); return; }
        const auto& line = lines_[idx_];
        switch (col) {
            case 0: sqlite3_result_int64(ctx, line.func_addr); break;
            case 1: sqlite3_result_int(ctx, line.line_num); break;
            case 2: sqlite3_result_text(ctx, line.text.c_str(), -1, SQLITE_TRANSIENT); break;
            case 3:
                if (line.ea != BADADDR) sqlite3_result_int64(ctx, line.ea);
                else sqlite3_result_null(ctx);
                break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(idx_); }
};

// Lvars iterator for single function
class LvarsInFuncIterator : public xsql::RowIterator {
    std::vector<LvarInfo> vars_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit LvarsInFuncIterator(ea_t func_addr) {
        collect_lvars(vars_, func_addr);
    }

    bool next() override {
        if (!started_) { started_ = true; return !vars_.empty(); }
        if (idx_ + 1 < vars_.size()) { ++idx_; return true; }
        return false;
    }

    bool eof() const override { return started_ && idx_ >= vars_.size(); }

    void column(sqlite3_context* ctx, int col) override {
        if (idx_ >= vars_.size()) { sqlite3_result_null(ctx); return; }
        const auto& v = vars_[idx_];
        switch (col) {
            case 0: sqlite3_result_int64(ctx, v.func_addr); break;
            case 1: sqlite3_result_int(ctx, v.idx); break;
            case 2: sqlite3_result_text(ctx, v.name.c_str(), -1, SQLITE_TRANSIENT); break;
            case 3: sqlite3_result_text(ctx, v.type.c_str(), -1, SQLITE_TRANSIENT); break;
            case 4: sqlite3_result_int(ctx, v.size); break;
            case 5: sqlite3_result_int(ctx, v.is_arg ? 1 : 0); break;
            case 6: sqlite3_result_int(ctx, v.is_result ? 1 : 0); break;
            case 7: sqlite3_result_int(ctx, v.is_stk_var ? 1 : 0); break;
            case 8: sqlite3_result_int(ctx, v.is_reg_var ? 1 : 0); break;
            case 9: v.is_stk_var ? sqlite3_result_int64(ctx, v.stkoff) : sqlite3_result_null(ctx); break;
            case 10: v.is_reg_var ? sqlite3_result_int(ctx, v.mreg) : sqlite3_result_null(ctx); break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(idx_); }
};

// Ctree iterator for single function
class CtreeInFuncIterator : public xsql::RowIterator {
    std::vector<CtreeItem> items_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit CtreeInFuncIterator(ea_t func_addr) {
        collect_ctree(items_, func_addr);
    }

    bool next() override {
        if (!started_) { started_ = true; return !items_.empty(); }
        if (idx_ + 1 < items_.size()) { ++idx_; return true; }
        return false;
    }

    bool eof() const override { return started_ && idx_ >= items_.size(); }

    void column(sqlite3_context* ctx, int col) override {
        if (idx_ >= items_.size()) { sqlite3_result_null(ctx); return; }
        const auto& item = items_[idx_];
        switch (col) {
            case 0: sqlite3_result_int64(ctx, item.func_addr); break;
            case 1: sqlite3_result_int(ctx, item.item_id); break;
            case 2: sqlite3_result_int(ctx, item.is_expr ? 1 : 0); break;
            case 3: sqlite3_result_int(ctx, item.op); break;
            case 4: sqlite3_result_text(ctx, item.op_name.c_str(), -1, SQLITE_TRANSIENT); break;
            case 5: item.ea != BADADDR ? sqlite3_result_int64(ctx, item.ea) : sqlite3_result_null(ctx); break;
            case 6: item.parent_id >= 0 ? sqlite3_result_int(ctx, item.parent_id) : sqlite3_result_null(ctx); break;
            case 7: sqlite3_result_int(ctx, item.depth); break;
            case 8: item.x_id >= 0 ? sqlite3_result_int(ctx, item.x_id) : sqlite3_result_null(ctx); break;
            case 9: item.y_id >= 0 ? sqlite3_result_int(ctx, item.y_id) : sqlite3_result_null(ctx); break;
            case 10: item.z_id >= 0 ? sqlite3_result_int(ctx, item.z_id) : sqlite3_result_null(ctx); break;
            case 11: item.cond_id >= 0 ? sqlite3_result_int(ctx, item.cond_id) : sqlite3_result_null(ctx); break;
            case 12: item.then_id >= 0 ? sqlite3_result_int(ctx, item.then_id) : sqlite3_result_null(ctx); break;
            case 13: item.else_id >= 0 ? sqlite3_result_int(ctx, item.else_id) : sqlite3_result_null(ctx); break;
            case 14: item.body_id >= 0 ? sqlite3_result_int(ctx, item.body_id) : sqlite3_result_null(ctx); break;
            case 15: item.init_id >= 0 ? sqlite3_result_int(ctx, item.init_id) : sqlite3_result_null(ctx); break;
            case 16: item.step_id >= 0 ? sqlite3_result_int(ctx, item.step_id) : sqlite3_result_null(ctx); break;
            case 17: item.var_idx >= 0 ? sqlite3_result_int(ctx, item.var_idx) : sqlite3_result_null(ctx); break;
            case 18: item.obj_ea != BADADDR ? sqlite3_result_int64(ctx, item.obj_ea) : sqlite3_result_null(ctx); break;
            case 19: item.op == cot_num ? sqlite3_result_int64(ctx, item.num_value) : sqlite3_result_null(ctx); break;
            case 20: !item.str_value.empty() ? sqlite3_result_text(ctx, item.str_value.c_str(), -1, SQLITE_TRANSIENT) : sqlite3_result_null(ctx); break;
            case 21: !item.helper_name.empty() ? sqlite3_result_text(ctx, item.helper_name.c_str(), -1, SQLITE_TRANSIENT) : sqlite3_result_null(ctx); break;
            case 22: (item.op == cot_memref || item.op == cot_memptr) ? sqlite3_result_int(ctx, item.member_offset) : sqlite3_result_null(ctx); break;
            case 23: !item.var_name.empty() ? sqlite3_result_text(ctx, item.var_name.c_str(), -1, SQLITE_TRANSIENT) : sqlite3_result_null(ctx); break;
            case 24: item.op == cot_var ? sqlite3_result_int(ctx, item.var_is_stk ? 1 : 0) : sqlite3_result_null(ctx); break;
            case 25: item.op == cot_var ? sqlite3_result_int(ctx, item.var_is_reg ? 1 : 0) : sqlite3_result_null(ctx); break;
            case 26: item.op == cot_var ? sqlite3_result_int(ctx, item.var_is_arg ? 1 : 0) : sqlite3_result_null(ctx); break;
            case 27: !item.obj_name.empty() ? sqlite3_result_text(ctx, item.obj_name.c_str(), -1, SQLITE_TRANSIENT) : sqlite3_result_null(ctx); break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(idx_); }
};

// Call args iterator for single function
class CallArgsInFuncIterator : public xsql::RowIterator {
    std::vector<CallArgInfo> args_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit CallArgsInFuncIterator(ea_t func_addr) {
        collect_call_args(args_, func_addr);
    }

    bool next() override {
        if (!started_) { started_ = true; return !args_.empty(); }
        if (idx_ + 1 < args_.size()) { ++idx_; return true; }
        return false;
    }

    bool eof() const override { return started_ && idx_ >= args_.size(); }

    void column(sqlite3_context* ctx, int col) override {
        if (idx_ >= args_.size()) { sqlite3_result_null(ctx); return; }
        const auto& ai = args_[idx_];
        switch (col) {
            case 0: sqlite3_result_int64(ctx, ai.func_addr); break;
            case 1: sqlite3_result_int(ctx, ai.call_item_id); break;
            case 2: sqlite3_result_int(ctx, ai.arg_idx); break;
            case 3: ai.arg_item_id >= 0 ? sqlite3_result_int(ctx, ai.arg_item_id) : sqlite3_result_null(ctx); break;
            case 4: sqlite3_result_text(ctx, ai.arg_op.c_str(), -1, SQLITE_TRANSIENT); break;
            case 5: ai.arg_var_idx >= 0 ? sqlite3_result_int(ctx, ai.arg_var_idx) : sqlite3_result_null(ctx); break;
            case 6: !ai.arg_var_name.empty() ? sqlite3_result_text(ctx, ai.arg_var_name.c_str(), -1, SQLITE_TRANSIENT) : sqlite3_result_null(ctx); break;
            case 7: ai.arg_var_idx >= 0 ? sqlite3_result_int(ctx, ai.arg_var_is_stk ? 1 : 0) : sqlite3_result_null(ctx); break;
            case 8: ai.arg_var_idx >= 0 ? sqlite3_result_int(ctx, ai.arg_var_is_arg ? 1 : 0) : sqlite3_result_null(ctx); break;
            case 9: ai.arg_obj_ea != BADADDR ? sqlite3_result_int64(ctx, ai.arg_obj_ea) : sqlite3_result_null(ctx); break;
            case 10: !ai.arg_obj_name.empty() ? sqlite3_result_text(ctx, ai.arg_obj_name.c_str(), -1, SQLITE_TRANSIENT) : sqlite3_result_null(ctx); break;
            case 11: ai.arg_op == "cot_num" ? sqlite3_result_int64(ctx, ai.arg_num_value) : sqlite3_result_null(ctx); break;
            case 12: !ai.arg_str_value.empty() ? sqlite3_result_text(ctx, ai.arg_str_value.c_str(), -1, SQLITE_TRANSIENT) : sqlite3_result_null(ctx); break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(idx_); }
};

// ============================================================================
// Table Definitions
// ============================================================================

inline VTableDef define_pseudocode() {
    return table("pseudocode")
        .count([]() { PseudocodeCache::rebuild(); return PseudocodeCache::get().size(); })
        .column_int64("func_addr", [](size_t i) -> int64_t {
            auto& c = PseudocodeCache::get();
            return i < c.size() ? c[i].func_addr : 0;
        })
        .column_int("line_num", [](size_t i) -> int {
            auto& c = PseudocodeCache::get();
            return i < c.size() ? c[i].line_num : 0;
        })
        .column_text("line", [](size_t i) -> std::string {
            auto& c = PseudocodeCache::get();
            return i < c.size() ? c[i].text : "";
        })
        .column_int64("ea", [](size_t i) -> int64_t {
            auto& c = PseudocodeCache::get();
            return (i < c.size() && c[i].ea != BADADDR) ? c[i].ea : 0;
        })
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<PseudocodeInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 50.0)
        .build();
}

inline VTableDef define_ctree_lvars() {
    return table("ctree_lvars")
        .count([]() { LvarsCache::rebuild(); return LvarsCache::get().size(); })
        .column_int64("func_addr", [](size_t i) -> int64_t {
            auto& c = LvarsCache::get(); return i < c.size() ? c[i].func_addr : 0;
        })
        .column_int("idx", [](size_t i) -> int {
            auto& c = LvarsCache::get(); return i < c.size() ? c[i].idx : 0;
        })
        .column_text("name", [](size_t i) -> std::string {
            auto& c = LvarsCache::get(); return i < c.size() ? c[i].name : "";
        })
        .column_text("type", [](size_t i) -> std::string {
            auto& c = LvarsCache::get(); return i < c.size() ? c[i].type : "";
        })
        .column_int("size", [](size_t i) -> int {
            auto& c = LvarsCache::get(); return i < c.size() ? c[i].size : 0;
        })
        .column_int("is_arg", [](size_t i) -> int {
            auto& c = LvarsCache::get(); return i < c.size() ? (c[i].is_arg ? 1 : 0) : 0;
        })
        .column_int("is_result", [](size_t i) -> int {
            auto& c = LvarsCache::get(); return i < c.size() ? (c[i].is_result ? 1 : 0) : 0;
        })
        .column_int("is_stk_var", [](size_t i) -> int {
            auto& c = LvarsCache::get(); return i < c.size() ? (c[i].is_stk_var ? 1 : 0) : 0;
        })
        .column_int("is_reg_var", [](size_t i) -> int {
            auto& c = LvarsCache::get(); return i < c.size() ? (c[i].is_reg_var ? 1 : 0) : 0;
        })
        .column_int64("stkoff", [](size_t i) -> int64_t {
            auto& c = LvarsCache::get(); return i < c.size() ? c[i].stkoff : 0;
        })
        .column_int("mreg", [](size_t i) -> int {
            auto& c = LvarsCache::get(); return i < c.size() ? c[i].mreg : 0;
        })
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<LvarsInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 10.0)
        .build();
}

inline VTableDef define_ctree() {
    return table("ctree")
        .count([]() { CtreeCache::rebuild(); return CtreeCache::get().size(); })
        .column_int64("func_addr", [](size_t i) -> int64_t { auto& c = CtreeCache::get(); return i < c.size() ? c[i].func_addr : 0; })
        .column_int("item_id", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].item_id : 0; })
        .column_int("is_expr", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? (c[i].is_expr ? 1 : 0) : 0; })
        .column_int("op", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].op : 0; })
        .column_text("op_name", [](size_t i) -> std::string { auto& c = CtreeCache::get(); return i < c.size() ? c[i].op_name : ""; })
        .column_int64("ea", [](size_t i) -> int64_t { auto& c = CtreeCache::get(); return (i < c.size() && c[i].ea != BADADDR) ? c[i].ea : 0; })
        .column_int("parent_id", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].parent_id : -1; })
        .column_int("depth", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].depth : 0; })
        .column_int("x_id", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].x_id : -1; })
        .column_int("y_id", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].y_id : -1; })
        .column_int("z_id", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].z_id : -1; })
        .column_int("cond_id", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].cond_id : -1; })
        .column_int("then_id", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].then_id : -1; })
        .column_int("else_id", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].else_id : -1; })
        .column_int("body_id", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].body_id : -1; })
        .column_int("init_id", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].init_id : -1; })
        .column_int("step_id", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].step_id : -1; })
        .column_int("var_idx", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].var_idx : -1; })
        .column_int64("obj_ea", [](size_t i) -> int64_t { auto& c = CtreeCache::get(); return (i < c.size() && c[i].obj_ea != BADADDR) ? c[i].obj_ea : 0; })
        .column_int64("num_value", [](size_t i) -> int64_t { auto& c = CtreeCache::get(); return i < c.size() ? c[i].num_value : 0; })
        .column_text("str_value", [](size_t i) -> std::string { auto& c = CtreeCache::get(); return i < c.size() ? c[i].str_value : ""; })
        .column_text("helper_name", [](size_t i) -> std::string { auto& c = CtreeCache::get(); return i < c.size() ? c[i].helper_name : ""; })
        .column_int("member_offset", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? c[i].member_offset : 0; })
        .column_text("var_name", [](size_t i) -> std::string { auto& c = CtreeCache::get(); return i < c.size() ? c[i].var_name : ""; })
        .column_int("var_is_stk", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? (c[i].var_is_stk ? 1 : 0) : 0; })
        .column_int("var_is_reg", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? (c[i].var_is_reg ? 1 : 0) : 0; })
        .column_int("var_is_arg", [](size_t i) -> int { auto& c = CtreeCache::get(); return i < c.size() ? (c[i].var_is_arg ? 1 : 0) : 0; })
        .column_text("obj_name", [](size_t i) -> std::string { auto& c = CtreeCache::get(); return i < c.size() ? c[i].obj_name : ""; })
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<CtreeInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 100.0)
        .build();
}

inline VTableDef define_ctree_call_args() {
    return table("ctree_call_args")
        .count([]() { CallArgsCache::rebuild(); return CallArgsCache::get().size(); })
        .column_int64("func_addr", [](size_t i) -> int64_t { auto& c = CallArgsCache::get(); return i < c.size() ? c[i].func_addr : 0; })
        .column_int("call_item_id", [](size_t i) -> int { auto& c = CallArgsCache::get(); return i < c.size() ? c[i].call_item_id : 0; })
        .column_int("arg_idx", [](size_t i) -> int { auto& c = CallArgsCache::get(); return i < c.size() ? c[i].arg_idx : 0; })
        .column_int("arg_item_id", [](size_t i) -> int { auto& c = CallArgsCache::get(); return i < c.size() ? c[i].arg_item_id : 0; })
        .column_text("arg_op", [](size_t i) -> std::string { auto& c = CallArgsCache::get(); return i < c.size() ? c[i].arg_op : ""; })
        .column_int("arg_var_idx", [](size_t i) -> int { auto& c = CallArgsCache::get(); return i < c.size() ? c[i].arg_var_idx : -1; })
        .column_text("arg_var_name", [](size_t i) -> std::string { auto& c = CallArgsCache::get(); return i < c.size() ? c[i].arg_var_name : ""; })
        .column_int("arg_var_is_stk", [](size_t i) -> int { auto& c = CallArgsCache::get(); return i < c.size() ? (c[i].arg_var_is_stk ? 1 : 0) : 0; })
        .column_int("arg_var_is_arg", [](size_t i) -> int { auto& c = CallArgsCache::get(); return i < c.size() ? (c[i].arg_var_is_arg ? 1 : 0) : 0; })
        .column_int64("arg_obj_ea", [](size_t i) -> int64_t { auto& c = CallArgsCache::get(); return (i < c.size() && c[i].arg_obj_ea != BADADDR) ? c[i].arg_obj_ea : 0; })
        .column_text("arg_obj_name", [](size_t i) -> std::string { auto& c = CallArgsCache::get(); return i < c.size() ? c[i].arg_obj_name : ""; })
        .column_int64("arg_num_value", [](size_t i) -> int64_t { auto& c = CallArgsCache::get(); return i < c.size() ? c[i].arg_num_value : 0; })
        .column_text("arg_str_value", [](size_t i) -> std::string { auto& c = CallArgsCache::get(); return i < c.size() ? c[i].arg_str_value : ""; })
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<CallArgsInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 100.0)
        .build();
}

// ============================================================================
// Views Registration
// ============================================================================

inline bool register_ctree_views(sqlite3* db) {
    char* err = nullptr;

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

    const char* v_loops = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_loops AS
        SELECT * FROM ctree
        WHERE op_name IN ('cit_for', 'cit_while', 'cit_do')
    )";
    sqlite3_exec(db, v_loops, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    const char* v_ifs = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_ifs AS
        SELECT * FROM ctree WHERE op_name = 'cit_if'
    )";
    sqlite3_exec(db, v_ifs, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

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

    const char* v_calls_in_loops = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_calls_in_loops AS
        WITH RECURSIVE loop_contents(func_addr, item_id, loop_id, loop_op, depth) AS (
            SELECT func_addr, item_id, item_id, op_name, 0
            FROM ctree
            WHERE op_name IN ('cit_for', 'cit_while', 'cit_do')
            UNION ALL
            SELECT c.func_addr, c.item_id, lc.loop_id, lc.loop_op, lc.depth + 1
            FROM ctree c
            JOIN loop_contents lc ON c.func_addr = lc.func_addr AND c.parent_id = lc.item_id
            WHERE lc.depth < 50
        )
        SELECT DISTINCT
            c.func_addr, c.item_id, c.ea, c.depth AS call_depth,
            lc.loop_id, lc.loop_op,
            x.obj_ea AS callee_addr, x.obj_name AS callee_name, x.helper_name
        FROM loop_contents lc
        JOIN ctree c ON c.func_addr = lc.func_addr AND c.item_id = lc.item_id
        LEFT JOIN ctree x ON x.func_addr = c.func_addr AND x.item_id = c.x_id
        WHERE c.op_name = 'cot_call'
    )";
    sqlite3_exec(db, v_calls_in_loops, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    const char* v_calls_in_ifs = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_calls_in_ifs AS
        WITH RECURSIVE if_contents(func_addr, item_id, if_id, branch, depth) AS (
            SELECT c.func_addr, c.item_id, p.item_id, 'then', 0
            FROM ctree c
            JOIN ctree p ON c.func_addr = p.func_addr AND c.item_id = p.then_id
            WHERE p.op_name = 'cit_if'
            UNION ALL
            SELECT c.func_addr, c.item_id, p.item_id, 'else', 0
            FROM ctree c
            JOIN ctree p ON c.func_addr = p.func_addr AND c.item_id = p.else_id
            WHERE p.op_name = 'cit_if'
            UNION ALL
            SELECT c.func_addr, c.item_id, ic.if_id, ic.branch, ic.depth + 1
            FROM ctree c
            JOIN if_contents ic ON c.func_addr = ic.func_addr AND c.parent_id = ic.item_id
            WHERE ic.depth < 50
        )
        SELECT DISTINCT
            c.func_addr, c.item_id, c.ea, c.depth AS call_depth,
            ic.if_id, ic.branch,
            x.obj_ea AS callee_addr, x.obj_name AS callee_name, x.helper_name
        FROM if_contents ic
        JOIN ctree c ON c.func_addr = ic.func_addr AND c.item_id = ic.item_id
        LEFT JOIN ctree x ON x.func_addr = c.func_addr AND x.item_id = c.x_id
        WHERE c.op_name = 'cot_call'
    )";
    sqlite3_exec(db, v_calls_in_ifs, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    const char* v_leaf_funcs = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_leaf_funcs AS
        SELECT f.address, f.name
        FROM funcs f
        LEFT JOIN ctree_v_calls c ON c.func_addr = f.address
        GROUP BY f.address
        HAVING COUNT(c.callee_addr) = 0
    )";
    sqlite3_exec(db, v_leaf_funcs, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    const char* v_call_chains = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_call_chains AS
        WITH RECURSIVE call_chain(root_func, current_func, depth) AS (
            SELECT func_addr, callee_addr, 1
            FROM ctree_v_calls
            WHERE callee_addr IS NOT NULL
            UNION ALL
            SELECT cc.root_func, c.callee_addr, cc.depth + 1
            FROM call_chain cc
            JOIN ctree_v_calls c ON c.func_addr = cc.current_func
            WHERE cc.depth < 10 AND c.callee_addr IS NOT NULL
        )
        SELECT root_func, current_func, depth FROM call_chain
    )";
    sqlite3_exec(db, v_call_chains, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    return true;
}

// ============================================================================
// Registry
// ============================================================================

struct DecompilerRegistry {
    VTableDef pseudocode;
    VTableDef ctree_lvars;
    VTableDef ctree;
    VTableDef ctree_call_args;

    DecompilerRegistry()
        : pseudocode(define_pseudocode())
        , ctree_lvars(define_ctree_lvars())
        , ctree(define_ctree())
        , ctree_call_args(define_ctree_call_args())
    {}

    void register_all(sqlite3* db) {
        register_vtable(db, "ida_pseudocode", &pseudocode);
        create_vtable(db, "pseudocode", "ida_pseudocode");

        register_vtable(db, "ida_ctree_lvars", &ctree_lvars);
        create_vtable(db, "ctree_lvars", "ida_ctree_lvars");

        register_vtable(db, "ida_ctree", &ctree);
        create_vtable(db, "ctree", "ida_ctree");

        register_vtable(db, "ida_ctree_call_args", &ctree_call_args);
        create_vtable(db, "ctree_call_args", "ida_ctree_call_args");

        register_ctree_views(db);
    }
};

} // namespace decompiler
} // namespace idasql
