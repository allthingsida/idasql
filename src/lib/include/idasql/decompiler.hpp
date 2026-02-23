/**
 * decompiler.hpp - Hex-Rays Decompiler Virtual Tables
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

#include <idasql/platform.hpp>

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include <string>
#include <vector>
#include <map>

#include <idasql/platform_undef.hpp>

// IDA SDK headers
#include <ida.hpp>
#include <auto.hpp>
#include <funcs.hpp>
#include <name.hpp>

// Hex-Rays decompiler headers
#include <lines.hpp>
#include <hexrays.hpp>

namespace idasql {
namespace decompiler {

// ============================================================================
// Decompiler Initialization
// ============================================================================

// Global flag tracking if Hex-Rays is available
// Set once during DecompilerRegistry::register_all()
inline bool& hexrays_available() {
    static bool available = false;
    return available;
}

// Initialize Hex-Rays decompiler - call ONCE at startup
// Returns true if decompiler is available
inline bool init_hexrays() {
    static bool initialized = false;

    if (!initialized) {
        initialized = true;
        hexrays_available() = init_hexrays_plugin();
        if (hexrays_available()) {
            // Hex-Rays initialization may trigger additional auto-analysis work.
            // Ensure analysis is complete before running decompiler-backed queries.
            auto_wait();
        }
    }
    return hexrays_available();
}

// Invalidate decompiler cache for the function containing ea.
// Safe to call even if Hex-Rays is unavailable or ea is not in a function.
inline void invalidate_decompiler_cache(ea_t ea) {
    if (!hexrays_available()) return;
    func_t* f = get_func(ea);
    if (f) {
        mark_cfunc_dirty(f->start_ea, false);
    }
}

// ============================================================================
// Data Structures
// ============================================================================

// ITP name ↔ enum helpers
inline const char* itp_to_name(item_preciser_t itp) {
    switch (itp) {
        case ITP_SEMI:   return "semi";
        case ITP_BLOCK1: return "block1";
        case ITP_BLOCK2: return "block2";
        case ITP_CURLY1: return "curly1";
        case ITP_CURLY2: return "curly2";
        case ITP_BRACE1: return "brace1";
        case ITP_BRACE2: return "brace2";
        case ITP_COLON:  return "colon";
        case ITP_CASE:   return "case";
        case ITP_ELSE:   return "else";
        case ITP_DO:     return "do";
        case ITP_ASM:    return "asm";
        default:         return "semi";
    }
}

inline item_preciser_t name_to_itp(const char* name) {
    if (!name || !name[0]) return ITP_SEMI;
    if (stricmp(name, "block1") == 0) return ITP_BLOCK1;
    if (stricmp(name, "block2") == 0) return ITP_BLOCK2;
    if (stricmp(name, "curly1") == 0) return ITP_CURLY1;
    if (stricmp(name, "curly2") == 0) return ITP_CURLY2;
    if (stricmp(name, "brace1") == 0) return ITP_BRACE1;
    if (stricmp(name, "brace2") == 0) return ITP_BRACE2;
    if (stricmp(name, "colon") == 0)  return ITP_COLON;
    if (stricmp(name, "case") == 0)   return ITP_CASE;
    if (stricmp(name, "else") == 0)   return ITP_ELSE;
    if (stricmp(name, "do") == 0)     return ITP_DO;
    if (stricmp(name, "asm") == 0)    return ITP_ASM;
    return ITP_SEMI;  // default
}

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
inline std::string get_full_ctype_name(ctype_t op) {
    const char* name = get_ctype_name(op);
    if (!name || !name[0]) return "";
    if (op < cit_empty) {
        return std::string("cot_") + name;
    } else {
        return std::string("cit_") + name;
    }
}

// Extract the first COLOR_ADDR anchor ea from a raw pseudocode line.
// Returns BADADDR if no anchor found.
inline ea_t extract_line_ea(cfunc_t* cfunc, const qstring& raw_line) {
    const char* p = raw_line.c_str();
    while (*p) {
        if (*p == COLOR_ON && *(p + 1) == COLOR_ADDR) {
            p += 2;  // skip COLOR_ON + COLOR_ADDR
            // Read 16 hex chars
            char hex[17] = {};
            for (int i = 0; i < 16; i++) {
                if (!p[i]) return BADADDR;
                hex[i] = p[i];
            }
            uint64_t val = strtoull(hex, nullptr, 16);
            uint32_t anchor = static_cast<uint32_t>(val);
            // ANCHOR_CITEM = type 0 (bits 31-30)
            uint32_t anchor_type = (anchor >> 30) & 0x3;
            if (anchor_type != 0) return BADADDR;
            uint32_t idx = anchor & 0x3FFFFFFF;
            if (idx >= cfunc->treeitems.size()) return BADADDR;
            citem_t* item = cfunc->treeitems[idx];
            return item ? item->ea : BADADDR;
        }
        p++;
    }
    return BADADDR;
}

// Collect pseudocode for a single function
inline bool collect_pseudocode(std::vector<PseudocodeLine>& lines, ea_t func_addr) {
    lines.clear();

    if (!hexrays_available()) return false;

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

        // Extract ea from COLOR_ADDR anchor BEFORE stripping tags
        pl.ea = extract_line_ea(&*cfunc, sv[i].line);

        qstring clean;
        tag_remove(&clean, sv[i].line);
        pl.text = clean.c_str();

        lines.push_back(pl);
    }

    // Read stored comments and match to lines by ea
    user_cmts_t* cmts = restore_user_cmts(func_addr);
    if (cmts) {
        for (auto it = user_cmts_begin(cmts); it != user_cmts_end(cmts); it = user_cmts_next(it)) {
            const treeloc_t& loc = user_cmts_first(it);
            const citem_cmt_t& cmt = user_cmts_second(it);
            // Match comment to first line with this ea
            for (auto& pl : lines) {
                if (pl.ea == loc.ea && pl.comment.empty()) {
                    pl.comment = cmt.c_str();
                    pl.comment_placement = loc.itp;
                    break;
                }
            }
        }
        user_cmts_free(cmts);
    }

    return true;
}

// Collect pseudocode for all functions
inline void collect_all_pseudocode(std::vector<PseudocodeLine>& lines) {
    lines.clear();

    if (!hexrays_available()) return;

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

    if (!hexrays_available()) return false;

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
        vi.comment = lv.cmt.c_str();

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

    if (!hexrays_available()) return;

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

    if (!hexrays_available()) return false;

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

    if (!hexrays_available()) return;

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
            std::string call_obj_name;
            std::string call_helper_name;
            if (expr->x != nullptr) {
                if (expr->x->op == cot_obj) {
                    qstring name;
                    if (get_name(&name, expr->x->obj_ea) > 0) {
                        call_obj_name = name.c_str();
                    }
                } else if (expr->x->op == cot_helper && expr->x->helper != nullptr) {
                    call_helper_name = expr->x->helper;
                }
            }

            carglist_t& arglist = *expr->a;
            for (size_t i = 0; i < arglist.size(); i++) {
                const carg_t& arg = arglist[i];

                CallArgInfo ai;
                ai.func_addr = func_addr;
                ai.call_item_id = my_id;
                ai.call_ea = expr->ea;
                ai.call_obj_name = call_obj_name;
                ai.call_helper_name = call_helper_name;
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

    if (!hexrays_available()) return false;

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

    if (!hexrays_available()) return;

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

// ctree and ctree_call_args use streaming generator tables (GeneratorTableDef).

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
        if (!started_) {
            started_ = true;
            if (lines_.empty()) return false;
            idx_ = 0;
            return true;
        }
        if (idx_ + 1 < lines_.size()) { ++idx_; return true; }
        idx_ = lines_.size();
        return false;
    }

    bool eof() const override { return started_ && idx_ >= lines_.size(); }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (idx_ >= lines_.size()) { ctx.result_null(); return; }
        const auto& line = lines_[idx_];
        switch (col) {
            case 0: ctx.result_int64(line.func_addr); break;
            case 1: ctx.result_int(line.line_num); break;
            case 2: ctx.result_text(line.text.c_str()); break;
            case 3:
                ctx.result_int64(line.ea != BADADDR ? line.ea : 0);
                break;
            case 4:
                if (!line.comment.empty())
                    ctx.result_text(line.comment.c_str());
                else
                    ctx.result_null();
                break;
            case 5:
                ctx.result_text_static(itp_to_name(line.comment_placement));
                break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(idx_); }
};

// Pseudocode iterator for a single mapped address
class PseudocodeAtEaIterator : public xsql::RowIterator {
    std::vector<PseudocodeLine> lines_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit PseudocodeAtEaIterator(ea_t ea) {
        func_t* f = get_func(ea);
        if (!f) return;

        std::vector<PseudocodeLine> all;
        collect_pseudocode(all, f->start_ea);
        for (const auto& line : all) {
            if (line.ea == ea) {
                lines_.push_back(line);
            }
        }
    }

    bool next() override {
        if (!started_) {
            started_ = true;
            if (lines_.empty()) return false;
            idx_ = 0;
            return true;
        }
        if (idx_ + 1 < lines_.size()) { ++idx_; return true; }
        idx_ = lines_.size();
        return false;
    }

    bool eof() const override { return started_ && idx_ >= lines_.size(); }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (idx_ >= lines_.size()) { ctx.result_null(); return; }
        const auto& line = lines_[idx_];
        switch (col) {
            case 0: ctx.result_int64(line.func_addr); break;
            case 1: ctx.result_int(line.line_num); break;
            case 2: ctx.result_text(line.text.c_str()); break;
            case 3: ctx.result_int64(line.ea != BADADDR ? line.ea : 0); break;
            case 4:
                if (!line.comment.empty()) ctx.result_text(line.comment.c_str());
                else ctx.result_null();
                break;
            case 5: ctx.result_text_static(itp_to_name(line.comment_placement)); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(idx_); }
};

// Pseudocode iterator for line number across all functions
class PseudocodeLineNumIterator : public xsql::RowIterator {
    std::vector<PseudocodeLine> lines_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit PseudocodeLineNumIterator(int line_num) {
        if (line_num < 0) return;

        size_t func_qty = get_func_qty();
        for (size_t i = 0; i < func_qty; ++i) {
            func_t* f = getn_func(i);
            if (!f) continue;

            std::vector<PseudocodeLine> func_lines;
            collect_pseudocode(func_lines, f->start_ea);
            for (const auto& line : func_lines) {
                if (line.line_num == line_num) {
                    lines_.push_back(line);
                }
            }
        }
    }

    bool next() override {
        if (!started_) {
            started_ = true;
            if (lines_.empty()) return false;
            idx_ = 0;
            return true;
        }
        if (idx_ + 1 < lines_.size()) { ++idx_; return true; }
        idx_ = lines_.size();
        return false;
    }

    bool eof() const override { return started_ && idx_ >= lines_.size(); }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (idx_ >= lines_.size()) { ctx.result_null(); return; }
        const auto& line = lines_[idx_];
        switch (col) {
            case 0: ctx.result_int64(line.func_addr); break;
            case 1: ctx.result_int(line.line_num); break;
            case 2: ctx.result_text(line.text.c_str()); break;
            case 3: ctx.result_int64(line.ea != BADADDR ? line.ea : 0); break;
            case 4:
                if (!line.comment.empty()) ctx.result_text(line.comment.c_str());
                else ctx.result_null();
                break;
            case 5: ctx.result_text_static(itp_to_name(line.comment_placement)); break;
            default: ctx.result_null(); break;
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
        if (!started_) {
            started_ = true;
            if (vars_.empty()) return false;
            idx_ = 0;
            return true;
        }
        if (idx_ + 1 < vars_.size()) { ++idx_; return true; }
        idx_ = vars_.size();
        return false;
    }

    bool eof() const override { return started_ && idx_ >= vars_.size(); }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (idx_ >= vars_.size()) { ctx.result_null(); return; }
        const auto& v = vars_[idx_];
        switch (col) {
            case 0: ctx.result_int64(v.func_addr); break;
            case 1: ctx.result_int(v.idx); break;
            case 2: ctx.result_text(v.name.c_str()); break;
            case 3: ctx.result_text(v.type.c_str()); break;
            case 4:
                if (!v.comment.empty()) ctx.result_text(v.comment.c_str());
                else ctx.result_null();
                break;
            case 5: ctx.result_int(v.size); break;
            case 6: ctx.result_int(v.is_arg ? 1 : 0); break;
            case 7: ctx.result_int(v.is_result ? 1 : 0); break;
            case 8: ctx.result_int(v.is_stk_var ? 1 : 0); break;
            case 9: ctx.result_int(v.is_reg_var ? 1 : 0); break;
            case 10: v.is_stk_var ? ctx.result_int64(v.stkoff) : ctx.result_null(); break;
            case 11: v.is_reg_var ? ctx.result_int(v.mreg) : ctx.result_null(); break;
            default: ctx.result_null(); break;
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
        if (!started_) {
            started_ = true;
            if (items_.empty()) return false;
            idx_ = 0;
            return true;
        }
        if (idx_ + 1 < items_.size()) { ++idx_; return true; }
        idx_ = items_.size();
        return false;
    }

    bool eof() const override { return started_ && idx_ >= items_.size(); }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (idx_ >= items_.size()) { ctx.result_null(); return; }
        const auto& item = items_[idx_];
        switch (col) {
            case 0: ctx.result_int64(item.func_addr); break;
            case 1: ctx.result_int(item.item_id); break;
            case 2: ctx.result_int(item.is_expr ? 1 : 0); break;
            case 3: ctx.result_int(item.op); break;
            case 4: ctx.result_text(item.op_name.c_str()); break;
            case 5: item.ea != BADADDR ? ctx.result_int64(item.ea) : ctx.result_null(); break;
            case 6: item.parent_id >= 0 ? ctx.result_int(item.parent_id) : ctx.result_null(); break;
            case 7: ctx.result_int(item.depth); break;
            case 8: item.x_id >= 0 ? ctx.result_int(item.x_id) : ctx.result_null(); break;
            case 9: item.y_id >= 0 ? ctx.result_int(item.y_id) : ctx.result_null(); break;
            case 10: item.z_id >= 0 ? ctx.result_int(item.z_id) : ctx.result_null(); break;
            case 11: item.cond_id >= 0 ? ctx.result_int(item.cond_id) : ctx.result_null(); break;
            case 12: item.then_id >= 0 ? ctx.result_int(item.then_id) : ctx.result_null(); break;
            case 13: item.else_id >= 0 ? ctx.result_int(item.else_id) : ctx.result_null(); break;
            case 14: item.body_id >= 0 ? ctx.result_int(item.body_id) : ctx.result_null(); break;
            case 15: item.init_id >= 0 ? ctx.result_int(item.init_id) : ctx.result_null(); break;
            case 16: item.step_id >= 0 ? ctx.result_int(item.step_id) : ctx.result_null(); break;
            case 17: item.var_idx >= 0 ? ctx.result_int(item.var_idx) : ctx.result_null(); break;
            case 18: item.obj_ea != BADADDR ? ctx.result_int64(item.obj_ea) : ctx.result_null(); break;
            case 19: item.op == cot_num ? ctx.result_int64(item.num_value) : ctx.result_null(); break;
            case 20: !item.str_value.empty() ? ctx.result_text(item.str_value.c_str()) : ctx.result_null(); break;
            case 21: !item.helper_name.empty() ? ctx.result_text(item.helper_name.c_str()) : ctx.result_null(); break;
            case 22: (item.op == cot_memref || item.op == cot_memptr) ? ctx.result_int(item.member_offset) : ctx.result_null(); break;
            case 23: !item.var_name.empty() ? ctx.result_text(item.var_name.c_str()) : ctx.result_null(); break;
            case 24: item.op == cot_var ? ctx.result_int(item.var_is_stk ? 1 : 0) : ctx.result_null(); break;
            case 25: item.op == cot_var ? ctx.result_int(item.var_is_reg ? 1 : 0) : ctx.result_null(); break;
            case 26: item.op == cot_var ? ctx.result_int(item.var_is_arg ? 1 : 0) : ctx.result_null(); break;
            case 27: !item.obj_name.empty() ? ctx.result_text(item.obj_name.c_str()) : ctx.result_null(); break;
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
        if (!started_) {
            started_ = true;
            if (args_.empty()) return false;
            idx_ = 0;
            return true;
        }
        if (idx_ + 1 < args_.size()) { ++idx_; return true; }
        idx_ = args_.size();
        return false;
    }

    bool eof() const override { return started_ && idx_ >= args_.size(); }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (idx_ >= args_.size()) { ctx.result_null(); return; }
        const auto& ai = args_[idx_];
        switch (col) {
            case 0: ctx.result_int64(ai.func_addr); break;
            case 1: ctx.result_int(ai.call_item_id); break;
            case 2: ai.call_ea != BADADDR ? ctx.result_int64(ai.call_ea) : ctx.result_null(); break;
            case 3: !ai.call_obj_name.empty() ? ctx.result_text(ai.call_obj_name.c_str()) : ctx.result_null(); break;
            case 4: !ai.call_helper_name.empty() ? ctx.result_text(ai.call_helper_name.c_str()) : ctx.result_null(); break;
            case 5: ctx.result_int(ai.arg_idx); break;
            case 6: ai.arg_item_id >= 0 ? ctx.result_int(ai.arg_item_id) : ctx.result_null(); break;
            case 7: ctx.result_text(ai.arg_op.c_str()); break;
            case 8: ai.arg_var_idx >= 0 ? ctx.result_int(ai.arg_var_idx) : ctx.result_null(); break;
            case 9: !ai.arg_var_name.empty() ? ctx.result_text(ai.arg_var_name.c_str()) : ctx.result_null(); break;
            case 10: ai.arg_var_idx >= 0 ? ctx.result_int(ai.arg_var_is_stk ? 1 : 0) : ctx.result_null(); break;
            case 11: ai.arg_var_idx >= 0 ? ctx.result_int(ai.arg_var_is_arg ? 1 : 0) : ctx.result_null(); break;
            case 12: ai.arg_obj_ea != BADADDR ? ctx.result_int64(ai.arg_obj_ea) : ctx.result_null(); break;
            case 13: !ai.arg_obj_name.empty() ? ctx.result_text(ai.arg_obj_name.c_str()) : ctx.result_null(); break;
            case 14: ai.arg_op == "cot_num" ? ctx.result_int64(ai.arg_num_value) : ctx.result_null(); break;
            case 15: !ai.arg_str_value.empty() ? ctx.result_text(ai.arg_str_value.c_str()) : ctx.result_null(); break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(idx_); }
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

    bool load_next_func() {
        if (!hexrays_available()) return false;

        size_t func_qty = get_func_qty();
        while (func_idx_ < func_qty) {
            func_t* f = getn_func(func_idx_++);
            if (!f) continue;

            if (collect_ctree(items_, f->start_ea) && !items_.empty()) {
                idx_ = 0;
                return true;
            }
        }
        return false;
    }

public:
    bool next() override {
        if (!started_) {
            started_ = true;
            if (!load_next_func()) return false;
            rowid_ = 0;
            return true;
        }

        if (idx_ + 1 < items_.size()) {
            ++idx_;
            ++rowid_;
            return true;
        }

        if (!load_next_func()) return false;
        ++rowid_;
        return true;
    }

    const CtreeItem& current() const override { return items_[idx_]; }

    int64_t rowid() const override { return rowid_; }
};

class CallArgsGenerator : public xsql::Generator<CallArgInfo> {
    size_t func_idx_ = 0;
    std::vector<CallArgInfo> args_;
    size_t idx_ = 0;
    int64_t rowid_ = -1;
    bool started_ = false;

    bool load_next_func() {
        if (!hexrays_available()) return false;

        size_t func_qty = get_func_qty();
        while (func_idx_ < func_qty) {
            func_t* f = getn_func(func_idx_++);
            if (!f) continue;

            if (collect_call_args(args_, f->start_ea) && !args_.empty()) {
                idx_ = 0;
                return true;
            }
        }
        return false;
    }

public:
    bool next() override {
        if (!started_) {
            started_ = true;
            if (!load_next_func()) return false;
            rowid_ = 0;
            return true;
        }

        if (idx_ + 1 < args_.size()) {
            ++idx_;
            ++rowid_;
            return true;
        }

        if (!load_next_func()) return false;
        ++rowid_;
        return true;
    }

    const CallArgInfo& current() const override { return args_[idx_]; }

    int64_t rowid() const override { return rowid_; }
};

// ============================================================================
// Table Definitions
// ============================================================================

// Helper: Set or delete a decompiler comment at an ea within a function
inline bool set_decompiler_comment(ea_t func_addr, ea_t target_ea, const char* comment, item_preciser_t itp = ITP_SEMI) {
    if (!hexrays_available()) return false;
    if (target_ea == BADADDR || target_ea == 0) return false;

    func_t* f = get_func(func_addr);
    if (!f) return false;

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc) return false;

    treeloc_t loc;
    loc.ea = target_ea;
    loc.itp = itp;

    // set_user_cmt with empty/nullptr deletes the comment
    cfunc->set_user_cmt(loc, (comment && comment[0]) ? comment : nullptr);

    cfunc->save_user_cmts();
    invalidate_decompiler_cache(func_addr);
    return true;
}

inline bool clear_decompiler_comment_all_placements(ea_t func_addr, ea_t target_ea) {
    if (!hexrays_available()) return false;
    if (target_ea == BADADDR || target_ea == 0) return false;

    func_t* f = get_func(func_addr);
    if (!f) return false;

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc) return false;

    // Clear any existing comment regardless of placement so UPDATE statements
    // like "SET comment = NULL, comment_placement = 'semi'" are order-independent.
    static const item_preciser_t kPlacements[] = {
        ITP_SEMI, ITP_BLOCK1, ITP_BLOCK2, ITP_CURLY1, ITP_CURLY2, ITP_BRACE1,
        ITP_BRACE2, ITP_COLON, ITP_CASE, ITP_ELSE, ITP_DO, ITP_ASM
    };
    for (item_preciser_t itp : kPlacements) {
        treeloc_t loc;
        loc.ea = target_ea;
        loc.itp = itp;
        cfunc->set_user_cmt(loc, nullptr);
    }

    cfunc->save_user_cmts();
    invalidate_decompiler_cache(func_addr);
    return true;
}

// Resolve an EA for a ctree item within a function.
inline bool get_ctree_item_ea(ea_t func_addr, int item_id, ea_t& out_ea) {
    out_ea = BADADDR;
    if (!hexrays_available()) return false;
    if (item_id < 0) return false;

    std::vector<CtreeItem> items;
    if (!collect_ctree(items, func_addr)) return false;
    for (const CtreeItem& item : items) {
        if (item.item_id != item_id) continue;
        if (item.ea == BADADDR || item.ea == 0) continue;
        out_ea = item.ea;
        return true;
    }
    return false;
}

// Persist user union selection path for an EA. Empty path clears selection.
inline bool set_union_selection_at_ea(ea_t func_addr, ea_t target_ea, const intvec_t& path) {
    if (!hexrays_available()) return false;
    if (target_ea == BADADDR || target_ea == 0) return false;

    user_unions_t* unions = restore_user_unions(func_addr);
    if (!unions) {
        unions = user_unions_new();
        if (!unions) return false;
    }

    const auto end = user_unions_end(unions);
    auto it = user_unions_find(unions, target_ea);

    if (path.empty()) {
        if (it != end) {
            user_unions_erase(unions, it);
        }
    } else if (it == end) {
        user_unions_insert(unions, target_ea, path);
    } else {
        user_unions_second(it) = path;
    }

    save_user_unions(func_addr, unions);
    user_unions_free(unions);
    invalidate_decompiler_cache(func_addr);
    return true;
}

// Persist user union selection path by ctree item id.
inline bool set_union_selection_at_item(ea_t func_addr, int item_id, const intvec_t& path) {
    ea_t target_ea = BADADDR;
    if (!get_ctree_item_ea(func_addr, item_id, target_ea)) {
        return false;
    }
    return set_union_selection_at_ea(func_addr, target_ea, path);
}

// Read user union selection path for an EA. Returns false when not found.
inline bool get_union_selection_at_ea(ea_t func_addr, ea_t target_ea, intvec_t& out_path) {
    out_path.clear();
    if (!hexrays_available()) return false;
    if (target_ea == BADADDR || target_ea == 0) return false;

    user_unions_t* unions = restore_user_unions(func_addr);
    if (!unions) return false;

    auto it = user_unions_find(unions, target_ea);
    const bool found = (it != user_unions_end(unions));
    if (found) {
        out_path = user_unions_second(it);
    }
    user_unions_free(unions);
    return found;
}

inline CachedTableDef<PseudocodeLine> define_pseudocode() {
    return cached_table<PseudocodeLine>("pseudocode")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return get_func_qty() * 20; })
        .cache_builder([](std::vector<PseudocodeLine>& cache) {
            collect_all_pseudocode(cache);
        })
        .row_populator([](PseudocodeLine& row, int argc, xsql::FunctionArg* argv) {
            // argv[2]=func_addr, argv[3]=line_num, argv[4]=line, argv[5]=ea, argv[6]=comment, argv[7]=comment_placement
            if (argc > 2) row.func_addr = static_cast<ea_t>(argv[2].as_int64());
            if (argc > 3) row.line_num = argv[3].as_int();
            if (argc > 5) row.ea = static_cast<ea_t>(argv[5].as_int64());
            if (argc > 7 && !argv[7].is_null()) {
                const char* p = argv[7].as_c_str();
                row.comment_placement = name_to_itp(p);
            }
        })
        .column_int64("func_addr", [](const PseudocodeLine& r) -> int64_t { return r.func_addr; })
        .column_int("line_num", [](const PseudocodeLine& r) -> int { return r.line_num; })
        .column_text("line", [](const PseudocodeLine& r) -> std::string { return r.text; })
        .column_int64("ea", [](const PseudocodeLine& r) -> int64_t {
            return r.ea != BADADDR ? r.ea : 0;
        })
        .column_text_rw("comment",
            [](const PseudocodeLine& r) -> std::string { return r.comment; },
            [](PseudocodeLine& row, xsql::FunctionArg val) -> bool {
                const char* text = nullptr;
                if (!val.is_null()) {
                    text = val.as_c_str();
                }
                const bool is_clear = (text == nullptr || text[0] == '\0');
                if (row.ea == BADADDR || row.ea == 0) {
                    // Non-addressable lines (signature/blank/comment-only) cannot hold
                    // user comments in Hex-Rays. Allow clear/no-op updates so bulk
                    // cleanup queries do not fail the full statement.
                    if (is_clear) {
                        row.comment.clear();
                        return true;
                    }
                    return false;
                }
                bool ok = false;
                if (is_clear) {
                    ok = clear_decompiler_comment_all_placements(row.func_addr, row.ea);
                } else {
                    ok = set_decompiler_comment(row.func_addr, row.ea, text, row.comment_placement);
                }
                if (ok) {
                    row.comment = text ? text : "";
                }
                return ok;
            })
        .column_text_rw("comment_placement",
            [](const PseudocodeLine& r) -> std::string { return itp_to_name(r.comment_placement); },
            [](PseudocodeLine& row, xsql::FunctionArg val) -> bool {
                if (val.is_null()) return false;
                const char* name = val.as_c_str();
                row.comment_placement = name_to_itp(name);
                return true;  // just sets the field, actual comment write happens in comment setter
            })
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<PseudocodeInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 50.0)
        .filter_eq("ea", [](int64_t ea) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<PseudocodeAtEaIterator>(static_cast<ea_t>(ea));
        }, 20.0, 5.0)
        .filter_eq("line_num", [](int64_t line_num) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<PseudocodeLineNumIterator>(static_cast<int>(line_num));
        }, 200.0, 100.0)
        .build();
}

// Snapshot one lvar from a function by index.
inline bool get_lvar_snapshot(ea_t func_addr, int lvar_idx, LvarInfo& out) {
    if (!hexrays_available()) return false;
    if (lvar_idx < 0) return false;

    std::vector<LvarInfo> vars;
    if (!collect_lvars(vars, func_addr)) return false;
    if (static_cast<size_t>(lvar_idx) >= vars.size()) return false;

    out = vars[static_cast<size_t>(lvar_idx)];
    return true;
}

// Helper: Rename lvar by func_addr and lvar index with explicit readback validation.
inline LvarRenameResult rename_lvar_at_ex(ea_t func_addr, int lvar_idx, const char* new_name) {
    LvarRenameResult result;
    result.func_addr = func_addr;
    result.lvar_idx = lvar_idx;
    result.requested_name = new_name ? new_name : "";

    if (!hexrays_available()) {
        result.success = false;
        result.reason = "hexrays_unavailable";
        return result;
    }
    if (!new_name || !new_name[0]) {
        result.success = true;
        result.reason = "invalid_name";
        return result;
    }

    LvarInfo before{};
    if (!get_lvar_snapshot(func_addr, lvar_idx, before)) {
        result.success = true;
        result.reason = "not_found";
        return result;
    }
    result.before_name = before.name;

    if (before.name == new_name) {
        result.success = true;
        result.applied = false;
        result.after_name = before.name;
        result.reason = "unchanged";
        return result;
    }

    func_t* f = get_func(func_addr);
    if (!f) {
        result.success = false;
        result.reason = "function_not_found";
        return result;
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc) {
        result.success = false;
        result.reason = "decompile_failed";
        return result;
    }

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || static_cast<size_t>(lvar_idx) >= lvars->size()) {
        result.success = true;
        result.reason = "not_found";
        return result;
    }

    lvar_t& lv = (*lvars)[lvar_idx];

    lvar_saved_info_t lsi;
    lsi.ll = lv;
    lsi.name = new_name;
    lsi.flags = 0;

    bool ok = modify_user_lvar_info(func_addr, MLI_NAME, lsi);
    if (!ok) {
        result.success = false;
        result.reason = "rename_failed";
        return result;
    }

    invalidate_decompiler_cache(func_addr);

    LvarInfo after{};
    if (!get_lvar_snapshot(func_addr, lvar_idx, after)) {
        result.success = false;
        result.reason = "post_verify_failed";
        return result;
    }

    result.success = true;
    result.after_name = after.name;
    if (result.after_name == new_name) {
        result.applied = true;
        return result;
    }

    result.applied = false;
    result.reason = result.after_name.empty() ? "not_nameable" : "not_applied";
    result.warnings.push_back("rename request did not match post-refresh lvar name");
    return result;
}

// Helper: Rename lvar by idx preserving legacy bool return.
// Returns true on a successful mutation or a no-op unchanged rename.
inline bool rename_lvar_at(ea_t func_addr, int lvar_idx, const char* new_name) {
    LvarRenameResult r = rename_lvar_at_ex(func_addr, lvar_idx, new_name);
    return r.success && (r.applied || r.reason == "unchanged");
}

// Helper: Rename lvar by old name (exact match).
inline LvarRenameResult rename_lvar_by_name_ex(ea_t func_addr, const char* old_name, const char* new_name) {
    LvarRenameResult result;
    result.func_addr = func_addr;
    result.lvar_idx = -1;
    result.target_name = old_name ? old_name : "";
    result.requested_name = new_name ? new_name : "";

    if (!hexrays_available()) {
        result.success = false;
        result.reason = "hexrays_unavailable";
        return result;
    }
    if (!old_name || !old_name[0]) {
        result.success = true;
        result.reason = "invalid_selector";
        return result;
    }

    std::vector<LvarInfo> vars;
    if (!collect_lvars(vars, func_addr)) {
        result.success = false;
        result.reason = "decompile_failed";
        return result;
    }

    std::vector<int> matches;
    matches.reserve(vars.size());
    for (const auto& v : vars) {
        if (v.name == old_name) {
            matches.push_back(v.idx);
        }
    }

    if (matches.empty()) {
        result.success = true;
        result.reason = "not_found";
        return result;
    }
    if (matches.size() > 1) {
        result.success = true;
        result.reason = "ambiguous_name";
        result.warnings.push_back("multiple locals matched selector; use rename_lvar(func_addr, idx, new_name)");
        return result;
    }

    result = rename_lvar_at_ex(func_addr, matches[0], new_name);
    result.target_name = old_name;
    return result;
}

// Helper: Set lvar type by func_addr and lvar index
inline bool set_lvar_type_at(ea_t func_addr, int lvar_idx, const char* type_str) {
    if (!hexrays_available())
        return false;

    func_t* f = get_func(func_addr);
    if (!f)
        return false;

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc)
        return false;

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || lvar_idx < 0 || static_cast<size_t>(lvar_idx) >= lvars->size())
        return false;

    lvar_t& lv = (*lvars)[lvar_idx];

    // Parse type string - try named type first, then parse as declaration
    tinfo_t tif;
    if (!tif.get_named_type(nullptr, type_str)) {
        // Use parse_decl for C declaration parsing
        qstring decl;
        decl.sprnt("%s __x;", type_str);
        qstring out_name;
        if (!parse_decl(&tif, &out_name, nullptr, decl.c_str(), PT_SIL))
            return false;
    }

    // Use modify_user_lvar_info to persist the type change
    lvar_saved_info_t lsi;
    lsi.ll = lv;  // Copy lvar_locator_t
    lsi.type = tif;
    lsi.flags = 0;  // No special flags needed

    bool ok = modify_user_lvar_info(func_addr, MLI_TYPE, lsi);
    if (ok) invalidate_decompiler_cache(func_addr);
    return ok;
}

// Helper: Set lvar comment by func_addr and lvar index
inline bool set_lvar_comment_at(ea_t func_addr, int lvar_idx, const char* comment) {
    if (!hexrays_available())
        return false;

    func_t* f = get_func(func_addr);
    if (!f)
        return false;

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc)
        return false;

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || lvar_idx < 0 || static_cast<size_t>(lvar_idx) >= lvars->size())
        return false;

    lvar_t& lv = (*lvars)[lvar_idx];

    lvar_saved_info_t lsi;
    lsi.ll = lv;  // Copy lvar_locator_t
    lsi.cmt = comment ? comment : "";
    lsi.flags = 0;

    bool ok = modify_user_lvar_info(func_addr, MLI_CMT, lsi);
    if (ok) invalidate_decompiler_cache(func_addr);
    return ok;
}

inline CachedTableDef<LvarInfo> define_ctree_lvars() {
    return cached_table<LvarInfo>("ctree_lvars")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return get_func_qty() * 20; })
        .cache_builder([](std::vector<LvarInfo>& rows) {
            collect_all_lvars(rows);
        })
        .row_populator([](LvarInfo& row, int argc, xsql::FunctionArg* argv) {
            // argv[2]=func_addr, argv[3]=idx, argv[4]=name, argv[5]=type, argv[6]=comment, ...
            if (argc > 2) row.func_addr = static_cast<ea_t>(argv[2].as_int64());
            if (argc > 3) row.idx = argv[3].as_int();
            if (argc > 4 && !argv[4].is_null()) {
                const char* v = argv[4].as_c_str();
                row.name = v ? v : "";
            }
            if (argc > 5 && !argv[5].is_null()) {
                const char* v = argv[5].as_c_str();
                row.type = v ? v : "";
            }
            if (argc > 6 && !argv[6].is_null()) {
                const char* v = argv[6].as_c_str();
                row.comment = v ? v : "";
            }
        })
        .column_int64("func_addr", [](const LvarInfo& row) -> int64_t { return row.func_addr; })
        .column_int("idx", [](const LvarInfo& row) -> int { return row.idx; })
        .column_text_rw("name",
            [](const LvarInfo& row) -> std::string {
                return row.name;
            },
            [](LvarInfo& row, const char* new_name) -> bool {
                bool ok = rename_lvar_at(row.func_addr, row.idx, new_name);
                if (ok) row.name = new_name ? new_name : "";
                return ok;
            })
        .column_text_rw("type",
            [](const LvarInfo& row) -> std::string {
                return row.type;
            },
            [](LvarInfo& row, const char* new_type) -> bool {
                bool ok = set_lvar_type_at(row.func_addr, row.idx, new_type);
                if (ok) row.type = new_type ? new_type : "";
                return ok;
            })
        .column_text_rw("comment",
            [](const LvarInfo& row) -> std::string {
                return row.comment;
            },
            [](LvarInfo& row, const char* new_comment) -> bool {
                bool ok = set_lvar_comment_at(row.func_addr, row.idx, new_comment);
                if (ok) row.comment = new_comment ? new_comment : "";
                return ok;
            })
        .column_int("size", [](const LvarInfo& row) -> int { return row.size; })
        .column_int("is_arg", [](const LvarInfo& row) -> int { return row.is_arg ? 1 : 0; })
        .column_int("is_result", [](const LvarInfo& row) -> int { return row.is_result ? 1 : 0; })
        .column_int("is_stk_var", [](const LvarInfo& row) -> int { return row.is_stk_var ? 1 : 0; })
        .column_int("is_reg_var", [](const LvarInfo& row) -> int { return row.is_reg_var ? 1 : 0; })
        .column_int64("stkoff", [](const LvarInfo& row) -> int64_t { return row.stkoff; })
        .column_int("mreg", [](const LvarInfo& row) -> int { return row.mreg; })
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<LvarsInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 10.0)
        .build();
}

inline GeneratorTableDef<CtreeItem> define_ctree() {
    return generator_table<CtreeItem>("ctree")
        // Cheap estimate for query planning (doesn't decompile)
        .estimate_rows([]() -> size_t {
            // Heuristic: ~50 AST items per function
            return get_func_qty() * 50;
        })
        // Full scan generator (decompiles one function at a time)
        .generator([]() -> std::unique_ptr<xsql::Generator<CtreeItem>> {
            return std::make_unique<CtreeGenerator>();
        })
        .column_int64("func_addr", [](const CtreeItem& r) -> int64_t { return r.func_addr; })
        .column_int("item_id", [](const CtreeItem& r) -> int { return r.item_id; })
        .column_int("is_expr", [](const CtreeItem& r) -> int { return r.is_expr ? 1 : 0; })
        .column_int("op", [](const CtreeItem& r) -> int { return r.op; })
        .column_text("op_name", [](const CtreeItem& r) -> std::string { return r.op_name; })
        .column_int64("ea", [](const CtreeItem& r) -> int64_t { return r.ea != BADADDR ? r.ea : 0; })
        .column_int("parent_id", [](const CtreeItem& r) -> int { return r.parent_id; })
        .column_int("depth", [](const CtreeItem& r) -> int { return r.depth; })
        .column_int("x_id", [](const CtreeItem& r) -> int { return r.x_id; })
        .column_int("y_id", [](const CtreeItem& r) -> int { return r.y_id; })
        .column_int("z_id", [](const CtreeItem& r) -> int { return r.z_id; })
        .column_int("cond_id", [](const CtreeItem& r) -> int { return r.cond_id; })
        .column_int("then_id", [](const CtreeItem& r) -> int { return r.then_id; })
        .column_int("else_id", [](const CtreeItem& r) -> int { return r.else_id; })
        .column_int("body_id", [](const CtreeItem& r) -> int { return r.body_id; })
        .column_int("init_id", [](const CtreeItem& r) -> int { return r.init_id; })
        .column_int("step_id", [](const CtreeItem& r) -> int { return r.step_id; })
        .column_int("var_idx", [](const CtreeItem& r) -> int { return r.var_idx; })
        .column_int64("obj_ea", [](const CtreeItem& r) -> int64_t { return r.obj_ea != BADADDR ? r.obj_ea : 0; })
        .column_int64("num_value", [](const CtreeItem& r) -> int64_t { return r.num_value; })
        .column_text("str_value", [](const CtreeItem& r) -> std::string { return r.str_value; })
        .column_text("helper_name", [](const CtreeItem& r) -> std::string { return r.helper_name; })
        .column_int("member_offset", [](const CtreeItem& r) -> int { return r.member_offset; })
        .column_text("var_name", [](const CtreeItem& r) -> std::string { return r.var_name; })
        .column_int("var_is_stk", [](const CtreeItem& r) -> int { return r.var_is_stk ? 1 : 0; })
        .column_int("var_is_reg", [](const CtreeItem& r) -> int { return r.var_is_reg ? 1 : 0; })
        .column_int("var_is_arg", [](const CtreeItem& r) -> int { return r.var_is_arg ? 1 : 0; })
        .column_text("obj_name", [](const CtreeItem& r) -> std::string { return r.obj_name; })
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<CtreeInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 100.0, 100.0)
        .build();
}

inline GeneratorTableDef<CallArgInfo> define_ctree_call_args() {
    return generator_table<CallArgInfo>("ctree_call_args")
        // Cheap estimate for query planning
        .estimate_rows([]() -> size_t {
            // Heuristic: ~20 call args per function
            return get_func_qty() * 20;
        })
        // Full scan generator (decompiles one function at a time)
        .generator([]() -> std::unique_ptr<xsql::Generator<CallArgInfo>> {
            return std::make_unique<CallArgsGenerator>();
        })
        .column_int64("func_addr", [](const CallArgInfo& r) -> int64_t { return r.func_addr; })
        .column_int("call_item_id", [](const CallArgInfo& r) -> int { return r.call_item_id; })
        .column_int64("call_ea", [](const CallArgInfo& r) -> int64_t {
            return r.call_ea != BADADDR ? static_cast<int64_t>(r.call_ea) : 0;
        })
        .column_text("call_obj_name", [](const CallArgInfo& r) -> std::string { return r.call_obj_name; })
        .column_text("call_helper_name", [](const CallArgInfo& r) -> std::string { return r.call_helper_name; })
        .column_int("arg_idx", [](const CallArgInfo& r) -> int { return r.arg_idx; })
        .column_int("arg_item_id", [](const CallArgInfo& r) -> int { return r.arg_item_id; })
        .column_text("arg_op", [](const CallArgInfo& r) -> std::string { return r.arg_op; })
        .column_int("arg_var_idx", [](const CallArgInfo& r) -> int { return r.arg_var_idx; })
        .column_text("arg_var_name", [](const CallArgInfo& r) -> std::string { return r.arg_var_name; })
        .column_int("arg_var_is_stk", [](const CallArgInfo& r) -> int { return r.arg_var_is_stk ? 1 : 0; })
        .column_int("arg_var_is_arg", [](const CallArgInfo& r) -> int { return r.arg_var_is_arg ? 1 : 0; })
        .column_int64("arg_obj_ea", [](const CallArgInfo& r) -> int64_t { return r.arg_obj_ea != BADADDR ? r.arg_obj_ea : 0; })
        .column_text("arg_obj_name", [](const CallArgInfo& r) -> std::string { return r.arg_obj_name; })
        .column_int64("arg_num_value", [](const CallArgInfo& r) -> int64_t { return r.arg_num_value; })
        .column_text("arg_str_value", [](const CallArgInfo& r) -> std::string { return r.arg_str_value; })
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<CallArgsInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 100.0, 100.0)
        .build();
}

// ============================================================================
// Views Registration
// ============================================================================

inline bool register_ctree_views(xsql::Database& db) {

    const char* v_calls = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_calls AS
        SELECT
            c.func_addr, c.item_id, c.ea,
            x.op_name AS callee_op,
            NULLIF(x.obj_ea, 0) AS callee_addr,
            x.obj_name AS callee_name,
            x.helper_name,
            (SELECT COUNT(*) FROM ctree_call_args a
             WHERE a.func_addr = c.func_addr AND a.call_item_id = c.item_id) AS arg_count
        FROM ctree c
        LEFT JOIN ctree x ON x.func_addr = c.func_addr AND x.item_id = c.x_id
        WHERE c.op_name = 'cot_call'
    )";
    db.exec(v_calls);

    const char* v_loops = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_loops AS
        SELECT * FROM ctree
        WHERE op_name IN ('cit_for', 'cit_while', 'cit_do')
    )";
    db.exec(v_loops);

    const char* v_ifs = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_ifs AS
        SELECT * FROM ctree WHERE op_name = 'cit_if'
    )";
    db.exec(v_ifs);

    const char* v_signed = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_signed_ops AS
        SELECT * FROM ctree WHERE op_name IN (
            'cot_sge', 'cot_sle', 'cot_sgt', 'cot_slt',
            'cot_sshr', 'cot_sdiv', 'cot_smod',
            'cot_asgsshr', 'cot_asgsdiv', 'cot_asgsmod'
        )
    )";
    db.exec(v_signed);

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
    db.exec(v_cmp);

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
    db.exec(v_asg);

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
    db.exec(v_deref);

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
            NULLIF(x.obj_ea, 0) AS callee_addr, x.obj_name AS callee_name, x.helper_name
        FROM loop_contents lc
        JOIN ctree c ON c.func_addr = lc.func_addr AND c.item_id = lc.item_id
        LEFT JOIN ctree x ON x.func_addr = c.func_addr AND x.item_id = c.x_id
        WHERE c.op_name = 'cot_call'
    )";
    db.exec(v_calls_in_loops);

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
            NULLIF(x.obj_ea, 0) AS callee_addr, x.obj_name AS callee_name, x.helper_name
        FROM if_contents ic
        JOIN ctree c ON c.func_addr = ic.func_addr AND c.item_id = ic.item_id
        LEFT JOIN ctree x ON x.func_addr = c.func_addr AND x.item_id = c.x_id
        WHERE c.op_name = 'cot_call'
    )";
    db.exec(v_calls_in_ifs);

    const char* v_leaf_funcs = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_leaf_funcs AS
        SELECT f.address, f.name
        FROM funcs f
        WHERE
            -- Only consider functions that Hex-Rays can decompile (avoid false "leaf" results
            -- when decompilation fails and the ctree tables return empty rows).
            EXISTS (
                SELECT 1 FROM ctree t
                WHERE t.func_addr = f.address
                LIMIT 1
            )
            AND NOT EXISTS (
                SELECT 1 FROM ctree_v_calls c
                WHERE c.func_addr = f.address AND c.callee_addr IS NOT NULL
                LIMIT 1
            )
    )";
    db.exec(v_leaf_funcs);

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
    db.exec(v_call_chains);

    // Return statements with return value details
    const char* v_returns = R"(
        CREATE VIEW IF NOT EXISTS ctree_v_returns AS
        SELECT
            ret.func_addr,
            ret.item_id,
            ret.ea,
            val.op_name AS return_op,
            val.item_id AS return_item_id,
            -- Numeric return (cot_num)
            CASE WHEN val.op_name = 'cot_num' THEN val.num_value ELSE NULL END AS return_num,
            -- String return (cot_str)
            CASE WHEN val.op_name = 'cot_str' THEN val.str_value ELSE NULL END AS return_str,
            -- Variable return (cot_var)
            CASE WHEN val.op_name = 'cot_var' THEN val.var_name ELSE NULL END AS return_var,
            CASE WHEN val.op_name = 'cot_var' THEN val.var_idx ELSE NULL END AS return_var_idx,
            CASE WHEN val.op_name = 'cot_var' THEN val.var_is_arg ELSE NULL END AS returns_arg,
            CASE WHEN val.op_name = 'cot_var' THEN val.var_is_stk ELSE NULL END AS returns_stk_var,
            -- Object/symbol return (cot_obj)
            CASE WHEN val.op_name = 'cot_obj' THEN val.obj_name ELSE NULL END AS return_obj,
            CASE WHEN val.op_name = 'cot_obj' THEN val.obj_ea ELSE NULL END AS return_obj_ea,
            -- Call result return (cot_call) - returning result of another call
            CASE WHEN val.op_name = 'cot_call' THEN 1 ELSE 0 END AS returns_call_result
        FROM ctree ret
        LEFT JOIN ctree val ON val.func_addr = ret.func_addr AND val.item_id = ret.x_id
        WHERE ret.op_name = 'cit_return'
    )";
    db.exec(v_returns);

    return true;
}

// ============================================================================
// Registry
// ============================================================================

struct DecompilerRegistry {
    // Cached tables (query-scoped cache, write support)
    CachedTableDef<PseudocodeLine> pseudocode;
    CachedTableDef<LvarInfo> ctree_lvars;
    // Generator tables (lazy full scans)
    GeneratorTableDef<CtreeItem> ctree;
    GeneratorTableDef<CallArgInfo> ctree_call_args;

    DecompilerRegistry()
        : pseudocode(define_pseudocode())
        , ctree_lvars(define_ctree_lvars())
        , ctree(define_ctree())
        , ctree_call_args(define_ctree_call_args())
    {}

    void register_all(xsql::Database& db) {
        // Initialize Hex-Rays decompiler ONCE at startup
        // If unavailable, skip registering decompiler tables entirely
        if (!init_hexrays()) {
            // Hex-Rays not available - don't register decompiler tables
            return;
        }

        // Cached table (query-scoped cache, freed when no cursors reference it)
        db.register_cached_table("ida_pseudocode", &pseudocode);
        db.create_table("pseudocode", "ida_pseudocode");

        db.register_cached_table("ida_ctree_lvars", &ctree_lvars);
        db.create_table("ctree_lvars", "ida_ctree_lvars");

        // Generator tables (lazy full scans, stop work early with LIMIT)
        db.register_generator_table("ida_ctree", &ctree);
        db.create_table("ctree", "ida_ctree");

        db.register_generator_table("ida_ctree_call_args", &ctree_call_args);
        db.create_table("ctree_call_args", "ida_ctree_call_args");

        register_ctree_views(db);
    }
};

} // namespace decompiler
} // namespace idasql

