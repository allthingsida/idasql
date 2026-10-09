// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "decompiler.hpp"

#include "function_rowid.hpp"
#include "types_members.hpp" // idasql::types::parse_type_declarator (array-aware)
#include "checkpoints.hpp"

#include <idasql/string_utils.hpp>

#include <xsql/json.hpp>

#include <sqlite3.h>

#include <cctype>
#include <climits>
#include <cstring>
#include <optional>
#include <sstream>
#include <unordered_map>

namespace idasql {
namespace decompiler {

// ============================================================================
// Hex-Rays microcode leg of the cross-tool low-IR (native `microcode` /
// `microcode_operands` tables + the ir_ops family of views), paired with the
// ctree/pseudocode implementation in decompiler_ctree.cpp.
// ============================================================================

static const char* microcode_canonical_op(int opcode) {
    switch (opcode) {
        case m_ldx:   return "LOAD";
        case m_stx:   return "STORE";
        case m_ldc:
        case m_mov:   return "COPY";
        case m_xds:   return "INT_SEXT";
        case m_xdu:   return "INT_ZEXT";
        case m_low:
        case m_high:  return "SUBPIECE";
        case m_neg:   return "INT_2COMP";
        case m_bnot:  return "INT_NEGATE";
        case m_lnot:  return "BOOL_NEGATE";
        case m_add:   return "INT_ADD";
        case m_sub:   return "INT_SUB";
        case m_mul:   return "INT_MULT";
        case m_udiv:  return "INT_DIV";
        case m_sdiv:  return "INT_SDIV";
        case m_umod:  return "INT_REM";
        case m_smod:  return "INT_SREM";
        case m_or:    return "INT_OR";
        case m_and:   return "INT_AND";
        case m_xor:   return "INT_XOR";
        case m_shl:   return "INT_LEFT";
        case m_shr:   return "INT_RIGHT";
        case m_sar:   return "INT_SRIGHT";
        case m_setz:  return "INT_EQUAL";
        case m_setnz: return "INT_NOTEQUAL";
        case m_setb:  return "INT_LESS";        // unsigned below (CF=1)
        case m_setbe: return "INT_LESSEQUAL";   // unsigned below-or-equal
        case m_setl:  return "INT_SLESS";       // signed less
        case m_setle: return "INT_SLESSEQUAL";  // signed less-or-equal
        case m_jcnd:
        case m_jnz: case m_jz:  case m_jae: case m_jb: case m_ja:
        case m_jbe: case m_jg:  case m_jge: case m_jl: case m_jle:
                      return "CBRANCH";
        case m_goto:  return "BRANCH";
        case m_ijmp:
        case m_jtbl:  return "BRANCHIND";
        case m_call:  return "CALL";
        case m_icall: return "CALLIND";
        case m_ret:   return "RETURN";
        case m_fadd:  return "FLOAT_ADD";
        case m_fsub:  return "FLOAT_SUB";
        case m_fmul:  return "FLOAT_MULT";
        case m_fdiv:  return "FLOAT_DIV";
        case m_fneg:  return "FLOAT_NEG";
        case m_f2i:
        case m_f2u:   return "TRUNC";           // fp -> integer
        case m_i2f:
        case m_u2f:   return "INT2FLOAT";
        case m_f2f:   return "FLOAT2FLOAT";
        default:      return "";                // no clean canonical (honest absence)
    }
}

// mba_maturity_t <-> rung name (the cross-tool maturity axis).
static const char* mmat_name(mba_maturity_t m) {
    switch (m) {
        case MMAT_GENERATED:    return "generated";
        case MMAT_PREOPTIMIZED: return "preoptimized";
        case MMAT_LOCOPT:       return "locopt";
        case MMAT_CALLS:        return "calls";
        case MMAT_GLBOPT1:      return "glbopt1";
        case MMAT_GLBOPT2:      return "glbopt2";
        case MMAT_GLBOPT3:      return "glbopt3";
        case MMAT_LVARS:        return "lvars";
        default:                return "lvars";
    }
}
static const char* mmat_stage(mba_maturity_t m) {
    switch (m) {
        case MMAT_GENERATED: return "raw";
        case MMAT_LVARS:     return "final";
        default:             return "optimized";
    }
}
static bool name_to_mmat(const char* name, mba_maturity_t& out) {
    std::string n = name ? name : "";
    if      (n == "generated")    out = MMAT_GENERATED;
    else if (n == "preoptimized") out = MMAT_PREOPTIMIZED;
    else if (n == "locopt")       out = MMAT_LOCOPT;
    else if (n == "calls")        out = MMAT_CALLS;
    else if (n == "glbopt1")      out = MMAT_GLBOPT1;
    else if (n == "glbopt2")      out = MMAT_GLBOPT2;
    else if (n == "glbopt3")      out = MMAT_GLBOPT3;
    else if (n == "lvars")        out = MMAT_LVARS;
    else return false;
    return true;
}

static uint8_t mmat_ordinal(const std::string& name) {
    if (name == "generated")
        return 0;
    if (name == "preoptimized")
        return 1;
    if (name == "locopt")
        return 2;
    if (name == "calls")
        return 3;
    if (name == "glbopt1")
        return 4;
    if (name == "glbopt2")
        return 5;
    if (name == "glbopt3")
        return 6;
    return 7; // lvars (and the defensive fallback used by mmat_name)
}

static bool microcode_scan_interrupted() {
    if (!xsql::vtab_interrupted()) return false;
    xsql::set_vtab_error("query interrupted while generating microcode");
    return true;
}

static std::string describe_microcode_failure(ea_t func_addr, mba_maturity_t requested,
                                              const hexrays_failure_t& failure) {
    const qstring description = failure.desc();
    std::ostringstream error;
    error << "microcode generation failed for " << idasql::format_ea_hex(func_addr)
          << " at maturity '" << mmat_name(requested) << "'";
    if (!description.empty()) {
        error << ": " << description.c_str();
    }
    return error.str();
}

static void set_microcode_generation_error(ea_t func_addr, mba_maturity_t requested,
                                           const hexrays_failure_t& failure) {
    xsql::set_vtab_error(describe_microcode_failure(func_addr, requested, failure));
}

std::optional<std::string> microcode_error(ea_t func_addr, const std::string& maturity,
                                           std::string* bad_argument) {
    mba_maturity_t reqmat = MMAT_LVARS;
    if (!maturity.empty() && !name_to_mmat(maturity.c_str(), reqmat)) {
        if (bad_argument) *bad_argument = "unknown maturity '" + maturity + "'";
        return std::nullopt;
    }
    if (!idasql_is_func_start(func_addr)) {
        if (bad_argument) *bad_argument = "no function starts at " + idasql::format_ea_hex(func_addr);
        return std::nullopt;
    }
    hexrays_failure_t hf;
    mba_t* mba = nullptr;
    {
        checkpoints::ScopedDerivedWrites derived;
        mba = idasql_gen_microcode(func_addr, &hf, nullptr, DECOMP_NO_WAIT, reqmat);
    }
    if (mba == nullptr) return describe_microcode_failure(func_addr, reqmat, hf);
    delete mba;
    return std::nullopt;
}

// `report_generation_failure` distinguishes the two callers. A pushed-down
// `WHERE func_addr = X` asked about exactly one function, so a gen_microcode
// failure there is the answer and must surface. A full scan must instead skip
// the function and keep going -- every real binary contains functions Hex-Rays
// cannot lift, and aborting on the first one made unfiltered `microcode` /
// `ir_ops` / `ir_v_*` queries fail outright. This mirrors CtreeGenerator, which
// silently skips functions it cannot decompile.
bool collect_microcode(std::vector<MicrocodeRow>& rows, ea_t func_addr,
                       mba_maturity_t reqmat = MMAT_LVARS,
                       bool require_exact_maturity = false,
                       bool report_generation_failure = true) {
    rows.clear();
    if (microcode_scan_interrupted()) return false;
    if (!hexrays_available()) return false;
    if (!idasql_is_func_start(func_addr)) return false;

    hexrays_failure_t hf;
    mba_t* mba = nullptr;
    {
        // A read: IDB changes Hex-Rays makes while lifting are not writes.
        checkpoints::ScopedDerivedWrites derived;
        mba = idasql_gen_microcode(func_addr, &hf, nullptr, DECOMP_NO_WAIT, reqmat);
    }
    if (!mba) {
        if (report_generation_failure) {
            set_microcode_generation_error(func_addr, reqmat, hf);
        }
        return false;
    }
    if (microcode_scan_interrupted()) {
        delete mba;
        return false;
    }
    if (require_exact_maturity && mba->maturity != reqmat) {
        delete mba;
        return false;
    }

    // Emit the RETURNED maturity (honest under coercion), not the requested one.
    const char* mat = mmat_name(mba->maturity);
    const char* stg = mmat_stage(mba->maturity);

    int seq = 0;
    size_t scanned = 0;
    for (int b = 0; b < mba->qty; ++b) {
        mblock_t* blk = mba->get_mblock(b);
        if (!blk) continue;
        for (minsn_t* ins = blk->head; ins != nullptr; ins = ins->next) {
            if (((scanned++) & 1023u) == 0 && microcode_scan_interrupted()) {
                rows.clear();
                delete mba;
                return false;
            }
            MicrocodeRow r;
            r.func_addr = func_addr;
            r.block_num = blk->serial;
            r.seq = seq++;
            r.ea = ins->ea;
            r.opcode = ins->opcode;
            r.canonical_op = microcode_canonical_op(ins->opcode);
            r.maturity = mat;
            r.stage = stg;
            const char* t = ins->dstr();
            r.text = t ? t : "";
            if (ins->l.t != mop_z) { const char* s = ins->l.dstr(); r.l_text = s ? s : ""; }
            if (ins->r.t != mop_z) { const char* s = ins->r.dstr(); r.r_text = s ? s : ""; }
            if (ins->d.t != mop_z) { const char* s = ins->d.dstr(); r.d_text = s ? s : ""; }
            rows.push_back(std::move(r));
        }
    }
    if (microcode_scan_interrupted()) {
        rows.clear();
        delete mba;
        return false;
    }
    delete mba;  // gen_microcode returns an mba the caller owns
    return true;
}

// minsn operand (l/r/d) -> one of the 5 canonical kinds, or "" if outside the model.
static const char* mop_canonical_kind(const mop_t& m) {
    switch (m.t) {
        case mop_r:              return "reg";
        case mop_n: case mop_fn: return "imm";
        case mop_v:              return "mem";
        case mop_S: case mop_l:  return "var";
        case mop_d:              return "result";
        default:                 return "";
    }
}

// Operand rows (5-kind model) for one function's microcode at a maturity rung.
bool collect_microcode_operands(std::vector<MicrocodeOperandRow>& rows, ea_t func_addr,
                                mba_maturity_t reqmat = MMAT_LVARS,
                                bool require_exact_maturity = false,
                                bool report_generation_failure = true) {
    rows.clear();
    if (microcode_scan_interrupted()) return false;
    if (!hexrays_available()) return false;
    if (!idasql_is_func_start(func_addr)) return false;
    hexrays_failure_t hf;
    mba_t* mba = nullptr;
    {
        // A read: IDB changes Hex-Rays makes while lifting are not writes.
        checkpoints::ScopedDerivedWrites derived;
        mba = idasql_gen_microcode(func_addr, &hf, nullptr, DECOMP_NO_WAIT, reqmat);
    }
    if (!mba) {
        if (report_generation_failure) {
            set_microcode_generation_error(func_addr, reqmat, hf);
        }
        return false;
    }
    if (microcode_scan_interrupted()) {
        delete mba;
        return false;
    }
    if (require_exact_maturity && mba->maturity != reqmat) {
        delete mba;
        return false;
    }
    const char* mat = mmat_name(mba->maturity);
    const char* stg = mmat_stage(mba->maturity);
    int seq = 0;
    size_t scanned = 0;
    for (int b = 0; b < mba->qty; ++b) {
        mblock_t* blk = mba->get_mblock(b);
        if (!blk) continue;
        for (minsn_t* ins = blk->head; ins != nullptr; ins = ins->next) {
            if (((scanned++) & 1023u) == 0 && microcode_scan_interrupted()) {
                rows.clear();
                delete mba;
                return false;
            }
            const int op_seq = seq++;
            const mop_t* slots[3] = { &ins->l, &ins->r, &ins->d };
            const char* roles[3] = { "in", "in", "out" };
            for (int si = 0; si < 3; ++si) {
                const mop_t& m = *slots[si];
                if (m.t == mop_z) continue;
                MicrocodeOperandRow r;
                r.func_addr = func_addr;
                r.op_seq = op_seq;
                r.operand_index = si;
                r.role = roles[si];
                r.kind = mop_canonical_kind(m);
                const char* d = m.dstr();
                r.text = d ? d : "";
                r.size = m.size;
                // `value` is an integer column. Preserve mop_fn floating literals
                // losslessly in `text` and leave `value` SQL NULL.
                if (m.t == mop_n) { r.value = static_cast<int64_t>(m.value(false)); r.has_value = true; }
                r.maturity = mat;
                r.stage = stg;
                rows.push_back(std::move(r));
            }
        }
    }
    if (microcode_scan_interrupted()) {
        rows.clear();
        delete mba;
        return false;
    }
    delete mba;
    return true;
}

// Column order (must match the .column_* declarations) — the constraint-filter
// factory reads the pushed func_addr / maturity by index.
enum {
    MC_FUNC_ADDR = 0, MC_BLOCK_NUM, MC_SEQ, MC_ADDR, MC_OPCODE,
    MC_CANONICAL_OP, MC_MATURITY, MC_STAGE, MC_TEXT, MC_L_TEXT, MC_R_TEXT, MC_D_TEXT
};
enum {
    MO_FUNC_ADDR = 0, MO_OP_SEQ, MO_OPERAND_INDEX, MO_ROLE, MO_KIND,
    MO_TEXT, MO_VALUE, MO_SIZE, MO_MATURITY, MO_STAGE
};

// Generator over microcode ops: one function when func_addr was constrained, or
// all functions otherwise, at each requested maturity rung. A function Hex-Rays
// cannot lift contributes no rows, never an error: a pushed-down func_addr looks
// exactly like one probe of a join or an IN list, and one unliftable function must
// not fail the whole statement. microcode_error(func_addr) says why it failed.
template <typename Row, bool (*Collect)(std::vector<Row>&, ea_t, mba_maturity_t, bool, bool)>
class MicrocodeRungGenerator : public xsql::Generator<Row> {
    std::vector<mba_maturity_t> rungs_;
    ea_t target_;
    bool single_;
    bool require_exact_maturity_;
    bool valid_;
    bool single_done_ = false;
    bool have_func_ = false;
    ea_t func_ = BADADDR;
    size_t func_idx_ = 0;
    size_t rung_idx_ = 0;
    std::vector<Row> current_;
    size_t row_idx_ = 0;
    bool load_next() {
        for (;;) {
            if (microcode_scan_interrupted()) return false;
            if (!have_func_ || rung_idx_ >= rungs_.size()) {
                if (single_) {
                    if (single_done_) return false;
                    single_done_ = true;
                    func_ = target_;
                } else {
                    if (func_idx_ >= get_func_qty()) return false;
                    func_ = idasql_func_ea_by_num(func_idx_++);
                    if (func_ == BADADDR) continue;
                }
                have_func_ = true;
                rung_idx_ = 0;
            }
            const mba_maturity_t rung = rungs_[rung_idx_++];
            current_.clear();
            if (Collect(current_, func_, rung, require_exact_maturity_,
                        /*report_generation_failure=*/false) &&
                !current_.empty()) {
                row_idx_ = 0;
                return true;
            }
        }
    }
public:
    MicrocodeRungGenerator(std::vector<mba_maturity_t> rungs = {MMAT_LVARS},
                           ea_t target = BADADDR, bool single = false,
                           bool require_exact_maturity = false, bool valid = true)
        : rungs_(std::move(rungs)), target_(target), single_(single),
          require_exact_maturity_(require_exact_maturity), valid_(valid && !rungs_.empty()) {}
    bool next() override {
        if (!valid_) return false;
        bool ok = (!current_.empty() && row_idx_ + 1 < current_.size())
                      ? (++row_idx_, true) : load_next();
        return ok;
    }
    const Row& current() const override { return current_[row_idx_]; }
    int64_t rowid() const override {
        const auto& row = current_[row_idx_];
        return idasql::detail::pack_function_maturity_rowid(row.func_addr,
                                                            mmat_ordinal(row.maturity), row_idx_);
    }
};

using MicrocodeGenerator = MicrocodeRungGenerator<MicrocodeRow, collect_microcode>;

// Generator over microcode operands (same func/maturity selection).
using MicrocodeOperandGenerator =
    MicrocodeRungGenerator<MicrocodeOperandRow, collect_microcode_operands>;

// The maturity rungs, in IDA's order.
static const mba_maturity_t kAllRungs[] = {MMAT_GENERATED, MMAT_PREOPTIMIZED, MMAT_LOCOPT, MMAT_CALLS,
                                           MMAT_GLBOPT1,   MMAT_GLBOPT2,      MMAT_GLBOPT3, MMAT_LVARS};

// Does rung `name` satisfy `maturity <op> value` the way SQLite would compare it?
// The column is TEXT: a number on the right is compared as its text, NULL matches
// nothing, and a blob sorts after every text (so only < and <= hold).
static bool rung_matches(const char* name, xsql::ConstraintOp op, xsql::FunctionArg value) {
    if (value.is_null()) return false;
    if (value.type() == SQLITE_BLOB)
        return op == xsql::ConstraintOp::Lt || op == xsql::ConstraintOp::Le;
    const char* rhs_text = value.as_c_str();
    const std::string rhs = rhs_text ? rhs_text : "";
    const int cmp = std::strcmp(name, rhs.c_str());
    switch (op) {
        case xsql::ConstraintOp::Eq: return value.type() == SQLITE_TEXT && cmp == 0;
        case xsql::ConstraintOp::Gt: return cmp > 0;
        case xsql::ConstraintOp::Ge: return cmp >= 0;
        case xsql::ConstraintOp::Lt: return cmp < 0;
        case xsql::ConstraintOp::Le: return cmp <= 0;
        case xsql::ConstraintOp::Like: return sqlite3_strlike(rhs.c_str(), name, 0) == 0;
    }
    return false;
}

// Shared constraint parsing: optional func_addr + any maturity predicate the
// planner hands over (=, LIKE, <, <=, >, >=; IN arrives as one = per value).
// The rungs are exactly those whose name satisfies every predicate; without one,
// the default rung (lvars).
static void parse_ir_constraints(const std::vector<xsql::GeneratorConstraintArg>& args,
                                 int func_addr_col, int maturity_col,
                                 ea_t& target, bool& target_constrained,
                                 std::vector<mba_maturity_t>& rungs, bool& maturity_constrained,
                                 bool& valid) {
    target = BADADDR;
    target_constrained = false;
    maturity_constrained = false;
    valid = true;
    std::vector<mba_maturity_t> candidates(std::begin(kAllRungs), std::end(kAllRungs));
    // Both constraints are omit=1: a func_addr no integer equals (4096.5,
    // NULL, 'a') matches no row, and each maturity predicate is applied here.
    for (const auto& arg : args) {
        if (arg.column_index == func_addr_col) {
            if (arg.op != xsql::ConstraintOp::Eq) continue;
            const std::optional<int64_t> key = xsql::exact_int64(arg.value);
            if (!key) {
                valid = false;
                continue;
            }
            target = static_cast<ea_t>(static_cast<uint64_t>(*key));
            target_constrained = true;
        } else if (arg.column_index == maturity_col) {
            maturity_constrained = true;
            std::vector<mba_maturity_t> kept;
            for (const mba_maturity_t m : candidates) {
                if (rung_matches(mmat_name(m), arg.op, arg.value)) kept.push_back(m);
            }
            candidates.swap(kept);
        }
    }
    rungs = maturity_constrained ? candidates : std::vector<mba_maturity_t>{MMAT_LVARS};
    if (rungs.empty()) valid = false;
}

std::unique_ptr<xsql::Generator<MicrocodeRow>> make_microcode_generator(
        const std::vector<xsql::GeneratorConstraintArg>& args) {
    ea_t target; bool target_constrained;
    std::vector<mba_maturity_t> rungs; bool maturity_constrained; bool valid;
    parse_ir_constraints(args, MC_FUNC_ADDR, MC_MATURITY, target,
                         target_constrained, rungs, maturity_constrained, valid);
    return std::make_unique<MicrocodeGenerator>(
        std::move(rungs), target, target_constrained, maturity_constrained, valid);
}

std::unique_ptr<xsql::Generator<MicrocodeOperandRow>> make_microcode_operand_generator(
        const std::vector<xsql::GeneratorConstraintArg>& args) {
    ea_t target; bool target_constrained;
    std::vector<mba_maturity_t> rungs; bool maturity_constrained; bool valid;
    parse_ir_constraints(args, MO_FUNC_ADDR, MO_MATURITY, target,
                         target_constrained, rungs, maturity_constrained, valid);
    return std::make_unique<MicrocodeOperandGenerator>(
        std::move(rungs), target, target_constrained, maturity_constrained, valid);
}

GeneratorTableDef<MicrocodeRow> define_microcode() {
    // Column order MUST match the MC_* enum (the constraint-filter reads by index).
    return generator_table<MicrocodeRow>("microcode")
        .estimate_rows([]() -> size_t { return get_func_qty() * 30; })
        // Unconstrained full scan: all functions at the default rung (MMAT_LVARS).
        .generator([]() -> std::unique_ptr<xsql::Generator<MicrocodeRow>> {
            return std::make_unique<MicrocodeGenerator>();
        })
        .column_int64("func_addr", [](const MicrocodeRow& r) -> int64_t { return r.func_addr; })
        .column_int("block_num", [](const MicrocodeRow& r) -> int { return r.block_num; })
        .column_int("seq", [](const MicrocodeRow& r) -> int { return r.seq; })
        .column("addr", xsql::ColumnType::Integer, [](xsql::FunctionContext& ctx, const MicrocodeRow& r) {
            r.ea != BADADDR ? ctx.result_int64(static_cast<int64_t>(r.ea)) : ctx.result_null();
        })
        .column_int("opcode", [](const MicrocodeRow& r) -> int { return r.opcode; })
        .column_text("canonical_op", [](const MicrocodeRow& r) -> std::string { return r.canonical_op; })
        .column_text("maturity", [](const MicrocodeRow& r) -> std::string { return r.maturity; })
        .column_text("stage", [](const MicrocodeRow& r) -> std::string { return r.stage; })
        .column_text("text", [](const MicrocodeRow& r) -> std::string { return r.text; })
        .column_text("l_text", [](const MicrocodeRow& r) -> std::string { return r.l_text; })
        .column_text("r_text", [](const MicrocodeRow& r) -> std::string { return r.r_text; })
        .column_text("d_text", [](const MicrocodeRow& r) -> std::string { return r.d_text; })
        // WHERE func_addr=X [AND maturity <op> ...] -> one gen_microcode per selected rung.
        .constraint_filter(
            { xsql::optional_eq("func_addr"), xsql::optional_eq("maturity"),
              xsql::optional_like("maturity"), xsql::optional_gt("maturity"),
              xsql::optional_ge("maturity"), xsql::optional_lt("maturity"),
              xsql::optional_le("maturity") },
            make_microcode_generator, 5.0, 30.0)
        .build();
}

GeneratorTableDef<MicrocodeOperandRow> define_microcode_operands() {
    // Column order MUST match the MO_* enum.
    return generator_table<MicrocodeOperandRow>("microcode_operands")
        .estimate_rows([]() -> size_t { return get_func_qty() * 60; })
        .generator([]() -> std::unique_ptr<xsql::Generator<MicrocodeOperandRow>> {
            return std::make_unique<MicrocodeOperandGenerator>();
        })
        .column_int64("func_addr", [](const MicrocodeOperandRow& r) -> int64_t { return r.func_addr; })
        .column_int("op_seq", [](const MicrocodeOperandRow& r) -> int { return r.op_seq; })
        .column_int("operand_index", [](const MicrocodeOperandRow& r) -> int { return r.operand_index; })
        .column_text("role", [](const MicrocodeOperandRow& r) -> std::string { return r.role; })
        .column_text("kind", [](const MicrocodeOperandRow& r) -> std::string { return r.kind; })
        .column_text("text", [](const MicrocodeOperandRow& r) -> std::string { return r.text; })
        .column("value", xsql::ColumnType::Integer, [](xsql::FunctionContext& ctx, const MicrocodeOperandRow& r) {
            r.has_value ? ctx.result_int64(r.value) : ctx.result_null();
        })
        .column_int("size", [](const MicrocodeOperandRow& r) -> int { return r.size; })
        .column_text("maturity", [](const MicrocodeOperandRow& r) -> std::string { return r.maturity; })
        .column_text("stage", [](const MicrocodeOperandRow& r) -> std::string { return r.stage; })
        .constraint_filter(
            { xsql::optional_eq("func_addr"), xsql::optional_eq("maturity"),
              xsql::optional_like("maturity"), xsql::optional_gt("maturity"),
              xsql::optional_ge("maturity"), xsql::optional_lt("maturity"),
              xsql::optional_le("maturity") },
            make_microcode_operand_generator, 5.0, 60.0)
        .build();
}


// ============================================================================
// Cross-tool low-IR views (ir_ops / ir_v_* / ir_operands / ir_maturities) over
// the microcode + microcode_operands tables. Registered by
// DecompilerRegistry::register_all() after the microcode generator tables.
// ============================================================================
bool register_microcode_views(xsql::Database& db) {
    // ------------------------------------------------------------------------
    // Cross-tool low-IR (ir_ops family) over the microcode table. idasql's
    // native leg is Hex-Rays microcode (MMAT_LVARS); ir_ops maps its mcode_t
    // opcodes to the canonical P-code-style vocabulary (op) while preserving the
    // native mnemonic (native_op). is_ssa=0: MMAT_LVARS microcode is SSA-like
    // but not explicit SSA (no PHI), so we do not claim SSA. The ir_v_* views
    // are the portable, engine-agnostic surface shared with the other tools.
    // Always scope by func_addr (pushes down to the microcode generator).
    // ------------------------------------------------------------------------
    if (db.exec(R"(
        CREATE VIEW IF NOT EXISTS ir_ops AS
        SELECT
            func_addr,
            seq,
            addr,
            NULLIF(canonical_op, '') AS op,
            CASE WHEN instr(text, ' ') > 0
                 THEN substr(text, 1, instr(text, ' ') - 1)
                 ELSE text END AS native_op,
            0 AS is_ssa,
            maturity,
            stage
        FROM microcode
    )") != xsql::Status::ok)
        return false;

    if (db.exec(R"(
        CREATE VIEW IF NOT EXISTS ir_v_calls AS
        SELECT func_addr, seq, addr, canonical_op AS op
        FROM microcode WHERE canonical_op IN ('CALL', 'CALLIND')
    )") != xsql::Status::ok)
        return false;

    if (db.exec(R"(
        CREATE VIEW IF NOT EXISTS ir_v_mem_writes AS
        SELECT func_addr, seq, addr, canonical_op AS op
        FROM microcode WHERE canonical_op = 'STORE'
    )") != xsql::Status::ok)
        return false;

    if (db.exec(R"(
        CREATE VIEW IF NOT EXISTS ir_v_mem_reads AS
        SELECT func_addr, seq, addr, canonical_op AS op
        FROM microcode WHERE canonical_op = 'LOAD'
    )") != xsql::Status::ok)
        return false;

    if (db.exec(R"(
        CREATE VIEW IF NOT EXISTS ir_v_branches AS
        SELECT func_addr, seq, addr, canonical_op AS op
        FROM microcode WHERE canonical_op IN ('BRANCH', 'CBRANCH', 'BRANCHIND', 'RETURN')
    )") != xsql::Status::ok)
        return false;

    if (db.exec(R"(
        CREATE VIEW IF NOT EXISTS ir_v_arith AS
        SELECT func_addr, seq, addr, canonical_op AS op
        FROM microcode WHERE canonical_op IN (
            'INT_ADD','INT_SUB','INT_MULT','INT_DIV','INT_SDIV','INT_REM','INT_SREM',
            'INT_2COMP','INT_NEGATE','INT_AND','INT_OR','INT_XOR','INT_LEFT','INT_RIGHT','INT_SRIGHT',
            'FLOAT_ADD','FLOAT_SUB','FLOAT_MULT','FLOAT_DIV','FLOAT_NEG'
        )
    )") != xsql::Status::ok)
        return false;

    // ir_operands — the portable 8-column operand shape. It is deliberately
    // fixed to the default lvars rung because the cross-tool schema has no
    // maturity coordinate; lower-rung IDASQL queries must join the native
    // microcode_operands table on func_addr + seq + maturity.
    if (db.exec(R"(
        CREATE VIEW IF NOT EXISTS ir_operands AS
        SELECT func_addr, op_seq, operand_index, role,
               NULLIF(kind, '') AS kind, text, value, size
        FROM microcode_operands
        WHERE maturity = 'lvars'
    )") != xsql::Status::ok)
        return false;

    // ir_maturities — the microcode maturity ladder (discoverability). is_default is the
    // rung used when a query does not constrain maturity (MMAT_LVARS). is_ssa=0 (microcode
    // is SSA-like, not explicit) on every rung.
    if (db.exec(R"(
        CREATE VIEW IF NOT EXISTS ir_maturities AS
        SELECT 'generated'    AS maturity, 'raw'       AS stage, 0 AS ordinal, 0 AS is_default, 0 AS is_ssa
        UNION ALL SELECT 'preoptimized', 'optimized', 1, 0, 0
        UNION ALL SELECT 'locopt',       'optimized', 2, 0, 0
        UNION ALL SELECT 'calls',        'optimized', 3, 0, 0
        UNION ALL SELECT 'glbopt1',      'optimized', 4, 0, 0
        UNION ALL SELECT 'glbopt2',      'optimized', 5, 0, 0
        UNION ALL SELECT 'glbopt3',      'optimized', 6, 0, 0
        UNION ALL SELECT 'lvars',        'final',     7, 1, 0
    )") != xsql::Status::ok)
        return false;

    return true;
}

} // namespace decompiler
} // namespace idasql
