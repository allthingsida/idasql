// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

#include "disassembly.hpp"

namespace idasql {
namespace disassembly {

std::string safe_name(ea_t ea) {
    qstring name;
    get_name(&name, ea);
    return std::string(name.c_str());
}

void collect_loops_for_func(std::vector<LoopInfo>& loops, func_t* pfn) {
    if (!pfn) return;

    qflow_chart_t fc;
    fc.create("", pfn, pfn->start_ea, pfn->end_ea, FC_NOEXT);

    for (int i = 0; i < fc.size(); i++) {
        const qbasic_block_t& block = fc.blocks[i];

        for (int j = 0; j < fc.nsucc(i); j++) {
            int succ_idx = fc.succ(i, j);
            if (succ_idx < 0 || succ_idx >= fc.size()) continue;

            const qbasic_block_t& succ = fc.blocks[succ_idx];

            if (succ.start_ea <= block.start_ea) {
                LoopInfo li;
                li.func_addr = pfn->start_ea;
                li.loop_id = succ_idx;
                li.header_ea = succ.start_ea;
                li.header_end_ea = succ.end_ea;
                li.back_edge_block_ea = block.start_ea;
                li.back_edge_block_end = block.end_ea;
                loops.push_back(li);
            }
        }
    }
}

// ============================================================================
// DisasmCallsInFuncIterator
// ============================================================================

class DisasmCallsInFuncIterator : public xsql::RowIterator {
    ea_t func_addr_;
    func_t* pfn_ = nullptr;
    func_item_iterator_t fii_;
    bool started_ = false;
    bool valid_ = false;
    ea_t current_ea_ = BADADDR;
    ea_t callee_addr_ = BADADDR;
    std::string callee_name_;

    bool find_next_call() {
        while (fii_.next_code()) {
            ea_t ea = fii_.current();
            insn_t insn;
            if (decode_insn(&insn, ea) > 0 && is_call_insn(insn)) {
                current_ea_ = ea;
                callee_addr_ = get_first_fcref_from(ea);
                if (callee_addr_ != BADADDR) {
                    callee_name_ = safe_name(callee_addr_);
                } else {
                    callee_name_.clear();
                }
                return true;
            }
        }
        return false;
    }

public:
    explicit DisasmCallsInFuncIterator(ea_t func_addr)
        : func_addr_(func_addr)
    {
        pfn_ = get_func(func_addr_);
    }

    bool next() override {
        if (!pfn_) return false;

        if (!started_) {
            started_ = true;
            if (!fii_.set(pfn_)) {
                valid_ = false;
                return false;
            }
            ea_t ea = fii_.current();
            insn_t insn;
            if (decode_insn(&insn, ea) > 0 && is_call_insn(insn)) {
                current_ea_ = ea;
                callee_addr_ = get_first_fcref_from(ea);
                if (callee_addr_ != BADADDR) {
                    callee_name_ = safe_name(callee_addr_);
                } else {
                    callee_name_.clear();
                }
                valid_ = true;
                return true;
            }
            valid_ = find_next_call();
            return valid_;
        }

        valid_ = find_next_call();
        return valid_;
    }

    bool eof() const override {
        return started_ && !valid_;
    }

    void column(xsql::FunctionContext& ctx, int col) override {
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(func_addr_)); break;
            case 1: ctx.result_int64(static_cast<int64_t>(current_ea_)); break;
            case 2:
                if (callee_addr_ != BADADDR) {
                    ctx.result_int64(static_cast<int64_t>(callee_addr_));
                } else {
                    ctx.result_int64(0);
                }
                break;
            case 3: ctx.result_text(callee_name_.c_str()); break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(current_ea_);
    }
};

// ============================================================================
// DisasmCallsGenerator
// ============================================================================

class DisasmCallsGenerator : public xsql::Generator<DisasmCallInfo> {
    size_t func_idx_ = 0;
    func_t* pfn_ = nullptr;
    func_item_iterator_t fii_;
    bool in_func_started_ = false;
    DisasmCallInfo current_;

    bool start_next_func() {
        size_t func_qty = get_func_qty();
        while (func_idx_ < func_qty) {
            pfn_ = getn_func(func_idx_++);
            if (!pfn_) continue;

            if (fii_.set(pfn_)) {
                in_func_started_ = false;
                return true;
            }
        }
        pfn_ = nullptr;
        return false;
    }

    bool find_next_call_in_current_func() {
        if (!pfn_) return false;

        while (true) {
            ea_t ea = BADADDR;
            if (!in_func_started_) {
                in_func_started_ = true;
                ea = fii_.current();
            } else {
                if (!fii_.next_code()) return false;
                ea = fii_.current();
            }

            insn_t insn;
            if (decode_insn(&insn, ea) > 0 && is_call_insn(insn)) {
                current_.func_addr = pfn_->start_ea;
                current_.ea = ea;
                current_.callee_addr = get_first_fcref_from(ea);
                if (current_.callee_addr != BADADDR) {
                    current_.callee_name = safe_name(current_.callee_addr);
                } else {
                    current_.callee_name.clear();
                }
                return true;
            }
        }
    }

public:
    bool next() override {
        while (true) {
            if (!pfn_) {
                if (!start_next_func()) return false;
            }

            if (find_next_call_in_current_func()) return true;
            pfn_ = nullptr;
        }
    }

    const DisasmCallInfo& current() const override { return current_; }
    int64_t rowid() const override { return static_cast<int64_t>(current_.ea); }
};

// ============================================================================
// LoopsInFuncIterator
// ============================================================================

class LoopsInFuncIterator : public xsql::RowIterator {
    std::vector<LoopInfo> loops_;
    size_t idx_ = 0;
    bool started_ = false;

public:
    explicit LoopsInFuncIterator(ea_t func_addr) {
        func_t* pfn = get_func(func_addr);
        if (pfn) {
            collect_loops_for_func(loops_, pfn);
        }
    }

    bool next() override {
        if (!started_) {
            started_ = true;
            if (loops_.empty()) return false;
            idx_ = 0;
            return true;
        }
        if (idx_ + 1 < loops_.size()) { ++idx_; return true; }
        idx_ = loops_.size();
        return false;
    }

    bool eof() const override { return started_ && idx_ >= loops_.size(); }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (idx_ >= loops_.size()) { ctx.result_null(); return; }
        const auto& li = loops_[idx_];
        switch (col) {
            case 0: ctx.result_int64(static_cast<int64_t>(li.func_addr)); break;
            case 1: ctx.result_int(li.loop_id); break;
            case 2: ctx.result_int64(static_cast<int64_t>(li.header_ea)); break;
            case 3: ctx.result_int64(static_cast<int64_t>(li.header_end_ea)); break;
            case 4: ctx.result_int64(static_cast<int64_t>(li.back_edge_block_ea)); break;
            case 5: ctx.result_int64(static_cast<int64_t>(li.back_edge_block_end)); break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(idx_); }
};

// ============================================================================
// DisasmLoopsGenerator
// ============================================================================

class DisasmLoopsGenerator : public xsql::Generator<LoopInfo> {
    size_t func_idx_ = 0;
    std::vector<LoopInfo> loops_;
    size_t idx_ = 0;
    int64_t rowid_ = -1;
    bool started_ = false;

    bool load_next_func() {
        size_t func_qty = get_func_qty();
        while (func_idx_ < func_qty) {
            func_t* pfn = getn_func(func_idx_++);
            if (!pfn) continue;

            loops_.clear();
            collect_loops_for_func(loops_, pfn);
            if (!loops_.empty()) {
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

        if (idx_ + 1 < loops_.size()) {
            ++idx_;
            ++rowid_;
            return true;
        }

        if (!load_next_func()) return false;
        ++rowid_;
        return true;
    }

    const LoopInfo& current() const override { return loops_[idx_]; }
    int64_t rowid() const override { return rowid_; }
};

// ============================================================================
// Table definitions
// ============================================================================

GeneratorTableDef<DisasmCallInfo> define_disasm_calls() {
    return generator_table<DisasmCallInfo>("disasm_calls")
        .estimate_rows([]() -> size_t {
            return get_func_qty() * 5;
        })
        .generator([]() -> std::unique_ptr<xsql::Generator<DisasmCallInfo>> {
            return std::make_unique<DisasmCallsGenerator>();
        })
        .column_int64("func_addr", [](const DisasmCallInfo& r) -> int64_t { return r.func_addr; })
        .column_int64("ea", [](const DisasmCallInfo& r) -> int64_t { return r.ea; })
        .column_int64("callee_addr", [](const DisasmCallInfo& r) -> int64_t {
            return r.callee_addr != BADADDR ? static_cast<int64_t>(r.callee_addr) : 0;
        })
        .column_text("callee_name", [](const DisasmCallInfo& r) -> std::string { return r.callee_name; })
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<DisasmCallsInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 10.0)
        .build();
}

GeneratorTableDef<LoopInfo> define_disasm_loops() {
    return generator_table<LoopInfo>("disasm_loops")
        .estimate_rows([]() -> size_t {
            return get_func_qty() * 2;
        })
        .generator([]() -> std::unique_ptr<xsql::Generator<LoopInfo>> {
            return std::make_unique<DisasmLoopsGenerator>();
        })
        .column_int64("func_addr", [](const LoopInfo& r) -> int64_t { return r.func_addr; })
        .column_int("loop_id", [](const LoopInfo& r) -> int { return r.loop_id; })
        .column_int64("header_ea", [](const LoopInfo& r) -> int64_t { return r.header_ea; })
        .column_int64("header_end_ea", [](const LoopInfo& r) -> int64_t { return r.header_end_ea; })
        .column_int64("back_edge_block_ea", [](const LoopInfo& r) -> int64_t { return r.back_edge_block_ea; })
        .column_int64("back_edge_block_end", [](const LoopInfo& r) -> int64_t { return r.back_edge_block_end; })
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<LoopsInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 5.0)
        .build();
}

bool register_disasm_views(xsql::Database& db) {
    const char* v_leaf_funcs = R"(
        CREATE VIEW IF NOT EXISTS disasm_v_leaf_funcs AS
        SELECT f.address, f.name
        FROM funcs f
        LEFT JOIN disasm_calls c ON c.func_addr = f.address
        GROUP BY f.address
        HAVING COUNT(c.callee_addr) = 0
    )";
    db.exec(v_leaf_funcs);

    const char* v_call_chains = R"(
        CREATE VIEW IF NOT EXISTS disasm_v_call_chains AS
        WITH RECURSIVE call_chain(root_func, current_func, depth) AS (
            SELECT DISTINCT func_addr, callee_addr, 1
            FROM disasm_calls
            WHERE callee_addr IS NOT NULL AND callee_addr != 0

            UNION ALL

            SELECT cc.root_func, c.callee_addr, cc.depth + 1
            FROM call_chain cc
            JOIN disasm_calls c ON c.func_addr = cc.current_func
            WHERE cc.depth < 10
              AND c.callee_addr IS NOT NULL
              AND c.callee_addr != 0
        )
        SELECT DISTINCT
            root_func,
            current_func,
            depth
        FROM call_chain
    )";
    db.exec(v_call_chains);

    const char* v_calls_in_loops = R"(
        CREATE VIEW IF NOT EXISTS disasm_v_calls_in_loops AS
        SELECT
            c.func_addr,
            c.ea,
            c.callee_addr,
            c.callee_name,
            l.loop_id,
            l.header_ea as loop_header,
            l.back_edge_block_ea,
            l.back_edge_block_end
        FROM disasm_calls c
        JOIN disasm_loops l ON l.func_addr = c.func_addr
        WHERE c.ea >= l.header_ea AND c.ea < l.back_edge_block_end
    )";
    db.exec(v_calls_in_loops);

    const char* v_funcs_with_loops = R"(
        CREATE VIEW IF NOT EXISTS disasm_v_funcs_with_loops AS
        SELECT
            f.address,
            f.name,
            COUNT(DISTINCT l.loop_id) as loop_count
        FROM funcs f
        JOIN disasm_loops l ON l.func_addr = f.address
        GROUP BY f.address
    )";
    db.exec(v_funcs_with_loops);

    return true;
}

// ============================================================================
// Registry
// ============================================================================

DisassemblyRegistry::DisassemblyRegistry()
    : disasm_calls(define_disasm_calls())
    , disasm_loops(define_disasm_loops())
{}

void DisassemblyRegistry::register_all(xsql::Database& db) {
    db.register_generator_table("ida_disasm_calls", &disasm_calls);
    db.create_table("disasm_calls", "ida_disasm_calls");

    db.register_generator_table("ida_disasm_loops", &disasm_loops);
    db.create_table("disasm_loops", "ida_disasm_loops");

    register_disasm_views(db);
}

} // namespace disassembly
} // namespace idasql
