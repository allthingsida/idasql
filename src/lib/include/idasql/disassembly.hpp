/**
 * disassembly.hpp - Disassembly-level SQL tables
 *
 * Provides instruction-level analysis via SQLite virtual tables.
 * Parallels the decompiler.hpp ctree tables but at the disassembly level.
 *
 * Tables:
 *   disasm_calls    - All call instructions with callee info
 *   disasm_loops    - Detected loops via back-edge analysis
 *
 * Views:
 *   disasm_v_leaf_funcs     - Functions with no outgoing calls
 *   disasm_v_call_chains    - Recursive call chain paths up to depth 10
 *   disasm_v_calls_in_loops - Calls that occur inside detected loops
 *   disasm_v_funcs_with_loops - Functions that contain loops
 *
 * All tables support constraint pushdown on func_addr for efficient queries.
 */

#pragma once

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

// macOS: Undefine Mach kernel types before IDA headers
// (system headers define processor_t and token_t as typedefs)
#ifdef __APPLE__
#undef processor_t
#undef token_t
#endif

// IDA SDK headers
#include <ida.hpp>
#include <funcs.hpp>
#include <ua.hpp>      // decode_insn, insn_t, is_call_insn
#include <idp.hpp>     // is_call_insn
#include <xref.hpp>    // get_first_fcref_from
#include <name.hpp>    // get_name
#include <gdl.hpp>     // qflow_chart_t for CFG analysis

#include <vector>
#include <string>

namespace idasql {
namespace disassembly {

// ============================================================================
// Helper functions
// ============================================================================

inline std::string safe_name(ea_t ea) {
    qstring name;
    get_name(&name, ea);
    return std::string(name.c_str());
}

// ============================================================================
// DISASM_CALLS Table
// All call instructions across all functions
// ============================================================================

struct DisasmCallInfo {
    ea_t func_addr;     // Function containing this call
    ea_t ea;            // Address of call instruction
    ea_t callee_addr;   // Target of call (BADADDR if unknown)
    std::string callee_name;
};

// ============================================================================
// DisasmCallsInFuncIterator - Constraint pushdown for func_addr = X
// Iterates calls in a single function without building the full cache
// ============================================================================

class DisasmCallsInFuncIterator : public xsql::RowIterator {
    ea_t func_addr_;
    func_t* pfn_ = nullptr;
    func_item_iterator_t fii_;
    bool started_ = false;
    bool valid_ = false;

    // Current call info
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
            // Initialize iterator and find first code item
            if (!fii_.set(pfn_)) {
                valid_ = false;
                return false;
            }
            // Check if first item is a call
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
            // First item wasn't a call, find next
            valid_ = find_next_call();
            return valid_;
        }

        valid_ = find_next_call();
        return valid_;
    }

    bool eof() const override {
        return started_ && !valid_;
    }

    void column(sqlite3_context* ctx, int col) override {
        switch (col) {
            case 0: // func_addr
                sqlite3_result_int64(ctx, static_cast<int64_t>(func_addr_));
                break;
            case 1: // ea
                sqlite3_result_int64(ctx, static_cast<int64_t>(current_ea_));
                break;
            case 2: // callee_addr
                if (callee_addr_ != BADADDR) {
                    sqlite3_result_int64(ctx, static_cast<int64_t>(callee_addr_));
                } else {
                    sqlite3_result_int64(ctx, 0);
                }
                break;
            case 3: // callee_name
                sqlite3_result_text(ctx, callee_name_.c_str(),
                                    static_cast<int>(callee_name_.size()),
                                    SQLITE_TRANSIENT);
                break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(current_ea_);
    }
};

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

    sqlite3_int64 rowid() const override { return static_cast<sqlite3_int64>(current_.ea); }
};

inline GeneratorTableDef<DisasmCallInfo> define_disasm_calls() {
    return generator_table<DisasmCallInfo>("disasm_calls")
        .estimate_rows([]() -> size_t {
            // Heuristic: a few calls per function
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
        // Constraint pushdown: func_addr = X bypasses full scan
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<DisasmCallsInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 10.0)  // Low cost - only iterates one function
        .build();
}

// ============================================================================
// DISASM_LOOPS Table
// Detected loops via back-edge analysis using qflow_chart_t
// ============================================================================

struct LoopInfo {
    ea_t func_addr;
    int loop_id;           // Unique ID (header block index)
    ea_t header_ea;        // Loop header start address
    ea_t header_end_ea;    // Loop header end address
    ea_t back_edge_block_ea;  // Block containing the back-edge jump
    ea_t back_edge_block_end; // End of back-edge block
};

inline void collect_loops_for_func(std::vector<LoopInfo>& loops, func_t* pfn) {
    if (!pfn) return;

    qflow_chart_t fc;
    fc.create("", pfn, pfn->start_ea, pfn->end_ea, FC_NOEXT);

    for (int i = 0; i < fc.size(); i++) {
        const qbasic_block_t& block = fc.blocks[i];

        // Check each successor for back-edges
        for (int j = 0; j < fc.nsucc(i); j++) {
            int succ_idx = fc.succ(i, j);
            if (succ_idx < 0 || succ_idx >= fc.size()) continue;

            const qbasic_block_t& succ = fc.blocks[succ_idx];

            // Back-edge: successor starts at or before current block
            // This indicates a loop where succ is the header
            if (succ.start_ea <= block.start_ea) {
                LoopInfo li;
                li.func_addr = pfn->start_ea;
                li.loop_id = succ_idx;  // Use header block index as loop ID
                li.header_ea = succ.start_ea;
                li.header_end_ea = succ.end_ea;
                li.back_edge_block_ea = block.start_ea;
                li.back_edge_block_end = block.end_ea;
                loops.push_back(li);
            }
        }
    }
}

// Iterator for loops in a single function (constraint pushdown)
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

    void column(sqlite3_context* ctx, int col) override {
        if (idx_ >= loops_.size()) { sqlite3_result_null(ctx); return; }
        const auto& li = loops_[idx_];
        switch (col) {
            case 0: sqlite3_result_int64(ctx, static_cast<int64_t>(li.func_addr)); break;
            case 1: sqlite3_result_int(ctx, li.loop_id); break;
            case 2: sqlite3_result_int64(ctx, static_cast<int64_t>(li.header_ea)); break;
            case 3: sqlite3_result_int64(ctx, static_cast<int64_t>(li.header_end_ea)); break;
            case 4: sqlite3_result_int64(ctx, static_cast<int64_t>(li.back_edge_block_ea)); break;
            case 5: sqlite3_result_int64(ctx, static_cast<int64_t>(li.back_edge_block_end)); break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(idx_); }
};

class DisasmLoopsGenerator : public xsql::Generator<LoopInfo> {
    size_t func_idx_ = 0;
    std::vector<LoopInfo> loops_;
    size_t idx_ = 0;
    sqlite3_int64 rowid_ = -1;
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

    sqlite3_int64 rowid() const override { return rowid_; }
};

inline GeneratorTableDef<LoopInfo> define_disasm_loops() {
    return generator_table<LoopInfo>("disasm_loops")
        .estimate_rows([]() -> size_t {
            // Heuristic: very few loops per function
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

// ============================================================================
// View Registration
// ============================================================================

inline bool register_disasm_views(xsql::Database& db) {

    // disasm_v_leaf_funcs - Functions with no outgoing calls (terminal/leaf functions)
    // Uses disasm_calls to detect calls at the disassembly level
    const char* v_leaf_funcs = R"(
        CREATE VIEW IF NOT EXISTS disasm_v_leaf_funcs AS
        SELECT f.address, f.name
        FROM funcs f
        LEFT JOIN disasm_calls c ON c.func_addr = f.address
        GROUP BY f.address
        HAVING COUNT(c.callee_addr) = 0
    )";
    db.exec(v_leaf_funcs);

    // disasm_v_call_chains - All call chain paths (root_func -> current_func at depth N)
    // Enables queries like "find functions with call chains reaching depth 6"
    const char* v_call_chains = R"(
        CREATE VIEW IF NOT EXISTS disasm_v_call_chains AS
        WITH RECURSIVE call_chain(root_func, current_func, depth) AS (
            -- Base: direct calls from each function
            SELECT DISTINCT func_addr, callee_addr, 1
            FROM disasm_calls
            WHERE callee_addr IS NOT NULL AND callee_addr != 0

            UNION ALL

            -- Recursive: follow callees deeper
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

    // disasm_v_calls_in_loops - Calls that occur inside detected loops
    // A call is considered "in a loop" if its address is between the loop header
    // and the end of the back-edge block
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

    // disasm_v_funcs_with_loops - Functions that contain loops
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
// Registry for all disassembly tables
// ============================================================================

struct DisassemblyRegistry {
    GeneratorTableDef<DisasmCallInfo> disasm_calls;
    GeneratorTableDef<LoopInfo> disasm_loops;

    DisassemblyRegistry()
        : disasm_calls(define_disasm_calls())
        , disasm_loops(define_disasm_loops())
    {}

    void register_all(xsql::Database& db) {
        db.register_generator_table("ida_disasm_calls", &disasm_calls);
        db.create_table("disasm_calls", "ida_disasm_calls");

        db.register_generator_table("ida_disasm_loops", &disasm_loops);
        db.create_table("disasm_loops", "ida_disasm_loops");

        // Register views on top
        register_disasm_views(db);
    }
};

} // namespace disassembly
} // namespace idasql
