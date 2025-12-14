/**
 * disassembly.hpp - Disassembly-level SQL tables
 *
 * Provides instruction-level analysis via SQLite virtual tables.
 * Parallels the decompiler.hpp ctree tables but at the disassembly level.
 *
 * Tables:
 *   disasm_calls    - All call instructions with callee info
 *
 * Views:
 *   disasm_v_leaf_funcs   - Functions with no outgoing calls
 *   disasm_v_call_chains  - Recursive call chain paths up to depth 10
 */

#pragma once

#include <idasql/vtable.hpp>

// IDA SDK headers
#include <ida.hpp>
#include <funcs.hpp>
#include <ua.hpp>      // decode_insn, insn_t, is_call_insn
#include <idp.hpp>     // is_call_insn
#include <xref.hpp>    // get_first_fcref_from
#include <name.hpp>    // get_name

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

inline std::vector<DisasmCallInfo>& get_disasm_calls_cache() {
    static std::vector<DisasmCallInfo> cache;
    return cache;
}

inline void rebuild_disasm_calls_cache() {
    auto& cache = get_disasm_calls_cache();
    cache.clear();

    size_t func_qty = get_func_qty();
    for (size_t i = 0; i < func_qty; i++) {
        func_t* pfn = getn_func(i);
        if (!pfn) continue;

        // Iterate all code items in function
        func_item_iterator_t fii;
        for (bool ok = fii.set(pfn); ok; ok = fii.next_code()) {
            ea_t ea = fii.current();
            insn_t insn;

            if (decode_insn(&insn, ea) > 0 && is_call_insn(insn)) {
                DisasmCallInfo info;
                info.func_addr = pfn->start_ea;
                info.ea = ea;

                // Get call target from xrefs
                info.callee_addr = get_first_fcref_from(ea);
                if (info.callee_addr != BADADDR) {
                    info.callee_name = safe_name(info.callee_addr);
                }

                cache.push_back(info);
            }
        }
    }
}

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

inline VTableDef define_disasm_calls() {
    rebuild_disasm_calls_cache();

    return table("disasm_calls")
        .count([]() {
            rebuild_disasm_calls_cache();
            return get_disasm_calls_cache().size();
        })
        .column_int64("func_addr", [](size_t i) -> int64_t {
            auto& cache = get_disasm_calls_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].func_addr) : 0;
        })
        .column_int64("ea", [](size_t i) -> int64_t {
            auto& cache = get_disasm_calls_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].ea) : 0;
        })
        .column_int64("callee_addr", [](size_t i) -> int64_t {
            auto& cache = get_disasm_calls_cache();
            if (i >= cache.size()) return 0;
            return cache[i].callee_addr != BADADDR
                ? static_cast<int64_t>(cache[i].callee_addr)
                : 0;  // NULL represented as 0 for now
        })
        .column_text("callee_name", [](size_t i) -> std::string {
            auto& cache = get_disasm_calls_cache();
            return i < cache.size() ? cache[i].callee_name : "";
        })
        // Constraint pushdown: func_addr = X bypasses full cache
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<DisasmCallsInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 10.0)  // Low cost - only iterates one function
        .build();
}

// ============================================================================
// View Registration
// ============================================================================

inline bool register_disasm_views(sqlite3* db) {
    char* err = nullptr;

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
    sqlite3_exec(db, v_leaf_funcs, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

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
    sqlite3_exec(db, v_call_chains, nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }

    return true;
}

// ============================================================================
// Registry for all disassembly tables
// ============================================================================

struct DisassemblyRegistry {
    VTableDef disasm_calls;

    DisassemblyRegistry()
        : disasm_calls(define_disasm_calls())
    {}

    void register_all(sqlite3* db) {
        // Register virtual table
        register_and_create(db, "disasm_calls", &disasm_calls);

        // Register views on top
        register_disasm_views(db);
    }

private:
    void register_and_create(sqlite3* db, const char* name, const VTableDef* def) {
        std::string module_name = std::string("ida_") + name;
        register_vtable(db, module_name.c_str(), def);
        create_vtable(db, name, module_name.c_str());
    }
};

} // namespace disassembly
} // namespace idasql
