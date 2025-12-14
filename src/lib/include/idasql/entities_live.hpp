/**
 * ida_entities_live.hpp - Live IDA entities with UPDATE/DELETE support
 *
 * Uses v2 framework for:
 *   - No caching - fresh data on every query
 *   - UPDATE support for writable columns
 *   - DELETE support where applicable
 *   - Automatic undo points for modifications
 *
 * Writable Tables:
 *   names_live     - Rename addresses (UPDATE name)
 *   comments_live  - Add/edit/delete comments (UPDATE/DELETE)
 *   funcs_live     - Rename functions (UPDATE name)
 *   bookmarks      - Full CRUD for bookmarks
 */

#pragma once

#include <idasql/vtable_v2.hpp>

// IDA SDK headers (order matters)
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>    // Must come before moves.hpp (defines tcc_renderer_type_t)
#include <ua.hpp>         // insn_t, op_t
#include <funcs.hpp>
#include <name.hpp>
#include <lines.hpp>
#include <segment.hpp>
#include <moves.hpp>

namespace idasql {
namespace live {

// ============================================================================
// NAMES_LIVE Table - Named locations with UPDATE support
// ============================================================================

inline VTableDef define_names_live() {
    return live_table("names_live")
        .count([]() {
            return get_nlist_size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            return get_nlist_ea(i);
        })
        .column_text_rw("name",
            // Getter
            [](size_t i) -> std::string {
                const char* n = get_nlist_name(i);
                return n ? n : "";
            },
            // Setter - rename the address
            [](size_t i, const char* new_name) -> bool {
                ea_t ea = get_nlist_ea(i);
                if (ea == BADADDR) return false;
                return set_name(ea, new_name, SN_CHECK) != 0;
            })
        .column_int("is_public", [](size_t i) -> int {
            return is_public_name(get_nlist_ea(i)) ? 1 : 0;
        })
        .column_int("is_weak", [](size_t i) -> int {
            return is_weak_name(get_nlist_ea(i)) ? 1 : 0;
        })
        .build();
}

// ============================================================================
// COMMENTS_LIVE Table - Comments with UPDATE/DELETE support
// ============================================================================

// Helper to iterate addresses with comments
struct CommentIterator {
    static std::vector<ea_t>& get_addresses() {
        static std::vector<ea_t> addrs;
        return addrs;
    }

    static void rebuild() {
        auto& addrs = get_addresses();
        addrs.clear();

        ea_t ea = inf_get_min_ea();
        ea_t max_ea = inf_get_max_ea();

        while (ea < max_ea) {
            qstring cmt, rpt;
            bool has_cmt = get_cmt(&cmt, ea, false) > 0;
            bool has_rpt = get_cmt(&rpt, ea, true) > 0;

            if (has_cmt || has_rpt) {
                addrs.push_back(ea);
            }

            ea = next_head(ea, max_ea);
            if (ea == BADADDR) break;
        }
    }
};

inline VTableDef define_comments_live() {
    return live_table("comments_live")
        .count([]() {
            CommentIterator::rebuild();
            return CommentIterator::get_addresses().size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& addrs = CommentIterator::get_addresses();
            return i < addrs.size() ? addrs[i] : 0;
        })
        .column_text_rw("comment",
            // Getter
            [](size_t i) -> std::string {
                auto& addrs = CommentIterator::get_addresses();
                if (i >= addrs.size()) return "";
                qstring cmt;
                get_cmt(&cmt, addrs[i], false);
                return cmt.c_str();
            },
            // Setter
            [](size_t i, const char* new_cmt) -> bool {
                auto& addrs = CommentIterator::get_addresses();
                if (i >= addrs.size()) return false;
                return set_cmt(addrs[i], new_cmt, false);
            })
        .column_text_rw("rpt_comment",
            // Getter
            [](size_t i) -> std::string {
                auto& addrs = CommentIterator::get_addresses();
                if (i >= addrs.size()) return "";
                qstring cmt;
                get_cmt(&cmt, addrs[i], true);
                return cmt.c_str();
            },
            // Setter
            [](size_t i, const char* new_cmt) -> bool {
                auto& addrs = CommentIterator::get_addresses();
                if (i >= addrs.size()) return false;
                return set_cmt(addrs[i], new_cmt, true);
            })
        .deletable([](size_t i) -> bool {
            // Delete both comments at this address
            auto& addrs = CommentIterator::get_addresses();
            if (i >= addrs.size()) return false;
            ea_t ea = addrs[i];
            set_cmt(ea, "", false);  // Delete regular
            set_cmt(ea, "", true);   // Delete repeatable
            return true;
        })
        .build();
}

// ============================================================================
// FUNCS_LIVE Table - Functions with UPDATE support
// ============================================================================

inline VTableDef define_funcs_live() {
    return live_table("funcs_live")
        .count([]() {
            return get_func_qty();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            func_t* f = getn_func(i);
            return f ? f->start_ea : 0;
        })
        .column_text_rw("name",
            // Getter
            [](size_t i) -> std::string {
                func_t* f = getn_func(i);
                if (!f) return "";
                qstring name;
                get_func_name(&name, f->start_ea);
                return name.c_str();
            },
            // Setter - rename function
            [](size_t i, const char* new_name) -> bool {
                func_t* f = getn_func(i);
                if (!f) return false;
                return set_name(f->start_ea, new_name, SN_CHECK) != 0;
            })
        .column_int64("size", [](size_t i) -> int64_t {
            func_t* f = getn_func(i);
            return f ? f->size() : 0;
        })
        .column_int("flags", [](size_t i) -> int {
            func_t* f = getn_func(i);
            return f ? f->flags : 0;
        })
        .column_int64("end_ea", [](size_t i) -> int64_t {
            func_t* f = getn_func(i);
            return f ? f->end_ea : 0;
        })
        .deletable([](size_t i) -> bool {
            // Delete the function definition
            func_t* f = getn_func(i);
            if (!f) return false;
            return del_func(f->start_ea);
        })
        .build();
}

// ============================================================================
// BOOKMARKS Table - Full CRUD support
// ============================================================================

// Helper for bookmark iteration
struct BookmarkIterator {
    struct Entry {
        uint32_t index;
        ea_t ea;
        std::string desc;
    };

    static std::vector<Entry>& get_entries() {
        static std::vector<Entry> entries;
        return entries;
    }

    static void rebuild() {
        auto& entries = get_entries();
        entries.clear();

        // Get bookmarks for IDA View (disassembly)
        // We need a place_t for the bookmark API
        idaplace_t idaplace(inf_get_min_ea(), 0);
        renderer_info_t rinfo;
        lochist_entry_t loc(&idaplace, rinfo);

        uint32_t count = bookmarks_t::size(loc, nullptr);

        for (uint32_t idx = 0; idx < count; ++idx) {
            idaplace_t place(0, 0);
            lochist_entry_t entry(&place, rinfo);
            qstring desc;
            uint32_t index = idx;

            if (bookmarks_t::get(&entry, &desc, &index, nullptr)) {
                Entry e;
                e.index = index;
                e.ea = ((idaplace_t*)entry.place())->ea;
                e.desc = desc.c_str();
                entries.push_back(e);
            }
        }
    }
};

inline VTableDef define_bookmarks() {
    return live_table("bookmarks")
        .count([]() {
            BookmarkIterator::rebuild();
            return BookmarkIterator::get_entries().size();
        })
        .column_int("slot", [](size_t i) -> int {
            auto& entries = BookmarkIterator::get_entries();
            return i < entries.size() ? entries[i].index : 0;
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& entries = BookmarkIterator::get_entries();
            return i < entries.size() ? entries[i].ea : 0;
        })
        .column_text_rw("description",
            // Getter
            [](size_t i) -> std::string {
                auto& entries = BookmarkIterator::get_entries();
                return i < entries.size() ? entries[i].desc : "";
            },
            // Setter - update bookmark description
            [](size_t i, const char* new_desc) -> bool {
                auto& entries = BookmarkIterator::get_entries();
                if (i >= entries.size()) return false;

                idaplace_t place(entries[i].ea, 0);
                renderer_info_t rinfo;
                lochist_entry_t loc(&place, rinfo);
                return bookmarks_t_set_desc(qstring(new_desc), loc, entries[i].index, nullptr);
            })
        .deletable([](size_t i) -> bool {
            auto& entries = BookmarkIterator::get_entries();
            if (i >= entries.size()) return false;

            idaplace_t place(entries[i].ea, 0);
            renderer_info_t rinfo;
            lochist_entry_t loc(&place, rinfo);
            return bookmarks_t::erase(loc, entries[i].index, nullptr);
        })
        .build();
}

// ============================================================================
// HEADS Table - All defined items in the database
// ============================================================================

// Helper to collect all heads
struct HeadsIterator {
    static std::vector<ea_t>& get_addresses() {
        static std::vector<ea_t> addrs;
        return addrs;
    }

    static void rebuild() {
        auto& addrs = get_addresses();
        addrs.clear();

        ea_t ea = inf_get_min_ea();
        ea_t max_ea = inf_get_max_ea();

        while (ea < max_ea && ea != BADADDR) {
            addrs.push_back(ea);
            ea = next_head(ea, max_ea);
        }
    }
};

inline const char* get_item_type_str(ea_t ea) {
    flags64_t f = get_flags(ea);
    if (is_code(f)) return "code";
    if (is_strlit(f)) return "string";
    if (is_struct(f)) return "struct";
    if (is_align(f)) return "align";
    if (is_data(f)) return "data";
    if (is_unknown(f)) return "unknown";
    return "other";
}

inline VTableDef define_heads() {
    return live_table("heads")
        .count([]() {
            HeadsIterator::rebuild();
            return HeadsIterator::get_addresses().size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& addrs = HeadsIterator::get_addresses();
            return i < addrs.size() ? addrs[i] : 0;
        })
        .column_int64("size", [](size_t i) -> int64_t {
            auto& addrs = HeadsIterator::get_addresses();
            if (i >= addrs.size()) return 0;
            return get_item_size(addrs[i]);
        })
        .column_text("type", [](size_t i) -> std::string {
            auto& addrs = HeadsIterator::get_addresses();
            if (i >= addrs.size()) return "";
            return get_item_type_str(addrs[i]);
        })
        .column_int64("flags", [](size_t i) -> int64_t {
            auto& addrs = HeadsIterator::get_addresses();
            if (i >= addrs.size()) return 0;
            return get_flags(addrs[i]);
        })
        .column_text("disasm", [](size_t i) -> std::string {
            auto& addrs = HeadsIterator::get_addresses();
            if (i >= addrs.size()) return "";
            qstring line;
            generate_disasm_line(&line, addrs[i], GENDSM_FORCE_CODE);
            tag_remove(&line);
            return line.c_str();
        })
        .build();
}

// ============================================================================
// INSTRUCTIONS Table - Using filter_eq framework for constraint pushdown
// ============================================================================
//
// Supports constraint pushdown for func_addr:
//   SELECT * FROM instructions WHERE func_addr = 0x401000
//
// When func_addr constraint is detected, uses InstructionsInFuncIterator
// with func_item_iterator_t instead of scanning the entire database.
// ============================================================================

// Iterator for instructions within a single function (constraint pushdown)
class InstructionsInFuncIterator : public xsql::RowIterator {
    ea_t func_addr_;
    func_t* pfn_ = nullptr;
    func_item_iterator_t fii_;
    bool started_ = false;
    bool valid_ = false;
    ea_t current_ea_ = BADADDR;

public:
    explicit InstructionsInFuncIterator(ea_t func_addr)
        : func_addr_(func_addr)
    {
        pfn_ = get_func(func_addr_);
    }

    bool next() override {
        if (!pfn_) return false;

        if (!started_) {
            started_ = true;
            valid_ = fii_.set(pfn_);
            if (valid_) current_ea_ = fii_.current();
        } else if (valid_) {
            valid_ = fii_.next_code();
            if (valid_) current_ea_ = fii_.current();
        }
        return valid_;
    }

    bool eof() const override {
        return started_ && !valid_;
    }

    void column(sqlite3_context* ctx, int col) override {
        switch (col) {
            case 0: // address
                sqlite3_result_int64(ctx, current_ea_);
                break;
            case 1: { // itype
                insn_t insn;
                if (decode_insn(&insn, current_ea_) > 0) {
                    sqlite3_result_int(ctx, insn.itype);
                } else {
                    sqlite3_result_int(ctx, 0);
                }
                break;
            }
            case 2: { // mnemonic
                qstring mnem;
                print_insn_mnem(&mnem, current_ea_);
                sqlite3_result_text(ctx, mnem.c_str(), -1, SQLITE_TRANSIENT);
                break;
            }
            case 3: // size
                sqlite3_result_int(ctx, get_item_size(current_ea_));
                break;
            case 4: // operand0
            case 5: // operand1
            case 6: { // operand2
                qstring op;
                print_operand(&op, current_ea_, col - 4);
                tag_remove(&op);
                sqlite3_result_text(ctx, op.c_str(), -1, SQLITE_TRANSIENT);
                break;
            }
            case 7: { // disasm
                qstring line;
                generate_disasm_line(&line, current_ea_, 0);
                tag_remove(&line);
                sqlite3_result_text(ctx, line.c_str(), -1, SQLITE_TRANSIENT);
                break;
            }
            case 8: // func_addr
                sqlite3_result_int64(ctx, func_addr_);
                break;
        }
    }

    int64_t rowid() const override {
        return static_cast<int64_t>(current_ea_);
    }
};

// Cache for full instruction scan
struct InstructionsCache {
    static std::vector<ea_t>& get() {
        static std::vector<ea_t> cache;
        return cache;
    }

    static void rebuild() {
        auto& cache = get();
        cache.clear();

        ea_t ea = inf_get_min_ea();
        ea_t max_ea = inf_get_max_ea();

        while (ea < max_ea && ea != BADADDR) {
            flags64_t f = get_flags(ea);
            if (is_code(f)) {
                cache.push_back(ea);
            }
            ea = next_head(ea, max_ea);
        }
    }
};

inline VTableDef define_instructions() {
    return live_table("instructions")
        .count([]() {
            InstructionsCache::rebuild();
            return InstructionsCache::get().size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& cache = InstructionsCache::get();
            return i < cache.size() ? cache[i] : 0;
        })
        .column_int("itype", [](size_t i) -> int {
            auto& cache = InstructionsCache::get();
            if (i >= cache.size()) return 0;
            insn_t insn;
            if (decode_insn(&insn, cache[i]) > 0) return insn.itype;
            return 0;
        })
        .column_text("mnemonic", [](size_t i) -> std::string {
            auto& cache = InstructionsCache::get();
            if (i >= cache.size()) return "";
            qstring mnem;
            print_insn_mnem(&mnem, cache[i]);
            return mnem.c_str();
        })
        .column_int("size", [](size_t i) -> int {
            auto& cache = InstructionsCache::get();
            if (i >= cache.size()) return 0;
            return get_item_size(cache[i]);
        })
        .column_text("operand0", [](size_t i) -> std::string {
            auto& cache = InstructionsCache::get();
            if (i >= cache.size()) return "";
            qstring op;
            print_operand(&op, cache[i], 0);
            tag_remove(&op);
            return op.c_str();
        })
        .column_text("operand1", [](size_t i) -> std::string {
            auto& cache = InstructionsCache::get();
            if (i >= cache.size()) return "";
            qstring op;
            print_operand(&op, cache[i], 1);
            tag_remove(&op);
            return op.c_str();
        })
        .column_text("operand2", [](size_t i) -> std::string {
            auto& cache = InstructionsCache::get();
            if (i >= cache.size()) return "";
            qstring op;
            print_operand(&op, cache[i], 2);
            tag_remove(&op);
            return op.c_str();
        })
        .column_text("disasm", [](size_t i) -> std::string {
            auto& cache = InstructionsCache::get();
            if (i >= cache.size()) return "";
            qstring line;
            generate_disasm_line(&line, cache[i], 0);
            tag_remove(&line);
            return line.c_str();
        })
        .column_int64("func_addr", [](size_t i) -> int64_t {
            auto& cache = InstructionsCache::get();
            if (i >= cache.size()) return 0;
            func_t* f = get_func(cache[i]);
            return f ? f->start_ea : 0;
        })
        // Constraint pushdown: func_addr = X uses optimized iterator
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<InstructionsInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 100.0)
        .build();
}

// ============================================================================
// Live Entity Registry
// ============================================================================

struct LiveRegistry {
    VTableDef names_live;
    VTableDef comments_live;
    VTableDef funcs_live;
    VTableDef bookmarks;
    VTableDef heads;
    VTableDef instructions;

    LiveRegistry()
        : names_live(define_names_live())
        , comments_live(define_comments_live())
        , funcs_live(define_funcs_live())
        , bookmarks(define_bookmarks())
        , heads(define_heads())
        , instructions(define_instructions())
    {}

    void register_all(sqlite3* db) {
        register_vtable(db, "ida_names_live", &names_live);
        create_vtable(db, "names_live", "ida_names_live");

        register_vtable(db, "ida_comments_live", &comments_live);
        create_vtable(db, "comments_live", "ida_comments_live");

        register_vtable(db, "ida_funcs_live", &funcs_live);
        create_vtable(db, "funcs_live", "ida_funcs_live");

        register_vtable(db, "ida_bookmarks", &bookmarks);
        create_vtable(db, "bookmarks", "ida_bookmarks");

        register_vtable(db, "ida_heads", &heads);
        create_vtable(db, "heads", "ida_heads");

        register_vtable(db, "ida_instructions", &instructions);
        create_vtable(db, "instructions", "ida_instructions");
    }
};

} // namespace live
} // namespace idasql
