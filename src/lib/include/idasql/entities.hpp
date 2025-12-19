/**
 * ida_entities.hpp - IDA entity definitions for SQLite virtual tables
 *
 * Defines all IDA entities as virtual tables using the clean ida_vtable.hpp framework.
 *
 * Tables:
 *   funcs      - Functions
 *   segments   - Memory segments
 *   names      - Named locations (from nlist)
 *   entries    - Entry points (exports)
 *   imports    - Imported functions
 *   strings    - String literals
 *   xrefs      - Cross-references (universal)
 */

#pragma once

#include <idasql/vtable.hpp>
#include <idasql/entities_search.hpp>

// IDA SDK headers
#include <ida.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <entry.hpp>
#include <nalt.hpp>
#include <xref.hpp>
#include <strlist.hpp>
#include <gdl.hpp>
#include <bytes.hpp>
#include <lines.hpp>  // For comments (get_cmt, set_cmt)

namespace idasql {
namespace entities {

// ============================================================================
// Helper: Safe string extraction from IDA
// ============================================================================

inline std::string safe_func_name(ea_t ea) {
    qstring name;
    get_func_name(&name, ea);
    return std::string(name.c_str());
}

inline std::string safe_segm_name(segment_t* seg) {
    if (!seg) return "";
    qstring name;
    get_segm_name(&name, seg);
    return std::string(name.c_str());
}

inline std::string safe_segm_class(segment_t* seg) {
    if (!seg) return "";
    qstring cls;
    get_segm_class(&cls, seg);
    return std::string(cls.c_str());
}

inline std::string safe_name(ea_t ea) {
    qstring name;
    get_name(&name, ea);
    return std::string(name.c_str());
}

inline std::string safe_entry_name(size_t idx) {
    uval_t ord = get_entry_ordinal(idx);
    qstring name;
    get_entry_name(&name, ord);
    return std::string(name.c_str());
}

// ============================================================================
// FUNCS Table (with UPDATE/DELETE support)
// ============================================================================

inline VTableDef define_funcs() {
    return table("funcs")
        .on_modify(ida_undo_hook)
        .count([]() { return get_func_qty(); })
        .column_int64("address", [](size_t i) -> int64_t {
            func_t* f = getn_func(i);
            return f ? static_cast<int64_t>(f->start_ea) : 0;
        })
        .column_text_rw("name",
            // Getter
            [](size_t i) -> std::string {
                func_t* f = getn_func(i);
                return f ? safe_func_name(f->start_ea) : "";
            },
            // Setter - rename function
            [](size_t i, const char* new_name) -> bool {
                func_t* f = getn_func(i);
                if (!f) return false;
                return set_name(f->start_ea, new_name, SN_CHECK) != 0;
            })
        .column_int64("size", [](size_t i) -> int64_t {
            func_t* f = getn_func(i);
            return f ? static_cast<int64_t>(f->size()) : 0;
        })
        .column_int64("end_ea", [](size_t i) -> int64_t {
            func_t* f = getn_func(i);
            return f ? static_cast<int64_t>(f->end_ea) : 0;
        })
        .column_int64("flags", [](size_t i) -> int64_t {
            func_t* f = getn_func(i);
            return f ? static_cast<int64_t>(f->flags) : 0;
        })
        .deletable([](size_t i) -> bool {
            func_t* f = getn_func(i);
            if (!f) return false;
            return del_func(f->start_ea);
        })
        .build();
}

// ============================================================================
// SEGMENTS Table
// ============================================================================

inline VTableDef define_segments() {
    return table("segments")
        .count([]() { return static_cast<size_t>(get_segm_qty()); })
        .column_int64("start_ea", [](size_t i) -> int64_t {
            segment_t* s = getnseg(static_cast<int>(i));
            return s ? static_cast<int64_t>(s->start_ea) : 0;
        })
        .column_int64("end_ea", [](size_t i) -> int64_t {
            segment_t* s = getnseg(static_cast<int>(i));
            return s ? static_cast<int64_t>(s->end_ea) : 0;
        })
        .column_text("name", [](size_t i) -> std::string {
            segment_t* s = getnseg(static_cast<int>(i));
            return safe_segm_name(s);
        })
        .column_text("class", [](size_t i) -> std::string {
            segment_t* s = getnseg(static_cast<int>(i));
            return safe_segm_class(s);
        })
        .column_int("perm", [](size_t i) -> int {
            segment_t* s = getnseg(static_cast<int>(i));
            return s ? s->perm : 0;
        })
        .build();
}

// ============================================================================
// NAMES Table (with UPDATE support)
// ============================================================================

inline VTableDef define_names() {
    return table("names")
        .on_modify(ida_undo_hook)
        .count([]() { return get_nlist_size(); })
        .column_int64("address", [](size_t i) -> int64_t {
            return static_cast<int64_t>(get_nlist_ea(i));
        })
        .column_text_rw("name",
            // Getter
            [](size_t i) -> std::string {
                const char* n = get_nlist_name(i);
                return n ? std::string(n) : "";
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
// ENTRIES Table (entry points / exports)
// ============================================================================

inline VTableDef define_entries() {
    return table("entries")
        .count([]() { return get_entry_qty(); })
        .column_int64("ordinal", [](size_t i) -> int64_t {
            return static_cast<int64_t>(get_entry_ordinal(i));
        })
        .column_int64("address", [](size_t i) -> int64_t {
            uval_t ord = get_entry_ordinal(i);
            return static_cast<int64_t>(get_entry(ord));
        })
        .column_text("name", [](size_t i) -> std::string {
            return safe_entry_name(i);
        })
        .build();
}

// ============================================================================
// COMMENTS Table (with UPDATE/DELETE support)
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

inline VTableDef define_comments() {
    return table("comments")
        .on_modify(ida_undo_hook)
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
// IMPORTS Table
// Collects all imports across all modules into a flat table
// ============================================================================

struct ImportInfo {
    int module_idx;
    ea_t ea;
    std::string name;
    uval_t ord;
};

inline std::string get_import_module_name_safe(int idx) {
    qstring name;
    get_import_module_name(&name, idx);
    return std::string(name.c_str());
}

// ============================================================================
// STRINGS Tables - By type (ASCII, Unicode)
// ============================================================================

// String type encoding (from ida_nalt):
// Bits 0-1: Width (0=1B/ASCII, 1=2B/UTF-16, 2=4B/UTF-32)
// Bits 2-7: Layout (0=TERMCHR, 1=PASCAL1, 2=PASCAL2, 3=PASCAL4)
// Bits 8-15: term1 (first termination character)
// Bits 16-23: term2 (second termination character)
// Bits 24-31: encoding index

inline int get_string_width(int strtype) {
    return strtype & 0x03;  // 0=ASCII, 1=UTF-16, 2=UTF-32
}

inline const char* get_string_type_name(int strtype) {
    int width = get_string_width(strtype);
    switch (width) {
        case 0: return "ascii";
        case 1: return "utf16";
        case 2: return "utf32";
        default: return "unknown";
    }
}

inline std::string get_string_content(const string_info_t& si) {
    qstring content;
    get_strlit_contents(&content, si.ea, si.length, si.type);
    return std::string(content.c_str());
}

// ============================================================================
// XREFS Table (universal cross-references)
// Collects all xrefs from all functions
// ============================================================================

struct XrefInfo {
    ea_t from_ea;
    ea_t to_ea;
    uint8_t type;
    bool is_code;
};

// ============================================================================
// Xref Iterators for Constraint Pushdown
// ============================================================================

/**
 * Iterator for xrefs TO a specific address.
 * Used when query has: WHERE to_ea = X
 * Uses xrefblk_t::first_to/next_to for O(refs_to_X) instead of O(all_xrefs)
 */
class XrefsToIterator : public xsql::RowIterator {
    ea_t target_;
    xrefblk_t xb_;
    bool started_ = false;
    bool valid_ = false;

public:
    explicit XrefsToIterator(ea_t target) : target_(target) {}

    bool next() override {
        if (!started_) {
            started_ = true;
            valid_ = xb_.first_to(target_, XREF_ALL);
        } else if (valid_) {
            valid_ = xb_.next_to();
        }
        return valid_;
    }

    bool eof() const override {
        return started_ && !valid_;
    }

    void column(sqlite3_context* ctx, int col) override {
        if (!valid_) {
            sqlite3_result_null(ctx);
            return;
        }
        switch (col) {
            case 0: sqlite3_result_int64(ctx, static_cast<int64_t>(xb_.from)); break;
            case 1: sqlite3_result_int64(ctx, static_cast<int64_t>(target_)); break;
            case 2: sqlite3_result_int(ctx, xb_.type); break;
            case 3: sqlite3_result_int(ctx, xb_.iscode ? 1 : 0); break;
            default: sqlite3_result_null(ctx); break;
        }
    }

    int64_t rowid() const override {
        return valid_ ? static_cast<int64_t>(xb_.from) : 0;
    }
};

/**
 * Iterator for xrefs FROM a specific address.
 * Used when query has: WHERE from_ea = X
 * Uses xrefblk_t::first_from/next_from for O(refs_from_X) instead of O(all_xrefs)
 */
class XrefsFromIterator : public xsql::RowIterator {
    ea_t source_;
    xrefblk_t xb_;
    bool started_ = false;
    bool valid_ = false;

public:
    explicit XrefsFromIterator(ea_t source) : source_(source) {}

    bool next() override {
        if (!started_) {
            started_ = true;
            valid_ = xb_.first_from(source_, XREF_ALL);
        } else if (valid_) {
            valid_ = xb_.next_from();
        }
        return valid_;
    }

    bool eof() const override {
        return started_ && !valid_;
    }

    void column(sqlite3_context* ctx, int col) override {
        if (!valid_) {
            sqlite3_result_null(ctx);
            return;
        }
        switch (col) {
            case 0: sqlite3_result_int64(ctx, static_cast<int64_t>(source_)); break;
            case 1: sqlite3_result_int64(ctx, static_cast<int64_t>(xb_.to)); break;
            case 2: sqlite3_result_int(ctx, xb_.type); break;
            case 3: sqlite3_result_int(ctx, xb_.iscode ? 1 : 0); break;
            default: sqlite3_result_null(ctx); break;
        }
    }

    int64_t rowid() const override {
        return valid_ ? static_cast<int64_t>(xb_.to) : 0;
    }
};

/**
 * Xrefs table with query-scoped cache.
 *
 * Features:
 * - Cache lives in cursor (freed when query completes)
 * - Lazy cache build (only if not using constraint pushdown)
 * - Row count estimation (no cache rebuild in xBestIndex)
 */
inline CachedTableDef<XrefInfo> define_xrefs() {
    return cached_table<XrefInfo>("xrefs")
        // Estimate row count without building cache
        .estimate_rows([]() -> size_t {
            // Heuristic: ~10 xrefs per function on average
            return get_func_qty() * 10;
        })
        // Cache builder (called lazily, only if pushdown doesn't handle query)
        .cache_builder([](std::vector<XrefInfo>& cache) {
            size_t func_qty = get_func_qty();
            for (size_t i = 0; i < func_qty; i++) {
                func_t* func = getn_func(i);
                if (!func) continue;

                // Xrefs TO this function
                xrefblk_t xb;
                for (bool ok = xb.first_to(func->start_ea, XREF_ALL); ok; ok = xb.next_to()) {
                    XrefInfo xi;
                    xi.from_ea = xb.from;
                    xi.to_ea = func->start_ea;
                    xi.type = xb.type;
                    xi.is_code = xb.iscode;
                    cache.push_back(xi);
                }
            }
        })
        // Column accessors take const XrefInfo& directly
        .column_int64("from_ea", [](const XrefInfo& r) -> int64_t {
            return static_cast<int64_t>(r.from_ea);
        })
        .column_int64("to_ea", [](const XrefInfo& r) -> int64_t {
            return static_cast<int64_t>(r.to_ea);
        })
        .column_int("type", [](const XrefInfo& r) -> int {
            return static_cast<int>(r.type);
        })
        .column_int("is_code", [](const XrefInfo& r) -> int {
            return r.is_code ? 1 : 0;
        })
        // Constraint pushdown filters (same iterators as V1)
        .filter_eq("to_ea", [](int64_t target) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<XrefsToIterator>(static_cast<ea_t>(target));
        }, 10.0, 5.0)
        .filter_eq("from_ea", [](int64_t source) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<XrefsFromIterator>(static_cast<ea_t>(source));
        }, 10.0, 5.0)
        .build();
}

// ============================================================================
// BLOCKS Table (basic blocks)
// ============================================================================

struct BlockInfo {
    ea_t func_ea;
    ea_t start_ea;
    ea_t end_ea;
};

/**
 * Iterator for blocks in a specific function.
 * Used when query has: WHERE func_ea = X
 * Uses qflow_chart_t on single function for O(func_blocks) instead of O(all_blocks)
 */
class BlocksInFuncIterator : public xsql::RowIterator {
    ea_t func_ea_;
    qflow_chart_t fc_;
    int idx_ = -1;
    bool valid_ = false;

public:
    explicit BlocksInFuncIterator(ea_t func_ea) : func_ea_(func_ea) {
        func_t* pfn = get_func(func_ea);
        if (pfn) {
            fc_.create("", pfn, pfn->start_ea, pfn->end_ea, FC_NOEXT);
        }
    }

    bool next() override {
        ++idx_;
        valid_ = (idx_ < fc_.size());
        return valid_;
    }

    bool eof() const override {
        return idx_ >= 0 && !valid_;
    }

    void column(sqlite3_context* ctx, int col) override {
        if (!valid_ || idx_ < 0 || idx_ >= fc_.size()) {
            sqlite3_result_null(ctx);
            return;
        }
        const qbasic_block_t& bb = fc_.blocks[idx_];
        switch (col) {
            case 0: sqlite3_result_int64(ctx, static_cast<int64_t>(func_ea_)); break;
            case 1: sqlite3_result_int64(ctx, static_cast<int64_t>(bb.start_ea)); break;
            case 2: sqlite3_result_int64(ctx, static_cast<int64_t>(bb.end_ea)); break;
            case 3: sqlite3_result_int64(ctx, static_cast<int64_t>(bb.end_ea - bb.start_ea)); break;
            default: sqlite3_result_null(ctx); break;
        }
    }

    int64_t rowid() const override {
        if (!valid_ || idx_ < 0 || idx_ >= fc_.size()) return 0;
        return static_cast<int64_t>(fc_.blocks[idx_].start_ea);
    }
};

inline CachedTableDef<BlockInfo> define_blocks() {
    return cached_table<BlockInfo>("blocks")
        .estimate_rows([]() -> size_t {
            // Heuristic: ~10 blocks per function
            return get_func_qty() * 10;
        })
        .cache_builder([](std::vector<BlockInfo>& cache) {
            size_t func_qty = get_func_qty();
            for (size_t i = 0; i < func_qty; i++) {
                func_t* func = getn_func(i);
                if (!func) continue;

                qflow_chart_t fc;
                fc.create("", func, func->start_ea, func->end_ea, FC_NOEXT);

                for (int j = 0; j < fc.size(); j++) {
                    const qbasic_block_t& bb = fc.blocks[j];
                    BlockInfo bi;
                    bi.func_ea = func->start_ea;
                    bi.start_ea = bb.start_ea;
                    bi.end_ea = bb.end_ea;
                    cache.push_back(bi);
                }
            }
        })
        .column_int64("func_ea", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_ea);
        })
        .column_int64("start_ea", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.start_ea);
        })
        .column_int64("end_ea", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.end_ea);
        })
        .column_int64("size", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.end_ea - r.start_ea);
        })
        .filter_eq("func_ea", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<BlocksInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 10.0, 10.0)
        .build();
}

// ============================================================================
// IMPORTS Table (query-scoped cache)
// ============================================================================

// Helper struct for import enumeration callback
struct ImportEnumContext {
    std::vector<ImportInfo>* cache;
    int module_idx;
};

inline CachedTableDef<ImportInfo> define_imports() {
    return cached_table<ImportInfo>("imports")
        .estimate_rows([]() -> size_t {
            // Estimate: ~100 imports per module
            return get_import_module_qty() * 100;
        })
        .cache_builder([](std::vector<ImportInfo>& cache) {
            uint mod_qty = get_import_module_qty();
            for (uint m = 0; m < mod_qty; m++) {
                ImportEnumContext ctx;
                ctx.cache = &cache;
                ctx.module_idx = static_cast<int>(m);

                enum_import_names(m, [](ea_t ea, const char* name, uval_t ord, void* param) -> int {
                    auto* ctx = static_cast<ImportEnumContext*>(param);
                    ImportInfo info;
                    info.module_idx = ctx->module_idx;
                    info.ea = ea;
                    info.name = name ? name : "";
                    info.ord = ord;
                    ctx->cache->push_back(info);
                    return 1;  // continue enumeration
                }, &ctx);
            }
        })
        .column_int64("address", [](const ImportInfo& r) -> int64_t {
            return static_cast<int64_t>(r.ea);
        })
        .column_text("name", [](const ImportInfo& r) -> std::string {
            return r.name;
        })
        .column_int64("ordinal", [](const ImportInfo& r) -> int64_t {
            return static_cast<int64_t>(r.ord);
        })
        .column_text("module", [](const ImportInfo& r) -> std::string {
            return get_import_module_name_safe(r.module_idx);
        })
        .column_int("module_idx", [](const ImportInfo& r) -> int {
            return r.module_idx;
        })
        .build();
}

// ============================================================================
// STRINGS Table (query-scoped cache)
// ============================================================================

inline CachedTableDef<string_info_t> define_strings() {
    return cached_table<string_info_t>("strings")
        .estimate_rows([]() -> size_t {
            return get_strlist_qty();
        })
        .cache_builder([](std::vector<string_info_t>& cache) {
            size_t n = get_strlist_qty();
            for (size_t i = 0; i < n; i++) {
                string_info_t si;
                if (get_strlist_item(&si, i)) {
                    cache.push_back(si);
                }
            }
        })
        .column_int64("address", [](const string_info_t& r) -> int64_t {
            return static_cast<int64_t>(r.ea);
        })
        .column_int("length", [](const string_info_t& r) -> int {
            return static_cast<int>(r.length);
        })
        .column_int("type", [](const string_info_t& r) -> int {
            return static_cast<int>(r.type);
        })
        .column_text("type_name", [](const string_info_t& r) -> std::string {
            return get_string_type_name(r.type);
        })
        .column_int("width", [](const string_info_t& r) -> int {
            return get_string_width(r.type);
        })
        .column_text("content", [](const string_info_t& r) -> std::string {
            return get_string_content(r);
        })
        .build();
}

// ============================================================================
// Registry: All tables in one place
// ============================================================================

struct TableRegistry {
    // Index-based tables (use IDA's indexed access, no cache needed)
    VTableDef funcs;
    VTableDef segments;
    VTableDef names;
    VTableDef entries;
    VTableDef comments;

    // Cached tables (query-scoped cache - memory freed after query)
    CachedTableDef<XrefInfo> xrefs;
    CachedTableDef<BlockInfo> blocks;
    CachedTableDef<ImportInfo> imports;
    CachedTableDef<string_info_t> strings;

    TableRegistry()
        : funcs(define_funcs())
        , segments(define_segments())
        , names(define_names())
        , entries(define_entries())
        , comments(define_comments())
        , xrefs(define_xrefs())
        , blocks(define_blocks())
        , imports(define_imports())
        , strings(define_strings())
    {}

    void register_all(sqlite3* db) {
        // Index-based tables (use IDA's indexed access)
        register_index_table(db, "funcs", &funcs);
        register_index_table(db, "segments", &segments);
        register_index_table(db, "names", &names);
        register_index_table(db, "entries", &entries);
        register_index_table(db, "comments", &comments);

        // Cached tables (query-scoped cache)
        register_cached_table(db, "xrefs", &xrefs);
        register_cached_table(db, "blocks", &blocks);
        register_cached_table(db, "imports", &imports);
        register_cached_table(db, "strings", &strings);

        // Table-valued function for entity search
        search::register_jump_entities(db);
    }

private:
    void register_index_table(sqlite3* db, const char* name, const VTableDef* def) {
        std::string module_name = std::string("ida_") + name;
        register_vtable(db, module_name.c_str(), def);
        create_vtable(db, name, module_name.c_str());
    }

    template<typename RowData>
    void register_cached_table(sqlite3* db, const char* name, const CachedTableDef<RowData>* def) {
        std::string module_name = std::string("ida_") + name;
        xsql::register_cached_vtable(db, module_name.c_str(), def);
        create_vtable(db, name, module_name.c_str());
    }
};

} // namespace entities
} // namespace idasql
