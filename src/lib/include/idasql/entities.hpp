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
// FUNCS Table
// ============================================================================

inline VTableDef define_funcs() {
    return table("funcs")
        .count([]() { return get_func_qty(); })
        .column_int64("address", [](size_t i) -> int64_t {
            func_t* f = getn_func(i);
            return f ? static_cast<int64_t>(f->start_ea) : 0;
        })
        .column_text("name", [](size_t i) -> std::string {
            func_t* f = getn_func(i);
            return f ? safe_func_name(f->start_ea) : "";
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
// NAMES Table (from nlist)
// ============================================================================

inline VTableDef define_names() {
    return table("names")
        .count([]() { return get_nlist_size(); })
        .column_int64("address", [](size_t i) -> int64_t {
            return static_cast<int64_t>(get_nlist_ea(i));
        })
        .column_text("name", [](size_t i) -> std::string {
            const char* n = get_nlist_name(i);
            return n ? std::string(n) : "";
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
// IMPORTS Table
// Collects all imports across all modules into a flat table
// ============================================================================

struct ImportInfo {
    int module_idx;
    ea_t ea;
    std::string name;
    uval_t ord;
};

// Global import cache (rebuilt on filter)
inline std::vector<ImportInfo>& get_import_cache() {
    static std::vector<ImportInfo> cache;
    return cache;
}

inline void rebuild_import_cache() {
    auto& cache = get_import_cache();
    cache.clear();

    uint mod_qty = get_import_module_qty();
    for (uint m = 0; m < mod_qty; m++) {
        enum_import_names(m, [](ea_t ea, const char* name, uval_t ord, void* param) -> int {
            int mod_idx = *static_cast<int*>(param);
            ImportInfo info;
            info.module_idx = mod_idx;
            info.ea = ea;
            info.name = name ? name : "";
            info.ord = ord;
            get_import_cache().push_back(info);
            return 1;  // continue enumeration
        }, &m);
    }
}

inline std::string get_import_module_name_safe(int idx) {
    qstring name;
    get_import_module_name(&name, idx);
    return std::string(name.c_str());
}

inline VTableDef define_imports() {
    // Build cache initially
    rebuild_import_cache();

    return table("imports")
        .count([]() {
            rebuild_import_cache();  // Refresh on each scan
            return get_import_cache().size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& cache = get_import_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].ea) : 0;
        })
        .column_text("name", [](size_t i) -> std::string {
            auto& cache = get_import_cache();
            return i < cache.size() ? cache[i].name : "";
        })
        .column_int64("ordinal", [](size_t i) -> int64_t {
            auto& cache = get_import_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].ord) : 0;
        })
        .column_text("module", [](size_t i) -> std::string {
            auto& cache = get_import_cache();
            if (i >= cache.size()) return "";
            return get_import_module_name_safe(cache[i].module_idx);
        })
        .column_int("module_idx", [](size_t i) -> int {
            auto& cache = get_import_cache();
            return i < cache.size() ? cache[i].module_idx : -1;
        })
        .build();
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

// All strings cache
inline std::vector<string_info_t>& get_strings_cache() {
    static std::vector<string_info_t> cache;
    return cache;
}

inline void rebuild_strings_cache() {
    auto& cache = get_strings_cache();
    cache.clear();

    size_t n = get_strlist_qty();
    for (size_t i = 0; i < n; i++) {
        string_info_t si;
        if (get_strlist_item(&si, i)) {
            cache.push_back(si);
        }
    }
}

inline std::string get_string_content(const string_info_t& si) {
    qstring content;
    get_strlit_contents(&content, si.ea, si.length, si.type);
    return std::string(content.c_str());
}

// Main strings table with type information
inline VTableDef define_strings() {
    rebuild_strings_cache();

    return table("strings")
        .count([]() {
            rebuild_strings_cache();
            return get_strings_cache().size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& cache = get_strings_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].ea) : 0;
        })
        .column_int("length", [](size_t i) -> int {
            auto& cache = get_strings_cache();
            return i < cache.size() ? static_cast<int>(cache[i].length) : 0;
        })
        .column_int("type", [](size_t i) -> int {
            auto& cache = get_strings_cache();
            return i < cache.size() ? static_cast<int>(cache[i].type) : 0;
        })
        .column_text("type_name", [](size_t i) -> std::string {
            auto& cache = get_strings_cache();
            if (i >= cache.size()) return "";
            return get_string_type_name(cache[i].type);
        })
        .column_int("width", [](size_t i) -> int {
            auto& cache = get_strings_cache();
            if (i >= cache.size()) return 0;
            return get_string_width(cache[i].type);
        })
        .column_text("content", [](size_t i) -> std::string {
            auto& cache = get_strings_cache();
            return i < cache.size() ? get_string_content(cache[i]) : "";
        })
        .build();
}

// ASCII strings only (width == 0)
inline std::vector<string_info_t>& get_ascii_strings_cache() {
    static std::vector<string_info_t> cache;
    return cache;
}

inline void rebuild_ascii_strings_cache() {
    auto& cache = get_ascii_strings_cache();
    cache.clear();

    size_t n = get_strlist_qty();
    for (size_t i = 0; i < n; i++) {
        string_info_t si;
        if (get_strlist_item(&si, i)) {
            if (get_string_width(si.type) == 0) {
                cache.push_back(si);
            }
        }
    }
}

inline VTableDef define_strings_ascii() {
    rebuild_ascii_strings_cache();

    return table("strings_ascii")
        .count([]() {
            rebuild_ascii_strings_cache();
            return get_ascii_strings_cache().size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& cache = get_ascii_strings_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].ea) : 0;
        })
        .column_int("length", [](size_t i) -> int {
            auto& cache = get_ascii_strings_cache();
            return i < cache.size() ? static_cast<int>(cache[i].length) : 0;
        })
        .column_text("content", [](size_t i) -> std::string {
            auto& cache = get_ascii_strings_cache();
            return i < cache.size() ? get_string_content(cache[i]) : "";
        })
        .build();
}

// Unicode strings only (width > 0: UTF-16 or UTF-32)
inline std::vector<string_info_t>& get_unicode_strings_cache() {
    static std::vector<string_info_t> cache;
    return cache;
}

inline void rebuild_unicode_strings_cache() {
    auto& cache = get_unicode_strings_cache();
    cache.clear();

    size_t n = get_strlist_qty();
    for (size_t i = 0; i < n; i++) {
        string_info_t si;
        if (get_strlist_item(&si, i)) {
            if (get_string_width(si.type) > 0) {  // UTF-16 or UTF-32
                cache.push_back(si);
            }
        }
    }
}

inline VTableDef define_strings_unicode() {
    rebuild_unicode_strings_cache();

    return table("strings_unicode")
        .count([]() {
            rebuild_unicode_strings_cache();
            return get_unicode_strings_cache().size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& cache = get_unicode_strings_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].ea) : 0;
        })
        .column_int("length", [](size_t i) -> int {
            auto& cache = get_unicode_strings_cache();
            return i < cache.size() ? static_cast<int>(cache[i].length) : 0;
        })
        .column_text("type_name", [](size_t i) -> std::string {
            auto& cache = get_unicode_strings_cache();
            if (i >= cache.size()) return "";
            return get_string_type_name(cache[i].type);
        })
        .column_text("content", [](size_t i) -> std::string {
            auto& cache = get_unicode_strings_cache();
            return i < cache.size() ? get_string_content(cache[i]) : "";
        })
        .build();
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

inline std::vector<XrefInfo>& get_xrefs_cache() {
    static std::vector<XrefInfo> cache;
    return cache;
}

inline void rebuild_xrefs_cache() {
    auto& cache = get_xrefs_cache();
    cache.clear();

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
}

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

inline VTableDef define_xrefs() {
    rebuild_xrefs_cache();

    return table("xrefs")
        .count([]() {
            rebuild_xrefs_cache();
            return get_xrefs_cache().size();
        })
        .column_int64("from_ea", [](size_t i) -> int64_t {
            auto& cache = get_xrefs_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].from_ea) : 0;
        })
        .column_int64("to_ea", [](size_t i) -> int64_t {
            auto& cache = get_xrefs_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].to_ea) : 0;
        })
        .column_int("type", [](size_t i) -> int {
            auto& cache = get_xrefs_cache();
            return i < cache.size() ? static_cast<int>(cache[i].type) : 0;
        })
        .column_int("is_code", [](size_t i) -> int {
            auto& cache = get_xrefs_cache();
            return i < cache.size() ? (cache[i].is_code ? 1 : 0) : 0;
        })
        // Constraint pushdown filters
        .filter_eq("to_ea", [](int64_t target) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<XrefsToIterator>(static_cast<ea_t>(target));
        }, 10.0, 5.0)  // Cost: 10, Est rows: 5
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

inline std::vector<BlockInfo>& get_blocks_cache() {
    static std::vector<BlockInfo> cache;
    return cache;
}

inline void rebuild_blocks_cache() {
    auto& cache = get_blocks_cache();
    cache.clear();

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
}

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

inline VTableDef define_blocks() {
    rebuild_blocks_cache();

    return table("blocks")
        .count([]() {
            rebuild_blocks_cache();
            return get_blocks_cache().size();
        })
        .column_int64("func_ea", [](size_t i) -> int64_t {
            auto& cache = get_blocks_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].func_ea) : 0;
        })
        .column_int64("start_ea", [](size_t i) -> int64_t {
            auto& cache = get_blocks_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].start_ea) : 0;
        })
        .column_int64("end_ea", [](size_t i) -> int64_t {
            auto& cache = get_blocks_cache();
            return i < cache.size() ? static_cast<int64_t>(cache[i].end_ea) : 0;
        })
        .column_int64("size", [](size_t i) -> int64_t {
            auto& cache = get_blocks_cache();
            if (i >= cache.size()) return 0;
            return static_cast<int64_t>(cache[i].end_ea - cache[i].start_ea);
        })
        // Constraint pushdown filter
        .filter_eq("func_ea", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<BlocksInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 10.0, 10.0)  // Cost: 10, Est rows: 10 blocks per function
        .build();
}

// ============================================================================
// Registry: All tables in one place
// ============================================================================

struct TableRegistry {
    VTableDef funcs;
    VTableDef segments;
    VTableDef names;
    VTableDef entries;
    VTableDef imports;
    VTableDef strings;
    VTableDef strings_ascii;
    VTableDef strings_unicode;
    VTableDef xrefs;
    VTableDef blocks;

    TableRegistry()
        : funcs(define_funcs())
        , segments(define_segments())
        , names(define_names())
        , entries(define_entries())
        , imports(define_imports())
        , strings(define_strings())
        , strings_ascii(define_strings_ascii())
        , strings_unicode(define_strings_unicode())
        , xrefs(define_xrefs())
        , blocks(define_blocks())
    {}

    void register_all(sqlite3* db) {
        register_and_create(db, "funcs", &funcs);
        register_and_create(db, "segments", &segments);
        register_and_create(db, "names", &names);
        register_and_create(db, "entries", &entries);
        register_and_create(db, "imports", &imports);
        register_and_create(db, "strings", &strings);
        register_and_create(db, "strings_ascii", &strings_ascii);
        register_and_create(db, "strings_unicode", &strings_unicode);
        register_and_create(db, "xrefs", &xrefs);
        register_and_create(db, "blocks", &blocks);
    }

private:
    void register_and_create(sqlite3* db, const char* name, const VTableDef* def) {
        std::string module_name = std::string("ida_") + name;
        register_vtable(db, module_name.c_str(), def);
        create_vtable(db, name, module_name.c_str());
    }
};

} // namespace entities
} // namespace idasql
