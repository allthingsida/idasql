/**
 * ida_entities_extended.hpp - Additional IDA entities as virtual tables
 *
 * This file provides additional virtual tables beyond the core entities.
 * These tables cover: fixups, hidden ranges, problems, function chunks,
 * signatures, local types, and more.
 *
 * Tables:
 *   fixups         - Relocation/fixup records
 *   hidden_ranges  - Collapsed/hidden regions
 *   problems       - Analysis problems
 *   fchunks        - Function chunks (tails)
 *   signatures     - Applied FLIRT signatures
 *   local_types    - Local type library entries
 *   comments       - Address comments (regular/repeatable)
 *   stack_vars     - Stack variables per function
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
#include <fixup.hpp>
#include <bytes.hpp>
#include <problems.hpp>
#include <funcs.hpp>
#include <typeinf.hpp>
#include <frame.hpp>
#include <name.hpp>
#include <lines.hpp>

namespace idasql {
namespace extended {

// ============================================================================
// FIXUPS Table - Relocation records
// ============================================================================

struct FixupEntry {
    ea_t ea;
    fixup_data_t data;
};

inline std::vector<FixupEntry>& get_fixups_cache() {
    static std::vector<FixupEntry> cache;
    return cache;
}

inline void rebuild_fixups_cache() {
    auto& cache = get_fixups_cache();
    cache.clear();

    for (ea_t ea = get_first_fixup_ea(); ea != BADADDR; ea = get_next_fixup_ea(ea)) {
        FixupEntry entry;
        entry.ea = ea;
        if (get_fixup(&entry.data, ea)) {
            cache.push_back(entry);
        }
    }
}

inline VTableDef define_fixups() {
    return table("fixups")
        .count([]() {
            rebuild_fixups_cache();
            return get_fixups_cache().size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& cache = get_fixups_cache();
            return i < cache.size() ? cache[i].ea : 0;
        })
        .column_int64("target", [](size_t i) -> int64_t {
            auto& cache = get_fixups_cache();
            return i < cache.size() ? cache[i].data.off : 0;
        })
        .column_int("type", [](size_t i) -> int {
            auto& cache = get_fixups_cache();
            return i < cache.size() ? cache[i].data.get_type() : 0;
        })
        .column_int("flags", [](size_t i) -> int {
            auto& cache = get_fixups_cache();
            return i < cache.size() ? cache[i].data.get_flags() : 0;
        })
        .build();
}

// ============================================================================
// HIDDEN_RANGES Table - Collapsed/hidden regions
// ============================================================================

inline VTableDef define_hidden_ranges() {
    return table("hidden_ranges")
        .count([]() {
            return static_cast<size_t>(get_hidden_range_qty());
        })
        .column_int64("start_ea", [](size_t i) -> int64_t {
            hidden_range_t* hr = getn_hidden_range(static_cast<int>(i));
            return hr ? hr->start_ea : 0;
        })
        .column_int64("end_ea", [](size_t i) -> int64_t {
            hidden_range_t* hr = getn_hidden_range(static_cast<int>(i));
            return hr ? hr->end_ea : 0;
        })
        .column_int64("size", [](size_t i) -> int64_t {
            hidden_range_t* hr = getn_hidden_range(static_cast<int>(i));
            return hr ? (hr->end_ea - hr->start_ea) : 0;
        })
        .column_text("description", [](size_t i) -> std::string {
            hidden_range_t* hr = getn_hidden_range(static_cast<int>(i));
            return hr && hr->description ? hr->description : "";
        })
        .column_text("header", [](size_t i) -> std::string {
            hidden_range_t* hr = getn_hidden_range(static_cast<int>(i));
            return hr && hr->header ? hr->header : "";
        })
        .column_text("footer", [](size_t i) -> std::string {
            hidden_range_t* hr = getn_hidden_range(static_cast<int>(i));
            return hr && hr->footer ? hr->footer : "";
        })
        .column_int("visible", [](size_t i) -> int {
            hidden_range_t* hr = getn_hidden_range(static_cast<int>(i));
            return hr ? hr->visible : 0;
        })
        .column_int("color", [](size_t i) -> int {
            hidden_range_t* hr = getn_hidden_range(static_cast<int>(i));
            return hr ? hr->color : 0;
        })
        .build();
}

// ============================================================================
// PROBLEMS Table - Analysis problems
// ============================================================================

struct ProblemEntry {
    ea_t ea;
    problist_id_t type;
    std::string description;
    std::string type_name;
};

inline std::vector<ProblemEntry>& get_problems_cache() {
    static std::vector<ProblemEntry> cache;
    return cache;
}

inline void rebuild_problems_cache() {
    auto& cache = get_problems_cache();
    cache.clear();

    // Iterate all problem types
    for (int t = PR_NOBASE; t < PR_END; ++t) {
        problist_id_t ptype = static_cast<problist_id_t>(t);
        const char* tname = get_problem_name(ptype, true);

        for (ea_t ea = get_problem(ptype, 0); ea != BADADDR; ea = get_problem(ptype, ea + 1)) {
            ProblemEntry entry;
            entry.ea = ea;
            entry.type = ptype;
            entry.type_name = tname ? tname : "";

            qstring desc;
            if (get_problem_desc(&desc, ptype, ea) > 0) {
                entry.description = desc.c_str();
            }
            cache.push_back(entry);
        }
    }
}

inline VTableDef define_problems() {
    return table("problems")
        .count([]() {
            rebuild_problems_cache();
            return get_problems_cache().size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& cache = get_problems_cache();
            return i < cache.size() ? cache[i].ea : 0;
        })
        .column_int("type_id", [](size_t i) -> int {
            auto& cache = get_problems_cache();
            return i < cache.size() ? cache[i].type : 0;
        })
        .column_text("type", [](size_t i) -> std::string {
            auto& cache = get_problems_cache();
            return i < cache.size() ? cache[i].type_name : "";
        })
        .column_text("description", [](size_t i) -> std::string {
            auto& cache = get_problems_cache();
            return i < cache.size() ? cache[i].description : "";
        })
        .build();
}

// ============================================================================
// FCHUNKS Table - Function chunks (tails)
// ============================================================================

inline VTableDef define_fchunks() {
    return table("fchunks")
        .count([]() {
            return get_fchunk_qty();
        })
        .column_int64("start_ea", [](size_t i) -> int64_t {
            func_t* chunk = getn_fchunk(i);
            return chunk ? chunk->start_ea : 0;
        })
        .column_int64("end_ea", [](size_t i) -> int64_t {
            func_t* chunk = getn_fchunk(i);
            return chunk ? chunk->end_ea : 0;
        })
        .column_int64("size", [](size_t i) -> int64_t {
            func_t* chunk = getn_fchunk(i);
            return chunk ? chunk->size() : 0;
        })
        .column_int64("owner", [](size_t i) -> int64_t {
            func_t* chunk = getn_fchunk(i);
            if (!chunk) return 0;
            // For tail chunks, find the owner
            func_t* owner = get_func(chunk->start_ea);
            return owner ? owner->start_ea : 0;
        })
        .column_int("flags", [](size_t i) -> int {
            func_t* chunk = getn_fchunk(i);
            return chunk ? chunk->flags : 0;
        })
        .column_int("is_tail", [](size_t i) -> int {
            func_t* chunk = getn_fchunk(i);
            // FUNC_TAIL indicates this is a tail/chunk of another function
            return chunk ? ((chunk->flags & FUNC_TAIL) ? 1 : 0) : 0;
        })
        .build();
}

// ============================================================================
// SIGNATURES Table - Applied FLIRT signatures
// ============================================================================

struct SignatureEntry {
    int index;
    std::string name;
    std::string optlibs;
    int32 state;
};

inline std::vector<SignatureEntry>& get_signatures_cache() {
    static std::vector<SignatureEntry> cache;
    return cache;
}

inline void rebuild_signatures_cache() {
    auto& cache = get_signatures_cache();
    cache.clear();

    int qty = get_idasgn_qty();
    for (int i = 0; i < qty; ++i) {
        SignatureEntry entry;
        entry.index = i;

        qstring signame, optlibs;
        entry.state = get_idasgn_desc(&signame, &optlibs, i);
        entry.name = signame.c_str();
        entry.optlibs = optlibs.c_str();
        cache.push_back(entry);
    }
}

inline VTableDef define_signatures() {
    return table("signatures")
        .count([]() {
            rebuild_signatures_cache();
            return get_signatures_cache().size();
        })
        .column_int("index", [](size_t i) -> int {
            auto& cache = get_signatures_cache();
            return i < cache.size() ? cache[i].index : 0;
        })
        .column_text("name", [](size_t i) -> std::string {
            auto& cache = get_signatures_cache();
            return i < cache.size() ? cache[i].name : "";
        })
        .column_text("optlibs", [](size_t i) -> std::string {
            auto& cache = get_signatures_cache();
            return i < cache.size() ? cache[i].optlibs : "";
        })
        .column_int("state", [](size_t i) -> int {
            auto& cache = get_signatures_cache();
            return i < cache.size() ? cache[i].state : 0;
        })
        .build();
}

// ============================================================================
// LOCAL_TYPES Table - Local type library entries
// ============================================================================

struct LocalTypeEntry {
    uint32_t ordinal;
    std::string name;
    std::string type_str;
    bool is_struct;
    bool is_enum;
    bool is_typedef;
};

inline std::vector<LocalTypeEntry>& get_local_types_cache() {
    static std::vector<LocalTypeEntry> cache;
    return cache;
}

inline void rebuild_local_types_cache() {
    auto& cache = get_local_types_cache();
    cache.clear();

    til_t* ti = get_idati();
    if (!ti) return;

    // Iterate numbered types
    uint32_t ord = 1;
    while (true) {
        const char* name = get_numbered_type_name(ti, ord);
        if (!name) break;

        LocalTypeEntry entry;
        entry.ordinal = ord;
        entry.name = name;

        tinfo_t tif;
        if (tif.get_numbered_type(ti, ord)) {
            qstring ts;
            tif.print(&ts);
            entry.type_str = ts.c_str();
            entry.is_struct = tif.is_struct() || tif.is_union();
            entry.is_enum = tif.is_enum();
            entry.is_typedef = tif.is_typedef();
        } else {
            entry.is_struct = false;
            entry.is_enum = false;
            entry.is_typedef = false;
        }

        cache.push_back(entry);
        ++ord;
    }
}

inline VTableDef define_local_types() {
    return table("local_types")
        .count([]() {
            rebuild_local_types_cache();
            return get_local_types_cache().size();
        })
        .column_int("ordinal", [](size_t i) -> int {
            auto& cache = get_local_types_cache();
            return i < cache.size() ? cache[i].ordinal : 0;
        })
        .column_text("name", [](size_t i) -> std::string {
            auto& cache = get_local_types_cache();
            return i < cache.size() ? cache[i].name : "";
        })
        .column_text("type", [](size_t i) -> std::string {
            auto& cache = get_local_types_cache();
            return i < cache.size() ? cache[i].type_str : "";
        })
        .column_int("is_struct", [](size_t i) -> int {
            auto& cache = get_local_types_cache();
            return i < cache.size() ? (cache[i].is_struct ? 1 : 0) : 0;
        })
        .column_int("is_enum", [](size_t i) -> int {
            auto& cache = get_local_types_cache();
            return i < cache.size() ? (cache[i].is_enum ? 1 : 0) : 0;
        })
        .column_int("is_typedef", [](size_t i) -> int {
            auto& cache = get_local_types_cache();
            return i < cache.size() ? (cache[i].is_typedef ? 1 : 0) : 0;
        })
        .build();
}

// ============================================================================
// COMMENTS Table - Address comments
// ============================================================================

struct CommentEntry {
    ea_t ea;
    std::string comment;
    std::string rpt_comment;
};

inline std::vector<CommentEntry>& get_comments_cache() {
    static std::vector<CommentEntry> cache;
    return cache;
}

inline void rebuild_comments_cache() {
    auto& cache = get_comments_cache();
    cache.clear();

    // Iterate all addresses that have flags
    ea_t ea = inf_get_min_ea();
    ea_t max_ea = inf_get_max_ea();

    while (ea < max_ea) {
        qstring cmt, rpt;
        ssize_t cmt_len = get_cmt(&cmt, ea, false);  // regular comment
        ssize_t rpt_len = get_cmt(&rpt, ea, true);   // repeatable comment

        if (cmt_len > 0 || rpt_len > 0) {
            CommentEntry entry;
            entry.ea = ea;
            entry.comment = cmt_len > 0 ? cmt.c_str() : "";
            entry.rpt_comment = rpt_len > 0 ? rpt.c_str() : "";
            cache.push_back(entry);
        }

        ea = next_head(ea, max_ea);
        if (ea == BADADDR) break;
    }
}

inline VTableDef define_comments() {
    return table("comments")
        .count([]() {
            rebuild_comments_cache();
            return get_comments_cache().size();
        })
        .column_int64("address", [](size_t i) -> int64_t {
            auto& cache = get_comments_cache();
            return i < cache.size() ? cache[i].ea : 0;
        })
        .column_text("comment", [](size_t i) -> std::string {
            auto& cache = get_comments_cache();
            return i < cache.size() ? cache[i].comment : "";
        })
        .column_text("rpt_comment", [](size_t i) -> std::string {
            auto& cache = get_comments_cache();
            return i < cache.size() ? cache[i].rpt_comment : "";
        })
        .column_int("has_regular", [](size_t i) -> int {
            auto& cache = get_comments_cache();
            return i < cache.size() ? (!cache[i].comment.empty() ? 1 : 0) : 0;
        })
        .column_int("has_repeatable", [](size_t i) -> int {
            auto& cache = get_comments_cache();
            return i < cache.size() ? (!cache[i].rpt_comment.empty() ? 1 : 0) : 0;
        })
        .build();
}

// ============================================================================
// MAPPINGS Table - Address mappings
// ============================================================================

inline VTableDef define_mappings() {
    return table("mappings")
        .count([]() {
            return get_mappings_qty();
        })
        .column_int64("from_ea", [](size_t i) -> int64_t {
            ea_t from, to;
            asize_t size;
            if (get_mapping(&from, &to, &size, i)) {
                return from;
            }
            return 0;
        })
        .column_int64("to_ea", [](size_t i) -> int64_t {
            ea_t from, to;
            asize_t size;
            if (get_mapping(&from, &to, &size, i)) {
                return to;
            }
            return 0;
        })
        .column_int64("size", [](size_t i) -> int64_t {
            ea_t from, to;
            asize_t size;
            if (get_mapping(&from, &to, &size, i)) {
                return size;
            }
            return 0;
        })
        .build();
}

// ============================================================================
// Extended Registry
// ============================================================================

struct ExtendedRegistry {
    VTableDef fixups;
    VTableDef hidden_ranges;
    VTableDef problems;
    VTableDef fchunks;
    VTableDef signatures;
    VTableDef local_types;
    VTableDef comments;
    VTableDef mappings;

    ExtendedRegistry()
        : fixups(define_fixups())
        , hidden_ranges(define_hidden_ranges())
        , problems(define_problems())
        , fchunks(define_fchunks())
        , signatures(define_signatures())
        , local_types(define_local_types())
        , comments(define_comments())
        , mappings(define_mappings())
    {}

    void register_all(xsql::Database& db) {
        db.register_table("ida_fixups", &fixups);
        db.create_table("fixups", "ida_fixups");

        db.register_table("ida_hidden_ranges", &hidden_ranges);
        db.create_table("hidden_ranges", "ida_hidden_ranges");

        db.register_table("ida_problems", &problems);
        db.create_table("problems", "ida_problems");

        db.register_table("ida_fchunks", &fchunks);
        db.create_table("fchunks", "ida_fchunks");

        db.register_table("ida_signatures", &signatures);
        db.create_table("signatures", "ida_signatures");

        db.register_table("ida_local_types", &local_types);
        db.create_table("local_types", "ida_local_types");

        db.register_table("ida_comments", &comments);
        db.create_table("comments", "ida_comments");

        db.register_table("ida_mappings", &mappings);
        db.create_table("mappings", "ida_mappings");
    }
};

} // namespace extended
} // namespace idasql
