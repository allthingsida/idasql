/**
 * entities_ext.hpp - Additional IDA entities as virtual tables
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
 *   mappings       - Address mappings
 */

#pragma once

#include <idasql/platform.hpp>

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include <idasql/platform_undef.hpp>

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

inline void collect_fixups(std::vector<FixupEntry>& rows) {
    rows.clear();

    for (ea_t ea = get_first_fixup_ea(); ea != BADADDR; ea = get_next_fixup_ea(ea)) {
        FixupEntry entry;
        entry.ea = ea;
        if (get_fixup(&entry.data, ea)) {
            rows.push_back(entry);
        }
    }
}

inline CachedTableDef<FixupEntry> define_fixups() {
    return cached_table<FixupEntry>("fixups")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 512; })
        .cache_builder([](std::vector<FixupEntry>& rows) {
            collect_fixups(rows);
        })
        .column_int64("address", [](const FixupEntry& row) -> int64_t {
            return static_cast<int64_t>(row.ea);
        })
        .column_int64("target", [](const FixupEntry& row) -> int64_t {
            return static_cast<int64_t>(row.data.off);
        })
        .column_int("type", [](const FixupEntry& row) -> int {
            return row.data.get_type();
        })
        .column_int("flags", [](const FixupEntry& row) -> int {
            return row.data.get_flags();
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

inline void collect_problems(std::vector<ProblemEntry>& rows) {
    rows.clear();

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
            rows.push_back(entry);
        }
    }
}

inline CachedTableDef<ProblemEntry> define_problems() {
    return cached_table<ProblemEntry>("problems")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 512; })
        .cache_builder([](std::vector<ProblemEntry>& rows) {
            collect_problems(rows);
        })
        .column_int64("address", [](const ProblemEntry& row) -> int64_t {
            return static_cast<int64_t>(row.ea);
        })
        .column_int("type_id", [](const ProblemEntry& row) -> int {
            return row.type;
        })
        .column_text("type", [](const ProblemEntry& row) -> std::string {
            return row.type_name;
        })
        .column_text("description", [](const ProblemEntry& row) -> std::string {
            return row.description;
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

inline void collect_signatures(std::vector<SignatureEntry>& rows) {
    rows.clear();

    int qty = get_idasgn_qty();
    for (int i = 0; i < qty; ++i) {
        SignatureEntry entry;
        entry.index = i;

        qstring signame, optlibs;
        entry.state = get_idasgn_desc(&signame, &optlibs, i);
        entry.name = signame.c_str();
        entry.optlibs = optlibs.c_str();
        rows.push_back(entry);
    }
}

inline CachedTableDef<SignatureEntry> define_signatures() {
    return cached_table<SignatureEntry>("signatures")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 128; })
        .cache_builder([](std::vector<SignatureEntry>& rows) {
            collect_signatures(rows);
        })
        .column_int("index", [](const SignatureEntry& row) -> int {
            return row.index;
        })
        .column_text("name", [](const SignatureEntry& row) -> std::string {
            return row.name;
        })
        .column_text("optlibs", [](const SignatureEntry& row) -> std::string {
            return row.optlibs;
        })
        .column_int("state", [](const SignatureEntry& row) -> int {
            return row.state;
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

inline void collect_local_types(std::vector<LocalTypeEntry>& rows) {
    rows.clear();

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

        rows.push_back(entry);
        ++ord;
    }
}

inline CachedTableDef<LocalTypeEntry> define_local_types() {
    return cached_table<LocalTypeEntry>("local_types")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 256; })
        .cache_builder([](std::vector<LocalTypeEntry>& rows) {
            collect_local_types(rows);
        })
        .column_int("ordinal", [](const LocalTypeEntry& row) -> int {
            return static_cast<int>(row.ordinal);
        })
        .column_text("name", [](const LocalTypeEntry& row) -> std::string {
            return row.name;
        })
        .column_text("type", [](const LocalTypeEntry& row) -> std::string {
            return row.type_str;
        })
        .column_int("is_struct", [](const LocalTypeEntry& row) -> int {
            return row.is_struct ? 1 : 0;
        })
        .column_int("is_enum", [](const LocalTypeEntry& row) -> int {
            return row.is_enum ? 1 : 0;
        })
        .column_int("is_typedef", [](const LocalTypeEntry& row) -> int {
            return row.is_typedef ? 1 : 0;
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
    CachedTableDef<FixupEntry> fixups;
    VTableDef hidden_ranges;
    CachedTableDef<ProblemEntry> problems;
    VTableDef fchunks;
    CachedTableDef<SignatureEntry> signatures;
    CachedTableDef<LocalTypeEntry> local_types;
    VTableDef mappings;

    ExtendedRegistry()
        : fixups(define_fixups())
        , hidden_ranges(define_hidden_ranges())
        , problems(define_problems())
        , fchunks(define_fchunks())
        , signatures(define_signatures())
        , local_types(define_local_types())
        , mappings(define_mappings())
    {}

    void register_all(xsql::Database& db) {
        db.register_cached_table("ida_fixups", &fixups);
        db.create_table("fixups", "ida_fixups");

        db.register_table("ida_hidden_ranges", &hidden_ranges);
        db.create_table("hidden_ranges", "ida_hidden_ranges");

        db.register_cached_table("ida_problems", &problems);
        db.create_table("problems", "ida_problems");

        db.register_table("ida_fchunks", &fchunks);
        db.create_table("fchunks", "ida_fchunks");

        db.register_cached_table("ida_signatures", &signatures);
        db.create_table("signatures", "ida_signatures");

        db.register_cached_table("ida_local_types", &local_types);
        db.create_table("local_types", "ida_local_types");

        db.register_table("ida_mappings", &mappings);
        db.create_table("mappings", "ida_mappings");
    }
};

} // namespace extended
} // namespace idasql
