// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "entities_ext.hpp"

#include "decompiler.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <optional>
#include <set>

namespace idasql {
namespace extended {

// ============================================================================
// Collection helpers
// ============================================================================

void collect_fixups(std::vector<FixupEntry>& rows) {
    rows.clear();

    for (ea_t ea = get_first_fixup_ea(); ea != BADADDR; ea = get_next_fixup_ea(ea)) {
        FixupEntry entry;
        entry.ea = ea;
        if (get_fixup(&entry.data, ea)) {
            rows.push_back(entry);
        }
    }
}

void collect_problems(std::vector<ProblemEntry>& rows) {
    rows.clear();

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

namespace {

std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::filesystem::path utf8_path(const std::string& s) {
    return std::filesystem::path(std::u8string(s.begin(), s.end()));
}

std::string path_utf8(const std::filesystem::path& p) {
    const std::u8string u = p.u8string();
    return std::string(u.begin(), u.end());
}

// A signature's library name, "" when IDA cannot find the file. The same lookup
// IDA uses when it applies the signature, but silent: no "could not find" box.
std::string signature_title(const std::string& name) {
    qstring title;
    if (get_idasgn_title(&title, name.c_str()) < 0)
        return {};
    return title.c_str();
}

bool has_directory(const std::string& name) {
    return name.find_first_of("/\\") != std::string::npos;
}

// The file name without its directory and a ".sig" extension, lowercased.
std::string signature_stem(const std::string& name) {
    const size_t slash = name.find_last_of("/\\");
    std::string base = lower_copy(slash == std::string::npos ? name : name.substr(slash + 1));
    if (base.size() > 4 && base.compare(base.size() - 4, 4, ".sig") == 0)
        base.resize(base.size() - 4);
    return base;
}

// The list entry that is `name`, or -1. IDA stores what it was given, so the same
// signature can be listed as "vc64rtf", "vc64rtf.sig" or a path: two names are the
// same signature when equal, or when either is a bare short name with the same stem.
int find_signature(const std::string& name) {
    const std::string want = lower_copy(name);
    const std::string stem = signature_stem(name);
    const int qty = get_idasgn_qty();
    for (int i = 0; i < qty; ++i) {
        qstring listed;
        get_idasgn_desc(&listed, nullptr, i);
        const std::string have = listed.c_str();
        if (lower_copy(have) == want)
            return i;
        if ((!has_directory(have) || !has_directory(name)) && signature_stem(have) == stem)
            return i;
    }
    return -1;
}

// The processor id a signature file is for, from its header (the leading
// "IDASGN" magic, a version byte, then the processor id: idasgn_header_t).
// nullopt when the file cannot be read or is not a FLIRT signature file.
std::optional<int> signature_file_processor(const std::string& path) {
    FILE* fp = fopenRB(path.c_str());
    if (fp == nullptr)
        return std::nullopt;
    uchar head[8] = {};
    const ssize_t got = qfread(fp, head, sizeof(head));
    qfclose(fp);
    if (got != static_cast<ssize_t>(sizeof(head)) || std::memcmp(head, "IDASGN", 6) != 0)
        return std::nullopt;
    return head[7];
}

const char* state_text(int state) {
    switch (state) {
        case IDASGN_APPLIED: return "applied";
        case IDASGN_CURRENT: return "current";
        case IDASGN_PLANNED: return "planned";
        default:             return "unknown";
    }
}

bool refuse(const std::string& why) {
    xsql::set_vtab_error("signatures: " + why);
    return false;
}

// INSERT INTO signatures(name): plan the signature and let auto-analysis apply it.
// argv follows the column order: 0 idx, 1 name, 2 title, 3 state, 4 matches, 5 optlibs.
bool insert_signature(int argc, xsql::FunctionArg* argv) {
    if (argc < 2 || argv[1].is_null() || argv[1].type() != SQLITE_TEXT)
        return refuse("INSERT needs a name: a short name (vc64rtf) or a .sig path");
    std::string name = argv[1].as_text();
    name.erase(0, name.find_first_not_of(" \t"));
    name.erase(name.find_last_not_of(" \t") + 1);
    if (name.empty())
        return refuse("INSERT needs a name: a short name (vc64rtf) or a .sig path");

    // A short name is only looked up in this processor's sig folders; a path can
    // name any file, so check what it is first.
    if (has_directory(name)) {
        if (!qfileexist(name.c_str()))
            return refuse("no signature file '" + name + "'");
        const std::optional<int> proc = signature_file_processor(name);
        if (!proc)
            return refuse("'" + name + "' is not a FLIRT signature file");
        if (*proc != PH.id)
            return refuse("'" + name + "' is for processor id " + std::to_string(*proc) +
                          "; this database's processor id is " + std::to_string(PH.id));
    }
    if (signature_title(name).empty())
        return refuse("no signature file '" + name + "' (searched IDAUSR, IDASGN and IDA's sig "
                      "folder for this processor; or give an absolute path)");
    if (const int n = find_signature(name); n >= 0) {
        qstring listed;
        get_idasgn_desc(&listed, nullptr, n);
        return refuse("'" + name + "' is already in the list (idx " + std::to_string(n) + ", " +
                      listed.c_str() + ", " + state_text(calc_idasgn_state(n)) + ")");
    }

    // A signature applies only with FLIRT on; turn it on for this one and put the
    // database's setting back afterwards.
    const bool flirt_was_on = inf_use_flirt();
    inf_set_use_flirt(true);
    const int qty = plan_to_apply_idasgn(name.c_str());
    if (qty > 0)
        idasql_auto_wait();
    inf_set_use_flirt(flirt_was_on);
    if (qty <= 0)
        return refuse("IDA refused '" + name + "'");

    // Matched functions were renamed: cached decompilations of their callers are stale.
    if (decompiler::hexrays_available())
        clear_cached_cfuncs();
    return true;
}

// DELETE: a planned signature leaves the list. An applied one cannot be undone by
// IDA, which keeps no record of what it changed.
bool delete_signature(SignatureEntry& row) {
    // Indexes shift when an entry is removed: find the row again by its name.
    const int n = find_signature(row.name);
    if (n < 0)
        return refuse("'" + row.name + "' is no longer in the list");
    const int state = calc_idasgn_state(n);
    if (state == IDASGN_APPLIED || state == IDASGN_CURRENT)
        return refuse("'" + row.name + "' is " + state_text(state) + " and IDA cannot unapply a "
                      "signature; create a checkpoint before applying (INSERT INTO checkpoints) "
                      "and roll back with UPDATE checkpoints");
    if (del_idasgn(n) != IDASGN_OK)
        return refuse("IDA refused to remove '" + row.name + "'");
    return true;
}

}  // namespace

void collect_signatures(std::vector<SignatureEntry>& rows) {
    rows.clear();

    const int qty = get_idasgn_qty();
    for (int i = 0; i < qty; ++i) {
        SignatureEntry entry;
        entry.index = i;

        qstring signame, optlibs;
        entry.matches = get_idasgn_desc(&signame, &optlibs, i);
        entry.name = signame.c_str();
        entry.optlibs = optlibs.c_str();
        entry.state = calc_idasgn_state(i);
        entry.title = signature_title(entry.name);
        rows.push_back(entry);
    }
}

void collect_available_signatures(std::vector<AvailableSignature>& rows) {
    rows.clear();

    // IDA's own search order: each IDAUSR directory, $IDASGN, then IDA's directory,
    // each with sig/<processor>. The first file of a name is the one IDA uses.
    qstrvec_t dirs;
    get_ida_subdirs(&dirs, "sig", IDA_SUBDIR_IDP);
    const std::string idadir_lower =
        lower_copy(path_utf8(utf8_path(idadir(nullptr)).lexically_normal()));
    qstring idasgn_env;
    const std::string idasgn_lower =
        qgetenv("IDASGN", &idasgn_env)
            ? lower_copy(path_utf8(utf8_path(idasgn_env.c_str()).lexically_normal()))
            : std::string();

    std::vector<std::string> listed;
    for (int i = 0, qty = get_idasgn_qty(); i < qty; ++i) {
        qstring name;
        get_idasgn_desc(&name, nullptr, i);
        listed.push_back(name.c_str());
    }

    std::set<std::string> seen;
    for (const qstring& dir : dirs) {
        const std::filesystem::path dpath = utf8_path(dir.c_str());
        std::error_code ec;
        if (!std::filesystem::is_directory(dpath, ec))
            continue;
        const std::string dlower = lower_copy(path_utf8(dpath.lexically_normal()));
        const char* source = !idasgn_lower.empty() && dlower.rfind(idasgn_lower, 0) == 0 ? "idasgn"
                           : dlower.rfind(idadir_lower, 0) == 0                          ? "idadir"
                                                                                          : "idausr";
        std::vector<std::filesystem::path> files;
        for (std::filesystem::directory_iterator it(dpath, ec), end; !ec && it != end; it.increment(ec)) {
            std::error_code fec;
            if (it->is_regular_file(fec) && lower_copy(path_utf8(it->path().extension())) == ".sig")
                files.push_back(it->path());
        }
        std::sort(files.begin(), files.end());
        for (const auto& file : files) {
            AvailableSignature row;
            row.name = path_utf8(file.stem());
            if (!seen.insert(lower_copy(row.name)).second)
                continue;
            row.path = path_utf8(file);
            row.source = source;
            row.title = signature_title(row.path);
#if IDASQL_HAS_IDASGN_HEADER
            idasgn_header_t header{};
            qstring libname;
            if (get_idasgn_header_by_short_name(&header, &libname, row.name.c_str())) {
                row.is_startup = (header.flags & LS_STARTUP) != 0 ? 1 : 0;
                row.modules = header.number_of_modules;
            }
#endif
            const std::string stem = lower_copy(row.name);
            row.in_list = std::any_of(listed.begin(), listed.end(), [&](const std::string& l) {
                return signature_stem(l) == stem;
            });
            rows.push_back(std::move(row));
        }
    }
}

void collect_local_types(std::vector<LocalTypeEntry>& rows) {
    rows.clear();

    til_t* ti = get_idati();
    if (!ti) return;

    // Valid local-type ordinals are 1..get_ordinal_limit(ti)-1; skip gaps (deleted types)
    // rather than stopping at the first one.
    uint32 limit = get_ordinal_limit(ti);
    for (uint32 ord = 1; ord < limit; ++ord) {
        const char* name = get_numbered_type_name(ti, ord);
        if (!name) continue;

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
    }
}

// ============================================================================
// Table definitions
// ============================================================================

CachedTableDef<FixupEntry> define_fixups() {
    return cached_table<FixupEntry>("fixups")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 512; })
        .cache_builder([](std::vector<FixupEntry>& rows) {
            collect_fixups(rows);
        })
        .column_int64("addr", [](const FixupEntry& row) -> int64_t {
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

VTableDef define_hidden_ranges() {
    return table("hidden_ranges")
        .row_count([]() {
            return static_cast<size_t>(get_hidden_range_qty());
        })
        .column_int64("start_addr", [](size_t i) -> int64_t {
            idasql_hidden_range_t hr;
            return idasql_hidden_range_by_num(static_cast<int>(i), &hr) ? hr.start_ea : 0;
        })
        .column_int64("end_addr", [](size_t i) -> int64_t {
            idasql_hidden_range_t hr;
            return idasql_hidden_range_by_num(static_cast<int>(i), &hr) ? hr.end_ea : 0;
        })
        .column_int64("size", [](size_t i) -> int64_t {
            idasql_hidden_range_t hr;
            return idasql_hidden_range_by_num(static_cast<int>(i), &hr) ? (hr.end_ea - hr.start_ea) : 0;
        })
        .column_text("description", [](size_t i) -> std::string {
            idasql_hidden_range_t hr;
            return idasql_hidden_range_by_num(static_cast<int>(i), &hr) ? hr.description.c_str() : "";
        })
        .column_text("header", [](size_t i) -> std::string {
            idasql_hidden_range_t hr;
            return idasql_hidden_range_by_num(static_cast<int>(i), &hr) ? hr.header.c_str() : "";
        })
        .column_text("footer", [](size_t i) -> std::string {
            idasql_hidden_range_t hr;
            return idasql_hidden_range_by_num(static_cast<int>(i), &hr) ? hr.footer.c_str() : "";
        })
        .column_int("visible", [](size_t i) -> int {
            idasql_hidden_range_t hr;
            return idasql_hidden_range_by_num(static_cast<int>(i), &hr) ? hr.visible : 0;
        })
        .column_int("color", [](size_t i) -> int {
            idasql_hidden_range_t hr;
            return idasql_hidden_range_by_num(static_cast<int>(i), &hr) ? hr.color : 0;
        })
        .build();
}

CachedTableDef<ProblemEntry> define_problems() {
    return cached_table<ProblemEntry>("problems")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 512; })
        .cache_builder([](std::vector<ProblemEntry>& rows) {
            collect_problems(rows);
        })
        .column_int64("addr", [](const ProblemEntry& row) -> int64_t {
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

// Chunk number `i` (0..get_fchunk_qty()-1); false for a bad `i`.
static bool fchunk_by_num(size_t i, idasql_fchunk_info_t* out) {
    const ea_t ea = idasql_fchunk_ea_by_num(static_cast<int>(i));
    return ea != BADADDR && idasql_fchunk_info(ea, out);
}

VTableDef define_fchunks() {
    return table("fchunks")
        .row_count([]() {
            return get_fchunk_qty();
        })
        .column_int64("start_addr", [](size_t i) -> int64_t {
            idasql_fchunk_info_t chunk;
            return fchunk_by_num(i, &chunk) ? chunk.start_ea : 0;
        })
        .column_int64("end_addr", [](size_t i) -> int64_t {
            idasql_fchunk_info_t chunk;
            return fchunk_by_num(i, &chunk) ? chunk.end_ea : 0;
        })
        .column_int64("size", [](size_t i) -> int64_t {
            idasql_fchunk_info_t chunk;
            return fchunk_by_num(i, &chunk) ? (chunk.end_ea - chunk.start_ea) : 0;
        })
        .column_int64("owner", [](size_t i) -> int64_t {
            idasql_fchunk_info_t chunk;
            if (!fchunk_by_num(i, &chunk)) return 0;
            const ea_t owner = idasql_func_start(chunk.start_ea);
            return owner != BADADDR ? owner : 0;
        })
        // The FUNC_* flags are 64-bit; an int column would truncate them.
        .column_int64("flags", [](size_t i) -> int64_t {
            idasql_fchunk_info_t chunk;
            return fchunk_by_num(i, &chunk) ? static_cast<int64_t>(chunk.flags) : 0;
        })
        .column_int("is_tail", [](size_t i) -> int {
            idasql_fchunk_info_t chunk;
            return fchunk_by_num(i, &chunk) ? (chunk.is_tail() ? 1 : 0) : 0;
        })
        .build();
}

CachedTableDef<SignatureEntry> define_signatures() {
    // Rebuilt for every query: the list is a few netnode reads, and IDA raises no
    // event when it changes (a GUI delete, a plan from a script).
    return cached_table<SignatureEntry>("signatures")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return static_cast<size_t>(std::max(get_idasgn_qty(), 1)); })
        .cache_builder([](std::vector<SignatureEntry>& rows) {
            collect_signatures(rows);
        })
        // "idx", not "index" (an SQL keyword): the position in IDA's list.
        .column_int("idx", [](const SignatureEntry& row) -> int {
            return row.index;
        })
        .column_text("name", [](const SignatureEntry& row) -> std::string {
            return row.name;
        })
        .column_text_nullable("title", [](const SignatureEntry& row) -> std::optional<std::string> {
            if (row.title.empty()) return std::nullopt;  // the file is gone
            return row.title;
        })
        .column_text("state", [](const SignatureEntry& row) -> std::string {
            return state_text(row.state);
        })
        .column_int("matches", [](const SignatureEntry& row) -> int {
            return row.matches;
        })
        .column_text("optlibs", [](const SignatureEntry& row) -> std::string {
            return row.optlibs;
        })
        .insertable(insert_signature)
        .deletable(delete_signature)
        .build();
}

CachedTableDef<AvailableSignature> define_available_signatures() {
    return cached_table<AvailableSignature>("available_signatures")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 256; })
        .cache_builder([](std::vector<AvailableSignature>& rows) {
            collect_available_signatures(rows);
        })
        .column_text("name", [](const AvailableSignature& row) -> std::string { return row.name; })
        .column_text_nullable("title", [](const AvailableSignature& row) -> std::optional<std::string> {
            if (row.title.empty()) return std::nullopt;
            return row.title;
        })
        .column_text("path", [](const AvailableSignature& row) -> std::string { return row.path; })
        .column_text("source", [](const AvailableSignature& row) -> std::string { return row.source; })
        // NULL where this SDK has no header reader (9.0 GA).
        .column_int_nullable("is_startup", [](const AvailableSignature& row) -> std::optional<int> {
            if (row.is_startup < 0) return std::nullopt;
            return row.is_startup;
        })
        .column_int_nullable("modules", [](const AvailableSignature& row) -> std::optional<int> {
            if (row.modules < 0) return std::nullopt;
            return static_cast<int>(row.modules);
        })
        .column_int("in_list", [](const AvailableSignature& row) -> int { return row.in_list ? 1 : 0; })
        .build();
}

CachedTableDef<LocalTypeEntry> define_local_types() {
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

VTableDef define_mappings() {
    return table("mappings")
        .row_count([]() {
            return get_mappings_qty();
        })
        .column_int64("from_addr", [](size_t i) -> int64_t {
            ea_t from, to;
            asize_t size;
            if (get_mapping(&from, &to, &size, i)) {
                return from;
            }
            return 0;
        })
        .column_int64("to_addr", [](size_t i) -> int64_t {
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
// Registry
// ============================================================================

ExtendedRegistry::ExtendedRegistry()
    : fixups(define_fixups())
    , hidden_ranges(define_hidden_ranges())
    , problems(define_problems())
    , fchunks(define_fchunks())
    , signatures(define_signatures())
    , available_signatures(define_available_signatures())
    , local_types(define_local_types())
    , mappings(define_mappings())
{}

void ExtendedRegistry::register_all(xsql::Database& db) {
    db.register_cached_table("fixups", &fixups);
    db.create_table("fixups", "fixups");

    db.register_table("hidden_ranges", &hidden_ranges);
    db.create_table("hidden_ranges", "hidden_ranges");

    db.register_cached_table("problems", &problems);
    db.create_table("problems", "problems");

    db.register_table("fchunks", &fchunks);
    db.create_table("fchunks", "fchunks");

    db.register_cached_table("signatures", &signatures);
    db.create_table("signatures", "signatures");

    db.register_cached_table("available_signatures", &available_signatures);
    db.create_table("available_signatures", "available_signatures");

    db.register_cached_table("local_types", &local_types);
    db.create_table("local_types", "local_types");

    db.register_table("mappings", &mappings);
    db.create_table("mappings", "mappings");
}

} // namespace extended
} // namespace idasql
