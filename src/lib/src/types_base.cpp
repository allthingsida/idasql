// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_base.hpp"

namespace idasql {
namespace types {

namespace {

// ---------------------------------------------------------------------------
// Shared single-type rendering (the expensive path)
// ---------------------------------------------------------------------------
//
// Filling a TypeEntry from an ordinal is cheap for identity (ordinal/name) but
// expensive for `definition` (tinfo_t::print renders the full C type). This is
// the one place that does the expensive render, reused by the full-scan builder
// (collect_types) and by the pushdown iterators so they render only the rows
// that survive a filter. Folder/full_path are NOT set here (the caller supplies
// them -- bulk via a prebuilt map, single-row via find_inode_path).
//
// Returns false for an ordinal gap (no named type at `ord`).
bool render_type_core(til_t* ti, uint32_t ord, TypeEntry& entry) {
    const char* name = get_numbered_type_name(ti, ord);
    if (!name) return false;  // gap in ordinal space

    entry.ordinal = ord;
    entry.name = name;

    tinfo_t tif;
    if (tif.get_numbered_type(ti, ord)) {
        entry.kind = get_type_kind(tif);
        entry.is_struct = tif.is_struct();
        entry.is_union = tif.is_union();
        entry.is_enum = tif.is_enum();
        entry.is_typedef = tif.is_typedef();
        entry.is_func = tif.is_func();
        entry.is_ptr = tif.is_ptr();
        entry.is_array = tif.is_array();

        size_t sz = tif.get_size();
        entry.size = (sz != BADSIZE) ? static_cast<int64_t>(sz) : -1;

        entry.alignment = 0;
        if (tif.is_struct() || tif.is_union()) {
            udt_type_data_t udt;
            if (tif.get_udt_details(&udt)) {
                entry.alignment = static_cast<int>(udt.effalign);
            }
        }
        entry.is_fixed = tif.is_fixed_struct();
        entry.is_bitmask = tif.is_bitmask_enum();

        // The expensive part: render the full definition.
        qstring def_str;
        tif.print(&def_str);
        entry.definition = def_str.c_str();

        if (tif.is_typedef()) {
            qstring res_name;
            if (tif.get_final_type_name(&res_name)) {
                entry.resolved = res_name.c_str();
            }
        }
    } else {
        entry.kind = "unknown";
        entry.size = -1;
        entry.alignment = 0;
        entry.is_struct = false;
        entry.is_union = false;
        entry.is_enum = false;
        entry.is_typedef = false;
        entry.is_func = false;
        entry.is_ptr = false;
        entry.is_array = false;
        entry.is_fixed = false;
        entry.is_bitmask = false;
    }
    return true;
}

// Single source of truth for emitting a TypeEntry's columns by index. MUST stay
// in lockstep with the column order declared in define_types(). The pushdown
// iterators below use this; a drift guard test compares pushed-down rows against
// the full-scan render to catch any divergence.
void emit_type_column(xsql::FunctionContext& ctx, const TypeEntry& e, int col) {
    switch (col) {
        case 0:  ctx.result_int(static_cast<int>(e.ordinal)); break;
        case 1:  ctx.result_text(e.name.c_str()); break;
        case 2:  ctx.result_text(e.kind.c_str()); break;
        case 3:  ctx.result_int64(e.size); break;
        case 4:  ctx.result_int(e.alignment); break;
        case 5:  ctx.result_int(e.is_struct ? 1 : 0); break;
        case 6:  ctx.result_int(e.is_union ? 1 : 0); break;
        case 7:  ctx.result_int(e.is_enum ? 1 : 0); break;
        case 8:  ctx.result_int(e.is_typedef ? 1 : 0); break;
        case 9:  ctx.result_int(e.is_func ? 1 : 0); break;
        case 10: ctx.result_int(e.is_ptr ? 1 : 0); break;
        case 11: ctx.result_int(e.is_array ? 1 : 0); break;
        case 12: ctx.result_text(e.definition.c_str()); break;
        case 13: ctx.result_text(e.resolved.c_str()); break;
        case 14: e.folder_path.empty() ? ctx.result_null()
                                       : ctx.result_text(e.folder_path.c_str()); break;
        case 15: ctx.result_text(e.full_path.c_str()); break;
        case 16: ctx.result_int(e.is_fixed ? 1 : 0); break;
        case 17: ctx.result_int(e.is_bitmask ? 1 : 0); break;
        default: ctx.result_null(); break;
    }
}

void fill_folder_path(uint32_t ord, TypeEntry& entry) {
    auto path = dirtrees::find_inode_path(DIRTREE_LOCAL_TYPES, static_cast<uint64_t>(ord));
    if (path) {
        entry.folder_path = path->folder_path;
        entry.full_path = path->full_path;
    }
}

inline char ascii_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// Extract the literal prefix of a LIKE pattern: the run of characters before the
// first wildcard (`%`/`_`) or escape (`\`). Stopping early always yields a valid
// SUPERSET prefix (correctness is guaranteed by SQLite re-applying the real LIKE,
// since the constraint is not omitted). An empty result means "match all".
std::string extract_like_prefix(const std::string& pattern) {
    std::string out;
    for (char c : pattern) {
        if (c == '%' || c == '_' || c == '\\') break;
        out.push_back(c);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Exact ordinal / name pushdown -- render exactly one type
// ---------------------------------------------------------------------------
class TypeByKeyIterator : public xsql::RowIterator {
public:
    explicit TypeByKeyIterator(uint32_t ordinal) {
        til_t* ti = get_idati();
        if (ti) resolve(ti, ordinal);
    }
    explicit TypeByKeyIterator(const std::string& name) {
        til_t* ti = get_idati();
        if (!ti || name.empty()) return;
        uint32 ord = get_type_ordinal(ti, name.c_str());  // O(1) hash lookup
        if (ord != 0) resolve(ti, ord);
    }

    bool next() override {
        if (has_row_ && !consumed_) {
            consumed_ = true;
            positioned_ = true;
            return true;
        }
        positioned_ = false;
        return false;
    }
    bool eof() const override { return !positioned_; }
    void column(xsql::FunctionContext& ctx, int col) override {
        if (!positioned_) { ctx.result_null(); return; }
        emit_type_column(ctx, entry_, col);
    }
    int64_t rowid() const override { return entry_.ordinal; }

private:
    void resolve(til_t* ti, uint32_t ord) {
        if (render_type_core(ti, ord, entry_)) {
            fill_folder_path(ord, entry_);
            has_row_ = true;
        }
    }
    TypeEntry entry_{};
    bool has_row_ = false;
    bool consumed_ = false;
    bool positioned_ = false;
};

// ---------------------------------------------------------------------------
// Prefix (LIKE 'prefix%') pushdown -- walk cheap names, render hits only
// ---------------------------------------------------------------------------
class TypePrefixIterator : public xsql::RowIterator {
public:
    explicit TypePrefixIterator(const std::string& pattern)
        : prefix_(extract_like_prefix(pattern)) {
        ti_ = get_idati();
        if (ti_) max_ord_ = get_ordinal_limit(ti_);
    }

    bool next() override {
        positioned_ = false;
        if (!ti_ || max_ord_ == 0 || max_ord_ == uint32_t(-1)) return false;

        uint32_t scanned = 0;
        for (uint32_t ord = cur_ord_; ord < max_ord_; ++ord) {
            if (((++scanned) & 1023u) == 0 && xsql::vtab_interrupted()) {
                xsql::set_vtab_error(
                    "query interrupted: timeout while scanning types by prefix");
                cur_ord_ = max_ord_;
                return false;
            }
            const char* name = get_numbered_type_name(ti_, ord);
            if (!name) continue;            // gap
            if (!prefix_matches(name)) continue;

            // Render only on a prefix hit -- this is the whole optimization.
            TypeEntry e{};
            if (!render_type_core(ti_, ord, e)) continue;
            fill_folder_path(ord, e);
            entry_ = std::move(e);
            cur_ord_ = ord + 1;
            positioned_ = true;
            return true;
        }
        cur_ord_ = max_ord_;
        return false;
    }
    bool eof() const override { return !positioned_; }
    void column(xsql::FunctionContext& ctx, int col) override {
        if (!positioned_) { ctx.result_null(); return; }
        emit_type_column(ctx, entry_, col);
    }
    int64_t rowid() const override { return entry_.ordinal; }

private:
    // Case-insensitive prefix compare -- a superset of LIKE's default
    // case-insensitivity (SQLite re-applies the exact pattern). Empty prefix
    // (leading-wildcard pattern) matches everything.
    bool prefix_matches(const char* name) const {
        for (size_t i = 0; i < prefix_.size(); ++i) {
            char c = name[i];
            if (c == '\0') return false;
            if (ascii_lower(c) != ascii_lower(prefix_[i])) return false;
        }
        return true;
    }

    std::string prefix_;
    til_t* ti_ = nullptr;
    uint32_t max_ord_ = 0;
    uint32_t cur_ord_ = 1;   // ordinals start at 1
    TypeEntry entry_{};
    bool positioned_ = false;
};

}  // namespace

void collect_types(std::vector<TypeEntry>& rows) {
    rows.clear();

    til_t* ti = get_idati();
    if (!ti) return;

    uint32_t max_ord = get_ordinal_limit(ti);
    if (max_ord == 0 || max_ord == uint32_t(-1)) return;

    auto folder_paths = dirtrees::collect_inode_paths(DIRTREE_LOCAL_TYPES);

    uint32_t scanned = 0;
    for (uint32_t ord = 1; ord < max_ord; ++ord) {
        // Cooperative cancellation -- a full type render can take tens of
        // seconds on a large IDB; the SQLite progress handler cannot interrupt
        // this C++ loop, so poll the query deadline and bail cleanly. The caller
        // clears the partially-built cache when a vtab error is set.
        if (((++scanned) & 1023u) == 0 && xsql::vtab_interrupted()) {
            xsql::set_vtab_error("query interrupted: timeout while building types");
            return;
        }

        TypeEntry entry;
        if (!render_type_core(ti, ord, entry)) continue;  // gap

        auto path_it = folder_paths.find(static_cast<uint64_t>(ord));
        if (path_it != folder_paths.end()) {
            entry.folder_path = path_it->second.folder_path;
            entry.full_path = path_it->second.full_path;
        }

        rows.push_back(std::move(entry));
    }
}

// ============================================================================
// TYPES Table - All local types (enhanced)
// ============================================================================

CachedTableDef<TypeEntry> define_types() {
    return cached_table<TypeEntry>("types")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            til_t* ti = get_idati();
            return ti ? static_cast<size_t>(get_ordinal_limit(ti)) : 0;
        })
        .cache_builder([](std::vector<TypeEntry>& rows) {
            collect_types(rows);
        })
        .column_int("ordinal", [](const TypeEntry& row) -> int {
            return static_cast<int>(row.ordinal);
        })
        .column_text_rw("name",
            [](const TypeEntry& row) -> std::string {
                return row.name;
            },
            [](TypeEntry& row, const char* new_name) -> bool {
                if (!new_name || !new_name[0]) {
                    xsql::set_vtab_error("types: name cannot be empty (ordinal=" + std::to_string(row.ordinal) + ")");
                    return false;
                }
                if (new_name == row.name) {
                    return true;
                }

                til_t* ti = get_idati();
                if (!ti) {
                    xsql::set_vtab_error("types: type library not available");
                    return false;
                }

                tinfo_t tif;
                if (!tif.get_numbered_type(ti, row.ordinal)) {
                    xsql::set_vtab_error("types: ordinal " + std::to_string(row.ordinal) + " not found");
                    return false;
                }

                bool ok = tif.rename_type(new_name) == TERR_OK;
                if (ok) row.name = new_name;
                else xsql::set_vtab_error("types: failed to rename ordinal " +
                                          std::to_string(row.ordinal) + " to '" + new_name + "'");
                return ok;
            })
        .column_text("kind", [](const TypeEntry& row) -> std::string {
            return row.kind;
        })
        // Writable size pins a FIXED struct's total size (set_struct_size).
        .column_int64_rw("size",
            [](const TypeEntry& row) -> int64_t {
                return row.size;
            },
            [](TypeEntry& row, int64_t new_size) -> bool {
                if (new_size < 0) {
                    xsql::set_vtab_error("types: size cannot be negative (ordinal=" +
                                          std::to_string(row.ordinal) + ")");
                    return false;
                }
                til_t* ti = get_idati();
                tinfo_t tif;
                if (!ti || !tif.get_numbered_type(ti, row.ordinal)) {
                    xsql::set_vtab_error("types: ordinal " + std::to_string(row.ordinal) + " not found");
                    return false;
                }
                // For an enum, `size` sets its storage width (set_nbytes).
                // Rebuild via enum_type_data_t -- preserves members and the bitmask
                // flag (carried in `bte`).
                if (tif.is_enum()) {
                    enum_type_data_t ei;
                    if (!tif.get_enum_details(&ei)) {
                        xsql::set_vtab_error("types: cannot read enum details (ordinal=" +
                                              std::to_string(row.ordinal) + ")");
                        return false;
                    }
                    if (!ei.set_nbytes(static_cast<int>(new_size))) {
                        xsql::set_vtab_error("types: enum width must be 1, 2, 4, or 8 (ordinal=" +
                                              std::to_string(row.ordinal) + ")");
                        return false;
                    }
                    tinfo_t rebuilt;
                    if (!rebuilt.create_enum(ei) ||
                        rebuilt.set_numbered_type(ti, row.ordinal, NTF_REPLACE, nullptr) != TERR_OK) {
                        xsql::set_vtab_error("types: failed to set enum width (ordinal=" +
                                              std::to_string(row.ordinal) + ")");
                        return false;
                    }
                    row.size = new_size;
                    return true;
                }
                if (!tif.is_struct() || !tif.is_fixed_struct()) {
                    xsql::set_vtab_error("types: size is only settable on a fixed-layout struct or "
                                         "an enum -- set is_fixed = 1 first for structs (ordinal=" +
                                          std::to_string(row.ordinal) + ")");
                    return false;
                }
                if (tif.set_struct_size(static_cast<size_t>(new_size)) != TERR_OK) {
                    xsql::set_vtab_error("types: failed to set size to " + std::to_string(new_size) +
                                         " (must be >= the unpadded struct size; ordinal=" +
                                          std::to_string(row.ordinal) + ")");
                    return false;
                }
                row.size = new_size;
                return true;
            })
        .column_int("alignment", [](const TypeEntry& row) -> int {
            return row.alignment;
        })
        .column_int("is_struct", [](const TypeEntry& row) -> int {
            return row.is_struct ? 1 : 0;
        })
        .column_int("is_union", [](const TypeEntry& row) -> int {
            return row.is_union ? 1 : 0;
        })
        .column_int("is_enum", [](const TypeEntry& row) -> int {
            return row.is_enum ? 1 : 0;
        })
        .column_int("is_typedef", [](const TypeEntry& row) -> int {
            return row.is_typedef ? 1 : 0;
        })
        .column_int("is_func", [](const TypeEntry& row) -> int {
            return row.is_func ? 1 : 0;
        })
        .column_int("is_ptr", [](const TypeEntry& row) -> int {
            return row.is_ptr ? 1 : 0;
        })
        .column_int("is_array", [](const TypeEntry& row) -> int {
            return row.is_array ? 1 : 0;
        })
        .column_text("definition", [](const TypeEntry& row) -> std::string {
            return row.definition;
        })
        .column_text("resolved", [](const TypeEntry& row) -> std::string {
            return row.resolved;
        })
        .column_text_nullable_rw("folder_path",
            [](const TypeEntry& row) -> std::optional<std::string> {
                if (row.folder_path.empty()) {
                    return std::nullopt;
                }
                return row.folder_path;
            },
            [](TypeEntry& row, xsql::FunctionArg val) -> bool {
                const bool ok = dirtrees::move_inode_to_folder(
                    DIRTREE_LOCAL_TYPES, static_cast<uint64_t>(row.ordinal),
                    row.name, val, "types.folder_path");
                if (ok) {
                    auto path = dirtrees::find_inode_path(
                        DIRTREE_LOCAL_TYPES, static_cast<uint64_t>(row.ordinal));
                    if (path) {
                        row.folder_path = path->folder_path;
                        row.full_path = path->full_path;
                    }
                }
                return ok;
            })
        .column_text("full_path", [](const TypeEntry& row) -> std::string {
            return row.full_path;
        })
        // Writable fixed-layout flag. ON freezes member offsets
        // (set_fixed_struct) so deletes leave gaps and explicit offsets stick; OFF
        // returns the struct to auto-layout (IDA repacks/recomputes -- may shrink).
        .column_int_rw("is_fixed",
            [](const TypeEntry& row) -> int {
                return row.is_fixed ? 1 : 0;
            },
            [](TypeEntry& row, int on) -> bool {
                til_t* ti = get_idati();
                tinfo_t tif;
                if (!ti || !tif.get_numbered_type(ti, row.ordinal)) {
                    xsql::set_vtab_error("types: ordinal " + std::to_string(row.ordinal) + " not found");
                    return false;
                }
                if (!tif.is_struct()) {
                    xsql::set_vtab_error("types: is_fixed applies only to structs (ordinal=" +
                                          std::to_string(row.ordinal) + ")");
                    return false;
                }
                if (tif.set_fixed_struct(on != 0) != TERR_OK) {
                    xsql::set_vtab_error("types: failed to set is_fixed (ordinal=" +
                                          std::to_string(row.ordinal) + ")");
                    return false;
                }
                row.is_fixed = (on != 0);
                return true;
            })
        // Writable bitmask-enum flag. ON marks the enum as a bitmask (its
        // members are bit flags; combined operand values render as OR'd flags);
        // OFF reverts to an ordinary ordinal enum. Set the width via `size`.
        .column_int_rw("is_bitmask",
            [](const TypeEntry& row) -> int {
                return row.is_bitmask ? 1 : 0;
            },
            [](TypeEntry& row, int on) -> bool {
                til_t* ti = get_idati();
                tinfo_t tif;
                if (!ti || !tif.get_numbered_type(ti, row.ordinal)) {
                    xsql::set_vtab_error("types: ordinal " + std::to_string(row.ordinal) + " not found");
                    return false;
                }
                if (!tif.is_enum()) {
                    xsql::set_vtab_error("types: is_bitmask applies only to enums (ordinal=" +
                                          std::to_string(row.ordinal) + ")");
                    return false;
                }
                if (tif.set_enum_is_bitmask(
                        on != 0 ? tinfo_t::ENUMBM_ON : tinfo_t::ENUMBM_OFF) != TERR_OK) {
                    xsql::set_vtab_error("types: failed to set is_bitmask (ordinal=" +
                                          std::to_string(row.ordinal) + ")");
                    return false;
                }
                row.is_bitmask = (on != 0);
                return true;
            })
        // Pushdown so exact and prefix lookups don't render every type.
        // Exact ordinal/name resolve+render one row; prefix walks cheap names and
        // renders only matches (the SDK has no sorted/prefix index -- the win is
        // skipping tinfo_t::print() for non-matches, which is the real cost).
        // Registered AFTER the columns so filter_eq can resolve the column index.
        .filter_eq("ordinal",
            [](int64_t ord) -> std::unique_ptr<xsql::RowIterator> {
                // Type ordinals are uint32; reject anything out of range rather
                // than truncating (e.g. 4294967297 -> 1 would return ordinal-1).
                // Ordinal 0 is always a gap, so the iterator resolves no row.
                if (ord <= 0 || ord > static_cast<int64_t>(UINT32_MAX))
                    return std::make_unique<TypeByKeyIterator>(0u);
                return std::make_unique<TypeByKeyIterator>(static_cast<uint32_t>(ord));
            }, 1.0, 1.0)
        .filter_eq_text("name",
            [](const char* name) -> std::unique_ptr<xsql::RowIterator> {
                return std::make_unique<TypeByKeyIterator>(name ? std::string(name)
                                                                : std::string());
            }, 1.0, 1.0)
        .filter_prefix("name",
            [](const std::string& pattern) -> std::unique_ptr<xsql::RowIterator> {
                return std::make_unique<TypePrefixIterator>(pattern);
            }, 50.0, 20.0)
        // The table's stable rowid is the type ordinal. The pushdown iterators
        // report it; rowid() makes the full-scan/index cursors agree; row_lookup()
        // reconstructs a row from it so UPDATE/DELETE resolve the exact type
        // regardless of whether the plan used a filter or a full scan.
        .rowid([](const TypeEntry& row) -> int64_t {
            return static_cast<int64_t>(row.ordinal);
        })
        .row_lookup([](TypeEntry& row, int64_t rowid) -> bool {
            // Type ordinals are uint32; reject anything that would truncate when
            // narrowed (a rowid > UINT32_MAX would silently alias a real ordinal).
            if (rowid <= 0 || rowid > static_cast<int64_t>(UINT32_MAX)) return false;
            til_t* ti = get_idati();
            if (!ti) return false;
            const uint32_t ord = static_cast<uint32_t>(rowid);
            if (!render_type_core(ti, ord, row)) return false;
            fill_folder_path(ord, row);
            return true;
        })
        .deletable([](TypeEntry& row) -> bool {
            til_t* ti = get_idati();
            if (!ti) return false;
            return del_numbered_type(ti, row.ordinal);
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            if (argc < 2 || argv[1].is_null()) {
                xsql::set_vtab_error("types: INSERT requires a name");
                return false;
            }

            const char* name = argv[1].as_c_str();
            if (!name || !name[0]) {
                xsql::set_vtab_error("types: name cannot be empty");
                return false;
            }

            // kind (col 2): defaults to "struct"
            std::string kind = "struct";
            if (argc > 2 && !argv[2].is_null()) {
                const char* k = argv[2].as_c_str();
                if (k && k[0]) kind = k;
            }

            til_t* ti = get_idati();
            if (!ti) {
                xsql::set_vtab_error("types: type library not available");
                return false;
            }

            // Check if type with this name already exists
            if (get_type_ordinal(ti, name) != 0) {
                xsql::set_vtab_error("types: a type named '" + std::string(name) +
                                     "' already exists");
                return false;
            }

            // Build the tinfo BEFORE allocating an ordinal so an invalid kind (or
            // any other pre-alloc failure) does not permanently leak an empty
            // ordinal as a forever gap in the ordinal space.
            tinfo_t tif;
            if (kind == "struct") {
                udt_type_data_t udt;
                udt.is_union = false;
                tif.create_udt(udt);
            } else if (kind == "union") {
                udt_type_data_t udt;
                udt.is_union = true;
                tif.create_udt(udt);
            } else if (kind == "enum") {
                enum_type_data_t ei;
                tif.create_enum(ei);
            } else {
                xsql::set_vtab_error("types: unsupported kind '" + kind +
                                     "'; expected struct, union, or enum");
                return false;
            }

            uint32_t ord = alloc_type_ordinal(ti);
            if (ord == 0) {
                xsql::set_vtab_error("types: failed to allocate a type ordinal for '" +
                                     std::string(name) + "'");
                return false;
            }

            if (tif.set_numbered_type(ti, ord, NTF_REPLACE, name) != TERR_OK) {
                xsql::set_vtab_error("types: failed to create type '" + std::string(name) +
                                     "' (kind=" + kind + ", ordinal=" + std::to_string(ord) + ")");
                return false;
            }
            return true;
        })
        .build();
}

// ============================================================================
// APPLIED_TYPES Table - Type bindings at addresses
// ============================================================================

} // namespace types
} // namespace idasql
