// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "types_bookmarks.hpp"

namespace idasql {
namespace types {

// Build a lochist_entry_t anchored at a local-type ordinal WITHOUT constructing
// tiplace_t directly: its place_t virtuals (get_kind, calc_udm_offset, ...) are
// GUI-side and not exported to idalib, so a direct `tiplace_t x;` fails to link.
// Instead clone the kernel-registered place-class template (valid vtable) and
// set the ordinal via plain member access (no vtable use).
// Sentinel for "this store bookmark has no DIRTREE_LTYPES_BOOKMARKS leaf yet"
// (a real dirtree inode can legitimately be 0, so 0 cannot mean "none").
static constexpr uint64_t kNoLeafInode = ~uint64_t(0);

static lochist_entry_t make_ltype_loc(uint32_t ordinal) {
    // Keep a long-lived, OWNED clone of the place-class template -- do NOT cache
    // the raw template pointer. get_place_class_template(TCCPT_TIPLACE) can
    // return nullptr after the Hex-Rays/pseudocode subsystem reshuffles and
    // FREES the registry template (e.g. after a decompile + cache invalidation);
    // a cached raw pointer would then dangle, and cloning it dereferences freed
    // memory once that block is reused (observed as a vtable call on garbage).
    // lochist_entry_t owns its place (deep-clones on construction, frees on
    // destruction) and the clone's vtable points at stable module code, so an
    // owned clone survives such reshuffles. Capture it once, the first time the
    // template is available, then clone from the owned copy thereafter.
    static lochist_entry_t s_owned;
    if (s_owned.place() == nullptr) {
        const place_t* tmpl = get_place_class_template(TCCPT_TIPLACE);
        if (tmpl != nullptr) {
            renderer_info_t rinfo;
            s_owned = lochist_entry_t(tmpl, rinfo);  // deep clone, owned
        }
    }

    renderer_info_t rinfo;
    // Clone from the owned template (stable) or stay empty if never captured.
    lochist_entry_t loc(s_owned.place(), rinfo);
    if (loc.place() != nullptr) {
        tiplace_t* tp = static_cast<tiplace_t*>(loc.place());
        tp->ordinal = ordinal;
        tp->cursor = TIF_CURSOR_HEADER;
    }
    return loc;
}

void collect_local_type_bookmark_rows(std::vector<LocalTypeBookmarkRow>& rows) {
    rows.clear();
    til_t* ti = get_idati();

    // The bookmarks_t store is the source of truth: bookmarks_t::mark() does not
    // auto-link a DIRTREE_LTYPES_BOOKMARKS leaf for a tiplace the way it does for
    // an EA-capable idaplace bookmark, so a dirtree-only scan misses store
    // bookmarks that have no leaf. Enumerate the store (slot 0..size) for the
    // ordinal/description, and overlay folder_path from the dirtree for the
    // bookmarks that do have a leaf (organized into folders).
    lochist_entry_t probe = make_ltype_loc(0);
    if (probe.place() == nullptr)
        return;  // tiplace place class unavailable in this runtime
    const uint32_t n = bookmarks_t::size(probe, nullptr);

    // dirtree leaf -> bookmark slot, so we can attach folder_path/inode.
    auto inode_paths = dirtrees::collect_inode_paths(DIRTREE_LTYPES_BOOKMARKS);
    std::unordered_map<uint32_t, std::pair<uint64_t, dirtrees::DirtreePathInfo>>
        slot_folder;
    for (const auto& ip : inode_paths) {
        lochist_entry_t e = make_ltype_loc(0);
        qstring d;
        uint32_t slot = idasql_bookmarks_get_by_inode(
            &e, &d, static_cast<inode_t>(ip.first), nullptr);
        if (slot != BOOKMARKS_BAD_INDEX)
            slot_folder[slot] = {ip.first, ip.second};
    }

    for (uint32_t slot = 0; slot < n; ++slot) {
        lochist_entry_t entry = make_ltype_loc(0);
        qstring desc;
        uint32_t idx = slot;
        if (!bookmarks_t::get(&entry, &desc, &idx, nullptr)
            || entry.place() == nullptr)
            continue;

        LocalTypeBookmarkRow row;
        row.index = slot;
        row.ordinal = static_cast<tiplace_t*>(entry.place())->ordinal;
        row.desc = desc.c_str();
        const char* tn = (ti != nullptr && row.ordinal != 0)
                             ? get_numbered_type_name(ti, row.ordinal)
                             : nullptr;
        row.type_name = tn ? tn : "";

        auto it = slot_folder.find(slot);
        if (it != slot_folder.end()) {
            row.inode = it->second.first;  // real dirtree inode (may legitimately be 0)
            row.folder_path = it->second.second.folder_path;
            row.full_path = it->second.second.full_path;
        } else {
            row.inode = kNoLeafInode;  // not linked into the dirtree yet
        }
        rows.push_back(std::move(row));
    }
}

CachedTableDef<LocalTypeBookmarkRow> define_local_type_bookmarks() {
    // Prime the tiplace place-class template cache at registration time (the
    // first QueryEngine init, before any Hex-Rays/pseudocode work can reshuffle
    // the place-class registry and make get_place_class_template return null).
    (void)make_ltype_loc(0);
    return cached_table<LocalTypeBookmarkRow>("local_type_bookmarks")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 128; })
        .cache_builder([](std::vector<LocalTypeBookmarkRow>& rows) {
            collect_local_type_bookmark_rows(rows);
        })
        .row_populator([](LocalTypeBookmarkRow& row, int argc, xsql::FunctionArg* argv) {
            if (argc > 2 && !argv[2].is_null())
                row.index = static_cast<uint32_t>(argv[2].as_int());
            if (argc > 3 && !argv[3].is_null())
                row.ordinal = static_cast<uint32_t>(argv[3].as_int());
            if (argc > 4 && !argv[4].is_null()) {
                const char* name = argv[4].as_c_str();
                row.type_name = name ? name : "";
            }
            if (argc > 5 && !argv[5].is_null()) {
                const char* desc = argv[5].as_c_str();
                row.desc = desc ? desc : "";
            }
            if (argc > 6 && !argv[6].is_null())
                row.inode = static_cast<uint64_t>(argv[6].as_int64());
            if (argc > 8 && !argv[8].is_null()) {
                const char* full = argv[8].as_c_str();
                row.full_path = full ? full : "";
            }
        })
        .column_int("slot", [](const LocalTypeBookmarkRow& row) -> int {
            return static_cast<int>(row.index);
        })
        .column_int("ordinal", [](const LocalTypeBookmarkRow& row) -> int {
            return static_cast<int>(row.ordinal);
        })
        .column_text("type_name", [](const LocalTypeBookmarkRow& row) -> std::string {
            return row.type_name;
        })
        .column_text_rw(
            "description",
            [](const LocalTypeBookmarkRow& row) -> std::string { return row.desc; },
            [](LocalTypeBookmarkRow& row, const char* new_desc) -> bool {
                idasql_auto_wait();
                lochist_entry_t loc = make_ltype_loc(row.ordinal);
                if (loc.place() == nullptr)
                    return false;
                bool ok = bookmarks_t_set_desc(qstring(new_desc ? new_desc : ""),
                                               loc, row.index, nullptr);
                if (ok)
                    row.desc = new_desc ? new_desc : "";
                idasql_auto_wait();
                return ok;
            })
        .column_int64("inode", [](const LocalTypeBookmarkRow& row) -> int64_t {
            return static_cast<int64_t>(row.inode);
        })
        .column_text_nullable_rw(
            "folder_path",
            [](const LocalTypeBookmarkRow& row) -> std::optional<std::string> {
                if (row.folder_path.empty())
                    return std::nullopt;
                return row.folder_path;
            },
            [](LocalTypeBookmarkRow& row, xsql::FunctionArg value) -> bool {
                // SQLite calls every writable setter on any UPDATE, so treat a
                // no-change folder as a no-op (lets `UPDATE ... SET description`
                // succeed without touching the folder).
                const std::string want =
                    value.is_null()
                        ? std::string()
                        : dirtrees::normalize_relative_path(
                              value.as_c_str() ? value.as_c_str() : "");
                if (want == row.folder_path)
                    return true;
                if (row.inode == kNoLeafInode) {
                    // Not yet linked into DIRTREE_LTYPES_BOOKMARKS. mark() does
                    // not auto-link a tiplace leaf (unlike EA-capable idaplace);
                    // the leaf CAN be linked headless via dirtree_t::link, but
                    // reliably mapping a store slot back to its inode is an open
                    // item, so folder moves currently
                    // require an already-linked bookmark.
                    if (want.empty())
                        return true;
                    xsql::set_vtab_error(
                        "local_type_bookmarks.folder_path: bookmark is not linked "
                        "into the dirtree; cannot set its folder yet");
                    return false;
                }
                std::string display = row.type_name.empty()
                                          ? std::to_string(row.ordinal)
                                          : row.type_name;
                const bool ok = dirtrees::move_inode_to_folder(
                    DIRTREE_LTYPES_BOOKMARKS, row.inode, display, value,
                    "local_type_bookmarks.folder_path");
                if (ok) {
                    auto path = dirtrees::find_inode_path(
                        DIRTREE_LTYPES_BOOKMARKS, row.inode);
                    if (path) {
                        row.folder_path = path->folder_path;
                        row.full_path = path->full_path;
                    }
                }
                return ok;
            })
        .column_text("full_path", [](const LocalTypeBookmarkRow& row) -> std::string {
            return row.full_path;
        })
        .deletable([](LocalTypeBookmarkRow& row) -> bool {
            idasql_auto_wait();
            lochist_entry_t loc = make_ltype_loc(row.ordinal);
            if (loc.place() == nullptr)
                return false;
            bool ok = bookmarks_t::erase(loc, row.index, nullptr);
            idasql_auto_wait();
            return ok;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            // columns: slot(0), ordinal(1), type_name(2), description(3), ...
            if (argc < 2 || argv[1].is_null()) {
                xsql::set_vtab_error("local_type_bookmarks: ordinal is required");
                return false;
            }
            uint32_t ordinal = static_cast<uint32_t>(argv[1].as_int());

            til_t* ti = get_idati();
            if (ti == nullptr || get_numbered_type_name(ti, ordinal) == nullptr) {
                xsql::set_vtab_error(
                    "local_type_bookmarks: no local type with ordinal "
                    + std::to_string(ordinal));
                return false;
            }

            const char* desc = "";
            if (argc > 3 && !argv[3].is_null()) {
                desc = argv[3].as_c_str();
                if (!desc)
                    desc = "";
            }

            idasql_auto_wait();
            lochist_entry_t loc = make_ltype_loc(ordinal);
            if (loc.place() == nullptr) {
                xsql::set_vtab_error(
                    "local_type_bookmarks: tiplace place class unavailable");
                return false;
            }

            uint32_t slot = bookmarks_t::size(loc, nullptr);
            if (argc > 0 && !argv[0].is_null())
                slot = static_cast<uint32_t>(argv[0].as_int());

            uint32_t result = bookmarks_t::mark(loc, slot, nullptr, desc, nullptr);
            idasql_auto_wait();
            return result != BOOKMARKS_BAD_INDEX;
        })
        .build();
}

// ============================================================================
// TYPES_MEMBERS Table - Struct/union field details
// ============================================================================

} // namespace types
} // namespace idasql
