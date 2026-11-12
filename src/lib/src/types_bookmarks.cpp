// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_bookmarks.hpp"

#include <cstdlib>
#include <limits>
#include <optional>

static bool parse_major_minor(const char* text, long& major, long& minor) {
    char* end = nullptr;
    major = std::strtol(text, &end, 10);
    if (end == text || *end != '.') return false;
    const char* rest = end + 1;
    minor = std::strtol(rest, &end, 10);
    return end != rest;
}

namespace idasql {
namespace types {

static constexpr uint64_t kNoLeafInode = ~uint64_t(0);

static lochist_entry_t& owned_ltype_place_template() {
    static lochist_entry_t owned;
    return owned;
}

void reset_local_type_bookmark_place_cache() {
    owned_ltype_place_template() = lochist_entry_t();
}

static lochist_entry_t make_ltype_loc(uint32_t ordinal) {
    lochist_entry_t& owned = owned_ltype_place_template();
    if (owned.place() == nullptr) {
        const place_t* tmpl = get_place_class_template(TCCPT_TIPLACE);
        if (tmpl != nullptr) {
            renderer_info_t rinfo;
            owned = lochist_entry_t(tmpl, rinfo);
        }
    }

    renderer_info_t rinfo;
    lochist_entry_t loc(owned.place(), rinfo);
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

    lochist_entry_t probe = make_ltype_loc(0);
    if (probe.place() == nullptr)
        return;
    const uint32_t n = bookmarks_t::size(probe, nullptr);

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
            row.inode = it->second.first;
            row.folder_path = it->second.second.folder_path;
            row.full_path = it->second.second.full_path;
        } else {
            row.inode = kNoLeafInode;
        }
        rows.push_back(std::move(row));
    }
}

CachedTableDef<LocalTypeBookmarkRow> define_local_type_bookmarks() {
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
                const std::string want =
                    value.is_null()
                        ? std::string()
                        : dirtrees::normalize_relative_path(
                              value.as_c_str() ? value.as_c_str() : "");
                if (want == row.folder_path)
                    return true;
                if (row.inode == kNoLeafInode) {
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
            if (argc < 2 || argv[1].is_null()) {
                xsql::set_vtab_error("local_type_bookmarks: ordinal is required");
                return false;
            }
            const std::optional<int64_t> ord = xsql::exact_int64(argv[1]);
            if (!ord || *ord < 1 || *ord > static_cast<int64_t>((std::numeric_limits<uint32_t>::max)())) {
                xsql::set_vtab_error(
                    "local_type_bookmarks: no local type with ordinal "
                    + (ord ? std::to_string(*ord) : std::string(argv[1].as_c_str())));
                return false;
            }
            const uint32_t ordinal = static_cast<uint32_t>(*ord);

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

            if (!is_idaq()) {
                char ver[32] = {};
                get_kernel_version(ver, sizeof(ver));
                long major = 0, minor = 0;
                if (parse_major_minor(ver, major, minor) && major == 9 && minor == 2) {
                    xsql::set_vtab_error(
                        std::string("local_type_bookmarks: IDA 9.2 crashes creating a local-type "
                                    "bookmark under idalib; create it in the IDA GUI or with "
                                    "another IDA version (this is IDA ") + ver + ")");
                    return false;
                }
            }

            idasql_auto_wait();
            lochist_entry_t loc = make_ltype_loc(ordinal);
            if (loc.place() == nullptr) {
                xsql::set_vtab_error(
                    "local_type_bookmarks: tiplace place class unavailable");
                return false;
            }

            uint32_t slot = bookmarks_t::size(loc, nullptr);
            if (argc > 0 && !argv[0].is_null()) {
                const std::optional<int64_t> s = xsql::exact_int64(argv[0]);
                if (!s || *s < 0 || *s >= static_cast<int64_t>(BOOKMARKS_BAD_INDEX)) {
                    xsql::set_vtab_error("local_type_bookmarks.slot: expected a slot number >= 0");
                    return false;
                }
                slot = static_cast<uint32_t>(*s);
            }

            uint32_t result = bookmarks_t::mark(loc, slot, nullptr, desc, nullptr);
            idasql_auto_wait();
            return result != BOOKMARKS_BAD_INDEX;
        })
        .build();
}

}
}
