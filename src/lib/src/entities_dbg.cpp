// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "entities_dbg.hpp"

#include "dirtree_utils.hpp"

namespace idasql {
namespace debugger {

const char* bpt_type_name(bpttype_t type) {
    switch (type) {
        case BPT_WRITE: return "hardware_write";
        case BPT_READ:  return "hardware_read";
        case BPT_RDWR:  return "hardware_rdwr";
        case BPT_SOFT:  return "software";
        case BPT_EXEC:  return "hardware_exec";
        default:        return "unknown";
    }
}

const char* bpt_loc_type_name(int loc_type) {
    switch (loc_type) {
        case BPLT_ABS: return "absolute";
        case BPLT_REL: return "relative";
        case BPLT_SYM: return "symbolic";
        case BPLT_SRC: return "source";
        default:       return "unknown";
    }
}

std::string safe_bpt_group(const bpt_t& bpt) {
    // A breakpoint's "group" is its folder in the DIRTREE_BPTS dirtree. Read it
    // from the dirtree first: find_inode_path() loads the tree, so this is
    // robust headless. The debugger-coupled get_bpt_group() returns empty under
    // idalib whenever the bpts dirtree hasn't been loaded yet this session
    // (order-dependent), so it is only a fallback. See safe_bpt_full_path().
    auto path = dirtrees::find_inode_path(DIRTREE_BPTS,
                                          static_cast<uint64_t>(bpt.bptid));
    if (path && !path->folder_path.empty())
        return dirtrees::normalize_relative_path(path->folder_path);
    qstring grp;
    if (get_bpt_group(&grp, bpt.loc))
        return dirtrees::normalize_relative_path(grp.c_str());
    return "";
}

std::optional<std::string> safe_bpt_folder_path(const bpt_t& bpt) {
    std::string group = safe_bpt_group(bpt);
    if (group.empty())
        return std::nullopt;
    return group;
}

std::string safe_bpt_full_path(const bpt_t& bpt) {
    auto path = dirtrees::find_inode_path(DIRTREE_BPTS, static_cast<uint64_t>(bpt.bptid));
    if (path)
        return path->full_path;
    std::string group = safe_bpt_group(bpt);
    if (group.empty())
        return "";
    return "/" + group + "/" + std::to_string(bpt.bptid);
}

bool set_bpt_folder(bpt_t& bpt, xsql::FunctionArg value, const char* surface) {
    const char* text = value.is_null() ? "" : value.as_c_str();
    std::string normalized = dirtrees::normalize_relative_path(text ? text : "");
    bool ok = set_bpt_group(bpt, normalized.c_str());
    if (!ok)
        xsql::set_vtab_error(std::string(surface) + ": failed to set breakpoint folder");
    return ok;
}

bool set_bpt_enabled(bpt_t& bpt, bool enable) {
    if (enable)
        bpt.flags |= BPT_ENABLED;
    else
        bpt.flags &= ~BPT_ENABLED;
    bool ok = update_bpt(&bpt);
    if (!ok)
        xsql::set_vtab_error("breakpoints: failed to set enabled state");
    return ok;
}

std::string safe_bpt_loc_path(const bpt_t& bpt) {
    const bpt_location_t& loc = bpt.loc;
    if (loc.type() == BPLT_REL || loc.type() == BPLT_SRC) {
        const char* p = loc.path();
        return p ? std::string(p) : "";
    }
    return "";
}

std::string safe_bpt_loc_symbol(const bpt_t& bpt) {
    const bpt_location_t& loc = bpt.loc;
    if (loc.type() == BPLT_SYM) {
        const char* s = loc.symbol();
        return s ? std::string(s) : "";
    }
    return "";
}

VTableDef define_breakpoints() {
    return table("breakpoints")
        .count([]() { return static_cast<size_t>(get_bpt_qty()); })
        // Column 0: address (R)
        .column_int64("addr", [](size_t i) -> int64_t {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return 0;
            return static_cast<int64_t>(bpt.ea);
        })
        // Column 1: enabled (RW)
        .column_int_rw("enabled",
            [](size_t i) -> int {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) return 0;
                return bpt.enabled() ? 1 : 0;
            },
            [](size_t i, int val) -> bool {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) {
                    xsql::set_vtab_error("breakpoints: breakpoint not found at index " + std::to_string(i));
                    return false;
                }
                return set_bpt_enabled(bpt, val != 0);
            })
        // Column 2: type (RW)
        .column_int_rw("type",
            [](size_t i) -> int {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) return 0;
                return static_cast<int>(bpt.type);
            },
            [](size_t i, int val) -> bool {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) {
                    xsql::set_vtab_error("breakpoints: breakpoint not found at index " + std::to_string(i));
                    return false;
                }
                bpt.type = static_cast<bpttype_t>(val);
                bool ok = update_bpt(&bpt);
                if (!ok) xsql::set_vtab_error("breakpoints: failed to update type");
                return ok;
            })
        // Column 3: type_name (R)
        .column_text("type_name", [](size_t i) -> std::string {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return "";
            return bpt_type_name(bpt.type);
        })
        // Column 4: size (RW)
        .column_int_rw("size",
            [](size_t i) -> int {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) return 0;
                return bpt.size;
            },
            [](size_t i, int val) -> bool {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) {
                    xsql::set_vtab_error("breakpoints: breakpoint not found at index " + std::to_string(i));
                    return false;
                }
                bpt.size = val;
                bool ok = update_bpt(&bpt);
                if (!ok) xsql::set_vtab_error("breakpoints: failed to update size");
                return ok;
            })
        // Column 5: flags (RW)
        .column_int64_rw("flags",
            [](size_t i) -> int64_t {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) return 0;
                return static_cast<int64_t>(bpt.flags);
            },
            [](size_t i, int64_t val) -> bool {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) {
                    xsql::set_vtab_error("breakpoints: breakpoint not found at index " + std::to_string(i));
                    return false;
                }
                // Preserve BPT_ENABLED from current state so flags writes
                // don't undo enabled-column writes during batch vtable updates
                uint32 cur_enabled = bpt.flags & BPT_ENABLED;
                bpt.flags = (static_cast<uint32>(val) & ~BPT_ENABLED) | cur_enabled;
                bool ok = update_bpt(&bpt);
                if (!ok) xsql::set_vtab_error("breakpoints: failed to update flags");
                return ok;
            })
        // Column 6: pass_count (RW)
        .column_int_rw("pass_count",
            [](size_t i) -> int {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) return 0;
                return bpt.pass_count;
            },
            [](size_t i, int val) -> bool {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) {
                    xsql::set_vtab_error("breakpoints: breakpoint not found at index " + std::to_string(i));
                    return false;
                }
                bpt.pass_count = val;
                bool ok = update_bpt(&bpt);
                if (!ok) xsql::set_vtab_error("breakpoints: failed to update pass_count");
                return ok;
            })
        // Column 7: condition (RW)
        .column_text_rw("condition",
            [](size_t i) -> std::string {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) return "";
                return std::string(bpt.cndbody.c_str());
            },
            [](size_t i, const char* val) -> bool {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) {
                    xsql::set_vtab_error("breakpoints: breakpoint not found at index " + std::to_string(i));
                    return false;
                }
                bpt.cndbody = val;
                bool ok = update_bpt(&bpt);
                if (!ok) xsql::set_vtab_error("breakpoints: failed to update condition");
                return ok;
            })
        // Column 8: loc_type (R)
        .column_int("loc_type", [](size_t i) -> int {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return 0;
            return bpt.loc.type();
        })
        // Column 9: loc_type_name (R)
        .column_text("loc_type_name", [](size_t i) -> std::string {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return "";
            return bpt_loc_type_name(bpt.loc.type());
        })
        // Column 10: module (R)
        .column_text("module", [](size_t i) -> std::string {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return "";
            return safe_bpt_loc_path(bpt);
        })
        // Column 11: symbol (R)
        .column_text("symbol", [](size_t i) -> std::string {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return "";
            return safe_bpt_loc_symbol(bpt);
        })
        // Column 12: offset (R)
        .column_int64("offset", [](size_t i) -> int64_t {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return 0;
            int lt = bpt.loc.type();
            if (lt == BPLT_REL || lt == BPLT_SYM)
                return static_cast<int64_t>(bpt.loc.offset());
            return 0;
        })
        // Column 13: source_file (R)
        .column_text("source_file", [](size_t i) -> std::string {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return "";
            if (bpt.loc.type() == BPLT_SRC) {
                const char* p = bpt.loc.path();
                return p ? std::string(p) : "";
            }
            return "";
        })
        // Column 14: source_line (R)
        .column_int("source_line", [](size_t i) -> int {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return 0;
            if (bpt.loc.type() == BPLT_SRC)
                return bpt.loc.lineno();
            return 0;
        })
        // Column 15: is_hardware (R)
        .column_int("is_hardware", [](size_t i) -> int {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return 0;
            return bpt.is_hwbpt() ? 1 : 0;
        })
        // Column 16: is_active (R)
        .column_int("is_active", [](size_t i) -> int {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return 0;
            return bpt.is_active() ? 1 : 0;
        })
        // Column 17: group (RW)
        .column_text_rw("group",
            [](size_t i) -> std::string {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) return "";
                return safe_bpt_group(bpt);
            },
            [](size_t i, const char* val) -> bool {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) {
                    xsql::set_vtab_error("breakpoints: breakpoint not found at index " + std::to_string(i));
                    return false;
                }
                std::string normalized = dirtrees::normalize_relative_path(val ? val : "");
                bool ok = set_bpt_group(bpt, normalized.c_str());
                if (!ok) xsql::set_vtab_error("breakpoints: failed to set group");
                return ok;
            })
        // Column 18: bptid (R)
        .column_int64("bptid", [](size_t i) -> int64_t {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return 0;
            return static_cast<int64_t>(bpt.bptid);
        })
        // Column 19: folder_path (RW, alias of group)
        .column_text_nullable_rw("folder_path",
            [](size_t i) -> std::optional<std::string> {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) return std::nullopt;
                return safe_bpt_folder_path(bpt);
            },
            [](size_t i, xsql::FunctionArg value) -> bool {
                bpt_t bpt;
                if (!getn_bpt(static_cast<int>(i), &bpt)) {
                    xsql::set_vtab_error("breakpoints.folder_path: breakpoint not found at index " + std::to_string(i));
                    return false;
                }
                return set_bpt_folder(bpt, value, "breakpoints.folder_path");
            })
        // Column 20: full_path (R)
        .column_text("full_path", [](size_t i) -> std::string {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return "";
            return safe_bpt_full_path(bpt);
        })
        // DELETE support
        .deletable([](size_t i) -> bool {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return false;
            return del_bpt(bpt.loc);
        })
        // INSERT support
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            auto is_non_null = [&](int col) -> bool {
                return col < argc && !argv[col].is_null();
            };

            auto get_text = [&](int col) -> const char* {
                if (col >= argc) return nullptr;
                return argv[col].as_c_str();
            };

            auto get_int = [&](int col, int def = 0) -> int {
                if (!is_non_null(col)) return def;
                return argv[col].as_int();
            };

            auto get_int64 = [&](int col, int64_t def = 0) -> int64_t {
                if (!is_non_null(col)) return def;
                return argv[col].as_int64();
            };

            bool ok = false;

            // Identity of the breakpoint we are about to insert, so the
            // post-property loops below update *that* bpt and not an unrelated
            // one. For the addr branch we match by ea; for the symbolic /
            // relative / source branches the bpt list is location-ordered (not
            // newest-last), so we must match by location.
            bool match_by_ea = is_non_null(0);
            ea_t target_ea = match_by_ea ? static_cast<ea_t>(get_int64(0)) : BADADDR;
            bpt_location_t target_loc;

            if (is_non_null(11)) {
                const char* sym = get_text(11);
                if (!sym) return false;
                int64_t off = get_int64(12, 0);
                bpt_t bpt;
                bpt.loc.set_sym_bpt(sym, static_cast<uval_t>(off));
                bpt.type = static_cast<bpttype_t>(get_int(2, BPT_SOFT));
                bpt.size = get_int(4, 0);
                target_loc = bpt.loc;
                ok = add_bpt(bpt);
            } else if (is_non_null(10)) {
                const char* mod = get_text(10);
                if (!mod) return false;
                int64_t off = get_int64(12, 0);
                bpt_t bpt;
                bpt.loc.set_rel_bpt(mod, static_cast<uval_t>(off));
                bpt.type = static_cast<bpttype_t>(get_int(2, BPT_SOFT));
                bpt.size = get_int(4, 0);
                target_loc = bpt.loc;
                ok = add_bpt(bpt);
            } else if (is_non_null(13)) {
                const char* file = get_text(13);
                if (!file) return false;
                int line = get_int(14, 1);
                bpt_t bpt;
                bpt.loc.set_src_bpt(file, line);
                bpt.type = static_cast<bpttype_t>(get_int(2, BPT_SOFT));
                bpt.size = get_int(4, 0);
                target_loc = bpt.loc;
                ok = add_bpt(bpt);
            } else if (is_non_null(0)) {
                ea_t ea = static_cast<ea_t>(get_int64(0));
                int sz = get_int(4, 0);
                bpttype_t tp = static_cast<bpttype_t>(get_int(2, BPT_SOFT));
                ok = add_bpt(ea, sz, tp);
            } else {
                return false;
            }

            if (!ok) return false;

            // Compare two breakpoint locations without going through the
            // UI-callback-backed operator== (which is unavailable headless):
            // equal type, and equal string+offset (or ea for absolute).
            auto loc_eq = [](const bpt_location_t& a, const bpt_location_t& b) -> bool {
                if (a.type() != b.type()) return false;
                if (a.type() == BPLT_ABS) return a.ea() == b.ea();
                if (a.type() == BPLT_SRC) {
                    if (a.lineno() != b.lineno()) return false;
                } else if (a.offset() != b.offset()) {
                    return false;
                }
                const char* pa = a.symbol();
                const char* pb = b.symbol();
                return (pa ? pa : "") == std::string(pb ? pb : "");
            };

            // Locate the just-inserted bpt into `bpt`; returns false if not found.
            auto find_inserted = [&](bpt_t& bpt) -> bool {
                int n = get_bpt_qty();
                for (int j = 0; j < n; ++j) {
                    if (!getn_bpt(j, &bpt)) continue;
                    if (match_by_ea) {
                        if (bpt.ea == target_ea) return true;
                    } else if (loc_eq(bpt.loc, target_loc)) {
                        return true;
                    }
                }
                return false;
            };

            // Apply optional properties after creation, all against the bpt we
            // just inserted (located via find_inserted).
            if (is_non_null(7)) {
                const char* cond = get_text(7);
                if (cond) {
                    bpt_t bpt;
                    if (find_inserted(bpt)) {
                        bpt.cndbody = cond;
                        update_bpt(&bpt);
                    }
                }
            }

            if (is_non_null(6)) {
                bpt_t bpt;
                if (find_inserted(bpt)) {
                    bpt.pass_count = get_int(6);
                    update_bpt(&bpt);
                }
            }

            if (is_non_null(5)) {
                bpt_t bpt;
                if (find_inserted(bpt)) {
                    // Preserve BPT_ENABLED from current state, matching the
                    // UPDATE flags setter, so a raw flags write does not undo
                    // the bpt's enabled status.
                    uint32 cur_enabled = bpt.flags & BPT_ENABLED;
                    bpt.flags = (static_cast<uint32>(get_int64(5)) & ~BPT_ENABLED) | cur_enabled;
                    update_bpt(&bpt);
                }
            }

            if (is_non_null(1)) {
                bool enable = get_int(1) != 0;
                bpt_t bpt;
                if (find_inserted(bpt)) {
                    set_bpt_enabled(bpt, enable);
                }
            }

            int folder_col = is_non_null(19) ? 19 : 17;
            if (is_non_null(folder_col)) {
                const char* grp = get_text(folder_col);
                if (grp) {
                    std::string normalized = dirtrees::normalize_relative_path(grp);
                    bpt_t bpt;
                    if (find_inserted(bpt)) {
                        set_bpt_group(bpt, normalized.c_str());
                    }
                }
            }

            return true;
        })
        .build();
}

// ============================================================================
// Registry
// ============================================================================

DebuggerRegistry::DebuggerRegistry()
    : breakpoints(define_breakpoints())
{}

void DebuggerRegistry::register_all(xsql::Database& db) {
    db.register_table("ida_breakpoints", &breakpoints);
    db.create_table("breakpoints", "ida_breakpoints");
}

} // namespace debugger
} // namespace idasql
