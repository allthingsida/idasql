// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "entities_dbg.hpp"

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
    qstring grp;
    if (get_bpt_group(&grp, bpt.loc))
        return std::string(grp.c_str());
    return "";
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
        .column_int64("address", [](size_t i) -> int64_t {
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
                bool ok = enable_bpt(bpt.loc, val != 0);
                if (!ok) xsql::set_vtab_error("breakpoints: failed to set enabled state");
                return ok;
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
                // don't undo enable_bpt() calls during batch vtable updates
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
                bool ok = set_bpt_group(bpt, val);
                if (!ok) xsql::set_vtab_error("breakpoints: failed to set group");
                return ok;
            })
        // Column 18: bptid (R)
        .column_int64("bptid", [](size_t i) -> int64_t {
            bpt_t bpt;
            if (!getn_bpt(static_cast<int>(i), &bpt)) return 0;
            return static_cast<int64_t>(bpt.bptid);
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

            if (is_non_null(11)) {
                const char* sym = get_text(11);
                if (!sym) return false;
                int64_t off = get_int64(12, 0);
                bpt_t bpt;
                bpt.loc.set_sym_bpt(sym, static_cast<uval_t>(off));
                bpt.type = static_cast<bpttype_t>(get_int(2, BPT_SOFT));
                bpt.size = get_int(4, 0);
                ok = add_bpt(bpt);
            } else if (is_non_null(10)) {
                const char* mod = get_text(10);
                if (!mod) return false;
                int64_t off = get_int64(12, 0);
                bpt_t bpt;
                bpt.loc.set_rel_bpt(mod, static_cast<uval_t>(off));
                bpt.type = static_cast<bpttype_t>(get_int(2, BPT_SOFT));
                bpt.size = get_int(4, 0);
                ok = add_bpt(bpt);
            } else if (is_non_null(13)) {
                const char* file = get_text(13);
                if (!file) return false;
                int line = get_int(14, 1);
                bpt_t bpt;
                bpt.loc.set_src_bpt(file, line);
                bpt.type = static_cast<bpttype_t>(get_int(2, BPT_SOFT));
                bpt.size = get_int(4, 0);
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

            // Apply optional properties after creation
            if (is_non_null(7)) {
                const char* cond = get_text(7);
                if (cond) {
                    bpt_t bpt;
                    int n = get_bpt_qty();
                    for (int j = n - 1; j >= 0; --j) {
                        if (getn_bpt(j, &bpt)) {
                            if (is_non_null(0) && bpt.ea == static_cast<ea_t>(get_int64(0))) {
                                bpt.cndbody = cond;
                                update_bpt(&bpt);
                                break;
                            } else if (!is_non_null(0)) {
                                bpt.cndbody = cond;
                                update_bpt(&bpt);
                                break;
                            }
                        }
                    }
                }
            }

            if (is_non_null(6)) {
                bpt_t bpt;
                int n = get_bpt_qty();
                for (int j = n - 1; j >= 0; --j) {
                    if (getn_bpt(j, &bpt)) {
                        if (is_non_null(0) && bpt.ea == static_cast<ea_t>(get_int64(0))) {
                            bpt.pass_count = get_int(6);
                            update_bpt(&bpt);
                            break;
                        } else if (!is_non_null(0)) {
                            bpt.pass_count = get_int(6);
                            update_bpt(&bpt);
                            break;
                        }
                    }
                }
            }

            if (is_non_null(5)) {
                bpt_t bpt;
                int n = get_bpt_qty();
                for (int j = n - 1; j >= 0; --j) {
                    if (getn_bpt(j, &bpt)) {
                        if (is_non_null(0) && bpt.ea == static_cast<ea_t>(get_int64(0))) {
                            bpt.flags = static_cast<uint32>(get_int64(5));
                            update_bpt(&bpt);
                            break;
                        } else if (!is_non_null(0)) {
                            bpt.flags = static_cast<uint32>(get_int64(5));
                            update_bpt(&bpt);
                            break;
                        }
                    }
                }
            }

            if (is_non_null(1)) {
                bool enable = get_int(1) != 0;
                bpt_t bpt;
                int n = get_bpt_qty();
                for (int j = n - 1; j >= 0; --j) {
                    if (getn_bpt(j, &bpt)) {
                        if (is_non_null(0) && bpt.ea == static_cast<ea_t>(get_int64(0))) {
                            enable_bpt(bpt.loc, enable);
                            break;
                        } else if (!is_non_null(0)) {
                            enable_bpt(bpt.loc, enable);
                            break;
                        }
                    }
                }
            }

            if (is_non_null(17)) {
                const char* grp = get_text(17);
                if (grp) {
                    bpt_t bpt;
                    int n = get_bpt_qty();
                    for (int j = n - 1; j >= 0; --j) {
                        if (getn_bpt(j, &bpt)) {
                            if (is_non_null(0) && bpt.ea == static_cast<ea_t>(get_int64(0))) {
                                set_bpt_group(bpt, grp);
                                break;
                            } else if (!is_non_null(0)) {
                                set_bpt_group(bpt, grp);
                                break;
                            }
                        }
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
