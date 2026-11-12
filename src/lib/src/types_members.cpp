// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_members.hpp"

#include "types_gaps.hpp"
#include "address_resolution.hpp"

#include <climits>

#include <algorithm>
#include <cctype>
#include <limits>

namespace idasql {
namespace types {

namespace {

std::string trim_copy(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(),
        [](unsigned char c) { return std::isspace(c) != 0; });
    const auto last = std::find_if_not(value.rbegin(), value.rend(),
        [](unsigned char c) { return std::isspace(c) != 0; }).base();
    if (first >= last) {
        return {};
    }
    return std::string(first, last);
}

uint64_t type_size_bits(const tinfo_t& tif) {
    const size_t size = tif.get_size();
    if (size == BADSIZE) {
        return 0;
    }
    return static_cast<uint64_t>(size) * 8;
}

std::string tinfo_to_string(const tinfo_t& tif) {
    qstring out;
    tif.print(&out);
    return out.c_str();
}

std::string member_context(const MemberEntry& row) {
    return "type=" + row.type_name + " ordinal=" + std::to_string(row.type_ordinal) +
           " member_index=" + std::to_string(row.member_index) +
           " member=" + row.member_name;
}

std::string type_error_text(tinfo_code_t code) {
    const char* text = tinfo_errstr(code);
    if (text && text[0]) {
        return std::string(text) + " (" + std::to_string(static_cast<int>(code)) + ")";
    }
    return std::to_string(static_cast<int>(code));
}

bool parse_nonnegative_int64(xsql::FunctionArg arg, const char* column, int64_t& out) {
    const auto v = idasql::write_int(arg, "types_members", column, INT64_MIN, INT64_MAX);
    if (!v) return false;
    out = *v;
    if (out < 0) {
        xsql::set_vtab_error(std::string("types_members: ") + column + " cannot be negative");
        return false;
    }
    return true;
}

bool move_member_offset(TypeMemberRef& ref, const MemberEntry& row, int idx, uint64_t new_bits) {
    if (new_bits == static_cast<uint64_t>(row.offset_bits)) {
        return true;
    }

    if (ref.tif.is_union()) {
        if (new_bits == 0) {
            return true;
        }
        xsql::set_vtab_error("types_members: union member offsets must be zero (" + member_context(row) + ")");
        return false;
    }

    if ((new_bits % 8) != 0 || (row.offset_bits % 8) != 0) {
        xsql::set_vtab_error("types_members: offset_bits updates currently require byte alignment (" +
                              member_context(row) + ")");
        return false;
    }

    if (idx < 0 || static_cast<size_t>(idx) >= ref.udt.size()) {
        xsql::set_vtab_error("types_members: member index out of range (" + member_context(row) + ")");
        return false;
    }
    const udm_t moved = ref.udt[idx];
    const uint64_t old_bits = static_cast<uint64_t>(moved.offset);
    const uint64_t size_bits = moved.size;
    const uint64_t end_bits = new_bits + size_bits;

    auto overlaps_other = [&](uint64_t lo, uint64_t hi) -> bool {
        if (hi <= old_bits || lo >= old_bits + size_bits) {
            return range_overlaps_member(ref.ordinal, lo, hi);
        }
        if (lo < old_bits && range_overlaps_member(ref.ordinal, lo, old_bits)) {
            return true;
        }
        if (hi > old_bits + size_bits
            && range_overlaps_member(ref.ordinal, old_bits + size_bits, hi)) {
            return true;
        }
        return false;
    };
    if (size_bits > 0 && overlaps_other(new_bits, end_bits)) {
        xsql::set_vtab_error(
            "types_members: offset range overlaps an existing member; move into a gap "
            "(see type_gaps) or pick a free offset (" + member_context(row) + ")");
        return false;
    }

    const tinfo_code_t fixed_code = ref.tif.set_fixed_struct(true);
    if (fixed_code != TERR_OK) {
        xsql::set_vtab_error("types_members: failed to make struct layout fixed (" +
                              member_context(row) + ", code=" + type_error_text(fixed_code) + ")");
        return false;
    }

    const size_t old_size = ref.tif.get_size();

    const tinfo_code_t del_code = idasql_udt_del_udm(ref.tif, static_cast<size_t>(idx));
    if (del_code != TERR_OK) {
        xsql::set_vtab_error("types_members: failed to move member offset (delete step: " +
                              member_context(row) + ", code=" + type_error_text(del_code) + ")");
        return false;
    }

    udm_t placed = moved;
    placed.offset = new_bits;
    const tinfo_code_t add_code = idasql_udt_add_udm(ref.tif, placed, ETF_MAY_DESTROY, 1, -1);
    if (add_code != TERR_OK) {
        udm_t restore = moved;
        restore.offset = old_bits;
        const tinfo_code_t restore_code = idasql_udt_add_udm(ref.tif, restore, ETF_MAY_DESTROY, 1, -1);
        if (restore_code != TERR_OK) {
            xsql::set_vtab_error(
                "types_members: move failed and rollback ALSO failed; struct may be "
                "missing the member (" + member_context(row) +
                ", move code=" + type_error_text(add_code) +
                ", rollback code=" + type_error_text(restore_code) + ")");
            return false;
        }
        if (old_size != BADSIZE && ref.tif.get_size() != old_size) {
            ref.tif.set_struct_size(old_size);
        }
        xsql::set_vtab_error("types_members: failed to move member offset (insert step: " +
                              member_context(row) + ", code=" + type_error_text(add_code) + ")");
        return false;
    }

    if (old_size != BADSIZE && ref.tif.get_size() != old_size) {
        ref.tif.set_struct_size(old_size);
    }
    return true;
}

}

std::string make_type_declarator(const std::string& type_text, const char* var_name) {
    std::string base = trim_copy(type_text);
    std::string array_suffixes;

    while (!base.empty()) {
        base = trim_copy(base);
        if (base.empty() || base.back() != ']') {
            break;
        }

        int depth = 0;
        size_t open = std::string::npos;
        for (size_t i = base.size(); i > 0; --i) {
            const char ch = base[i - 1];
            if (ch == ']') {
                ++depth;
            } else if (ch == '[') {
                --depth;
                if (depth == 0) {
                    open = i - 1;
                    break;
                }
            }
        }
        if (open == std::string::npos) {
            break;
        }

        array_suffixes = trim_copy(base.substr(open)) + array_suffixes;
        base = trim_copy(base.substr(0, open));
    }

    if (base.empty()) {
        return {};
    }
    return base + " " + var_name + array_suffixes + ";";
}

bool parse_type_declarator(const std::string& type_text, tinfo_t& out_type, std::string& error,
                           const char* what) {
    const std::string label = (what && what[0]) ? what : "type";
    const std::string trimmed = trim_copy(type_text);
    if (trimmed.empty()) {
        error = label + " cannot be empty";
        return false;
    }

    tinfo_t parsed_type;
    qstring parsed_name;
    const std::string decl = make_type_declarator(trimmed);
    if (decl.empty()
        || !parse_decl(&parsed_type, &parsed_name, nullptr, decl.c_str(), PT_SIL | PT_VAR)) {
        const std::string type_only = trimmed.back() == ';' ? trimmed : trimmed + ";";
        tinfo_t fallback_type;
        if (!fallback_type.parse(type_only.c_str(), nullptr, PT_SIL | PT_TYP)) {
            error = "failed to parse " + label + " '" + trimmed + "'";
            return false;
        }
        out_type = fallback_type;
    } else {
        out_type = parsed_type;
    }

    if (out_type.empty()) {
        error = label + " parsed to an empty type: '" + trimmed + "'";
        return false;
    }

    const size_t size = out_type.get_size();
    if (size == BADSIZE) {
        error = label + " has unknown size: '" + trimmed + "'";
        return false;
    }
    return true;
}

int resolve_member_index(const TypeMemberRef& ref, const MemberEntry& row, std::string& error) {
    if (!ref.valid) {
        error = "types_members: type not found (" + member_context(row) + ")";
        return -1;
    }

    if (row.member_index >= 0 && static_cast<size_t>(row.member_index) < ref.udt.size()
        && ref.udt[row.member_index].name == row.member_name.c_str()) {
        return row.member_index;
    }

    int found = -1;
    for (size_t i = 0; i < ref.udt.size(); ++i) {
        if (ref.udt[i].name == row.member_name.c_str()) {
            if (found != -1) {
                error = "types_members: member name is ambiguous after layout change (" +
                        member_context(row) + ")";
                return -1;
            }
            found = static_cast<int>(i);
        }
    }

    if (found != -1) {
        return found;
    }

    error = "types_members: member '" + row.member_name + "' no longer exists at its "
            "cached position (layout changed?); re-query types_members (" +
            member_context(row) + ")";
    return -1;
}

int get_type_ordinal_by_name(til_t* ti, const char* type_name) {
    if (!ti || !type_name || !type_name[0]) return -1;
    uint32_t ord = get_type_ordinal(ti, type_name);
    return (ord != 0) ? static_cast<int>(ord) : -1;
}

void classify_member_type(const tinfo_t& mtype, til_t* ti,
                          bool& is_struct, bool& is_union, bool& is_enum,
                          bool& is_ptr, bool& is_array, int& type_ordinal) {
    is_struct = false;
    is_union = false;
    is_enum = false;
    is_ptr = mtype.is_ptr();
    is_array = mtype.is_array();
    type_ordinal = -1;

    tinfo_t base_type = mtype;
    if (mtype.is_ptr()) {
        base_type = mtype.get_pointed_object();
    } else if (mtype.is_array()) {
        base_type = mtype.get_array_element();
    }

    is_struct = base_type.is_struct();
    is_union = base_type.is_union();
    is_enum = base_type.is_enum();

    qstring type_name;
    if (base_type.get_type_name(&type_name) && !type_name.empty()) {
        type_ordinal = get_type_ordinal_by_name(ti, type_name.c_str());
    }
}

void collect_members(std::vector<MemberEntry>& rows) {
    rows.clear();

    til_t* ti = get_idati();
    if (!ti) return;

    uint32_t max_ord = get_ordinal_limit(ti);
    if (max_ord == 0 || max_ord == uint32_t(-1)) return;

    for (uint32_t ord = 1; ord < max_ord; ++ord) {
        const char* name = get_numbered_type_name(ti, ord);
        if (!name) continue;

        tinfo_t tif;
        if (tif.get_numbered_type(ti, ord)) {
            if (tif.is_struct() || tif.is_union()) {
                udt_type_data_t udt;
                if (tif.get_udt_details(&udt)) {
                    for (size_t i = 0; i < udt.size(); i++) {
                        const udm_t& m = udt[i];
                        MemberEntry entry;
                        entry.type_ordinal = ord;
                        entry.type_name = name;
                        entry.member_index = static_cast<int>(i);
                        entry.member_name = m.name.c_str();
                        entry.offset = static_cast<int64_t>(m.offset / 8);
                        entry.offset_bits = static_cast<int64_t>(m.offset);
                        entry.size = static_cast<int64_t>(m.size / 8);
                        entry.size_bits = static_cast<int64_t>(m.size);
                        entry.is_bitfield = m.is_bitfield();
                        entry.is_baseclass = m.is_baseclass();
                        entry.is_gap = m.is_gap();
                        entry.comment = m.cmt.c_str();

                        qstring type_str;
                        m.type.print(&type_str);
                        entry.member_type = type_str.c_str();

                        classify_member_type(m.type, ti,
                            entry.mt_is_struct, entry.mt_is_union, entry.mt_is_enum,
                            entry.mt_is_ptr, entry.mt_is_array, entry.member_type_ordinal);

                        rows.push_back(std::move(entry));
                    }
                }
            }
        }
    }
}

MembersInTypeIterator::MembersInTypeIterator(uint32_t ordinal) : type_ordinal_(ordinal) {
    til_t* ti = get_idati();
    if (!ti) return;

    const char* name = get_numbered_type_name(ti, type_ordinal_);
    if (!name) return;
    type_name_ = name;

    tinfo_t tif;
    if (tif.get_numbered_type(ti, type_ordinal_)) {
        if (tif.is_struct() || tif.is_union()) {
            has_data_ = tif.get_udt_details(&udt_);
        }
    }
}

bool MembersInTypeIterator::next() {
    if (!has_data_) return false;
    ++idx_;
    valid_ = (idx_ >= 0 && static_cast<size_t>(idx_) < udt_.size());
    return valid_;
}

bool MembersInTypeIterator::eof() const {
    return idx_ >= 0 && !valid_;
}

void MembersInTypeIterator::column(xsql::FunctionContext& ctx, int col) {
    if (!valid_ || idx_ < 0 || static_cast<size_t>(idx_) >= udt_.size()) {
        ctx.result_null();
        return;
    }
    const udm_t& m = udt_[idx_];
    switch (col) {
        case 0: ctx.result_int(type_ordinal_); break;
        case 1: ctx.result_text(type_name_.c_str()); break;
        case 2: ctx.result_int(idx_); break;
        case 3: ctx.result_text(m.name.c_str()); break;
        case 4: ctx.result_int64(static_cast<int64_t>(m.offset / 8)); break;
        case 5: ctx.result_int64(static_cast<int64_t>(m.offset)); break;
        case 6: ctx.result_int64(static_cast<int64_t>(m.size / 8)); break;
        case 7: ctx.result_int64(static_cast<int64_t>(m.size)); break;
        case 8: {
            qstring type_str;
            m.type.print(&type_str);
            ctx.result_text(type_str.c_str());
            break;
        }
        case 9: ctx.result_int(m.is_bitfield() ? 1 : 0); break;
        case 10: ctx.result_int(m.is_baseclass() ? 1 : 0); break;
        case 11: ctx.result_text(m.cmt.c_str()); break;
        case 12: case 13: case 14: case 15: case 16: case 17: {
            bool mt_is_struct, mt_is_union, mt_is_enum, mt_is_ptr, mt_is_array;
            int mt_ordinal;
            classify_member_type(m.type, get_idati(),
                mt_is_struct, mt_is_union, mt_is_enum,
                mt_is_ptr, mt_is_array, mt_ordinal);
            switch (col) {
                case 12: ctx.result_int(mt_is_struct ? 1 : 0); break;
                case 13: ctx.result_int(mt_is_union ? 1 : 0); break;
                case 14: ctx.result_int(mt_is_enum ? 1 : 0); break;
                case 15: ctx.result_int(mt_is_ptr ? 1 : 0); break;
                case 16: ctx.result_int(mt_is_array ? 1 : 0); break;
                case 17: ctx.result_int(mt_ordinal); break;
            }
            break;
        }
        case 18: ctx.result_int(m.is_gap() ? 1 : 0); break;
        default: ctx.result_null(); break;
    }
}

int64_t MembersInTypeIterator::rowid() const {
    return pack_type_rowid(type_ordinal_, static_cast<int>(idx_));
}

TypeMemberRef::TypeMemberRef(uint32_t ord) : valid(false), ordinal(ord) {
    til_t* ti = get_idati();
    if (!ti) return;
    if (tif.get_numbered_type(ti, ord)) {
        if (tif.is_struct() || tif.is_union()) {
            valid = tif.get_udt_details(&udt);
        }
    }
}

bool build_member_entry(uint32_t ordinal, int member_index, MemberEntry& entry) {
    til_t* ti = get_idati();
    if (!ti) return false;

    const char* type_name = get_numbered_type_name(ti, ordinal);
    if (!type_name) return false;

    tinfo_t tif;
    if (!tif.get_numbered_type(ti, ordinal)) return false;
    if (!(tif.is_struct() || tif.is_union())) return false;

    udt_type_data_t udt;
    if (!tif.get_udt_details(&udt)) return false;
    if (member_index < 0 || static_cast<size_t>(member_index) >= udt.size()) return false;

    const udm_t& m = udt[member_index];
    entry.type_ordinal = ordinal;
    entry.type_name = type_name;
    entry.member_index = member_index;
    entry.member_name = m.name.c_str();
    entry.offset = static_cast<int64_t>(m.offset / 8);
    entry.offset_bits = static_cast<int64_t>(m.offset);
    entry.size = static_cast<int64_t>(m.size / 8);
    entry.size_bits = static_cast<int64_t>(m.size);
    entry.is_bitfield = m.is_bitfield();
    entry.is_baseclass = m.is_baseclass();
    entry.is_gap = m.is_gap();
    entry.comment = m.cmt.c_str();

    qstring type_str;
    m.type.print(&type_str);
    entry.member_type = type_str.c_str();

    classify_member_type(m.type, ti,
        entry.mt_is_struct, entry.mt_is_union, entry.mt_is_enum,
        entry.mt_is_ptr, entry.mt_is_array, entry.member_type_ordinal);
    return true;
}

CachedTableDef<MemberEntry> define_types_members() {
    return cached_table<MemberEntry>("types_members")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            til_t* ti = get_idati();
            return ti ? static_cast<size_t>(get_ordinal_limit(ti)) * 8 : 0;
        })
        .cache_builder([](std::vector<MemberEntry>& rows) {
            collect_members(rows);
        })
        .row_populator([](MemberEntry& row, int argc, xsql::FunctionArg* argv) {
            if (argc > 2 && !argv[2].is_null()) row.type_ordinal = static_cast<uint32_t>(argv[2].as_int());
            if (argc > 4 && !argv[4].is_null()) row.member_index = argv[4].as_int();
        })
        .rowid([](const MemberEntry& row) -> int64_t {
            return pack_type_rowid(row.type_ordinal, row.member_index);
        })
        .row_lookup([](MemberEntry& row, int64_t rowid) -> bool {
            uint32_t ordinal = 0;
            int member_index = 0;
            if (!unpack_type_rowid(rowid, ordinal, member_index)) return false;
            return build_member_entry(ordinal, member_index, row);
        })
        .snapshot_mutations()
        .column_int("type_ordinal", [](const MemberEntry& row) -> int {
            return static_cast<int>(row.type_ordinal);
        })
        .column_text("type_name", [](const MemberEntry& row) -> std::string {
            return row.type_name;
        })
        .column_int("member_index", [](const MemberEntry& row) -> int {
            return row.member_index;
        })
        .column_text_rw("member_name",
            [](const MemberEntry& row) -> std::string {
                return row.member_name;
            },
            [](MemberEntry& row, const char* new_name) -> bool {
                const std::string ctx = "type=" + row.type_name + " member=" + std::to_string(row.member_index);
                TypeMemberRef ref(row.type_ordinal);
                if (!ref.valid) {
                    xsql::set_vtab_error("types_members: type not found (" + ctx + ")");
                    return false;
                }
                const char* requested = new_name ? new_name : "";
                if (requested == row.member_name) {
                    return true;
                }

                std::string error;
                const int idx = resolve_member_index(ref, row, error);
                if (idx < 0) {
                    xsql::set_vtab_error(error);
                    return false;
                }

                tinfo_code_t code = ref.tif.rename_udm(static_cast<size_t>(idx), requested);
                bool ok = code == TERR_OK;
                if (ok) row.member_name = new_name ? new_name : "";
                else xsql::set_vtab_error("types_members: failed to rename member (" + ctx +
                                          ", code=" + type_error_text(code) + ")");
                return ok;
            })
        .column_int64_rw("offset",
            [](const MemberEntry& row) -> int64_t {
                return row.offset;
            },
            [](MemberEntry& row, int64_t new_offset) -> bool {
                if (new_offset < 0) {
                    xsql::set_vtab_error("types_members: offset cannot be negative (" + member_context(row) + ")");
                    return false;
                }
                if (new_offset > std::numeric_limits<int64_t>::max() / 8) {
                    xsql::set_vtab_error("types_members: offset is too large (" + member_context(row) + ")");
                    return false;
                }
                const int64_t new_bits = new_offset * 8;
                if (new_bits == row.offset_bits) {
                    return true;
                }

                TypeMemberRef ref(row.type_ordinal);
                std::string error;
                const int idx = resolve_member_index(ref, row, error);
                if (idx < 0) {
                    xsql::set_vtab_error(error);
                    return false;
                }

                bool ok = move_member_offset(ref, row, idx, static_cast<uint64_t>(new_bits));
                if (ok) {
                    row.offset = new_offset;
                    row.offset_bits = new_bits;
                }
                return ok;
            })
        .column_int64_rw("offset_bits",
            [](const MemberEntry& row) -> int64_t {
                return row.offset_bits;
            },
            [](MemberEntry& row, int64_t new_bits) -> bool {
                if (new_bits < 0) {
                    xsql::set_vtab_error("types_members: offset_bits cannot be negative (" + member_context(row) + ")");
                    return false;
                }
                if (new_bits == row.offset_bits) {
                    return true;
                }

                TypeMemberRef ref(row.type_ordinal);
                std::string error;
                const int idx = resolve_member_index(ref, row, error);
                if (idx < 0) {
                    xsql::set_vtab_error(error);
                    return false;
                }

                bool ok = move_member_offset(ref, row, idx, static_cast<uint64_t>(new_bits));
                if (ok) {
                    row.offset_bits = new_bits;
                    row.offset = new_bits / 8;
                }
                return ok;
            })
        .column_int64("size", [](const MemberEntry& row) -> int64_t {
            return row.size;
        })
        .column_int64("size_bits", [](const MemberEntry& row) -> int64_t {
            return row.size_bits;
        })
        .column_text_rw("member_type",
            [](const MemberEntry& row) -> std::string {
                return row.member_type;
            },
            [](MemberEntry& row, const char* new_type_text) -> bool {
                const std::string requested = new_type_text ? new_type_text : "";
                if (requested == row.member_type) {
                    return true;
                }

                tinfo_t new_type;
                std::string parse_error;
                if (!parse_type_declarator(requested, new_type, parse_error, "member_type")) {
                    xsql::set_vtab_error("types_members: " + parse_error + " (" + member_context(row) + ")");
                    return false;
                }

                TypeMemberRef ref(row.type_ordinal);
                std::string error;
                const int idx = resolve_member_index(ref, row, error);
                if (idx < 0) {
                    xsql::set_vtab_error(error);
                    return false;
                }

                tinfo_code_t code = ref.tif.set_udm_type(static_cast<size_t>(idx), new_type);
                const bool ok = code == TERR_OK;
                if (ok) {
                    row.member_type = tinfo_to_string(new_type);
                    row.size_bits = static_cast<int64_t>(type_size_bits(new_type));
                    row.size = row.size_bits / 8;
                    classify_member_type(new_type, get_idati(),
                        row.mt_is_struct, row.mt_is_union, row.mt_is_enum,
                        row.mt_is_ptr, row.mt_is_array, row.member_type_ordinal);
                } else {
                    xsql::set_vtab_error("types_members: failed to set member_type (" +
                                          member_context(row) + ", code=" + type_error_text(code) + ")");
                }
                return ok;
            })
        .column_int("is_bitfield", [](const MemberEntry& row) -> int {
            return row.is_bitfield ? 1 : 0;
        })
        .column_int("is_baseclass", [](const MemberEntry& row) -> int {
            return row.is_baseclass ? 1 : 0;
        })
        .column_text_rw("comment",
            [](const MemberEntry& row) -> std::string {
                return row.comment;
            },
            [](MemberEntry& row, const char* new_comment) -> bool {
                const std::string ctx = "type=" + row.type_name + " member=" + std::to_string(row.member_index);
                TypeMemberRef ref(row.type_ordinal);
                if (!ref.valid) {
                    xsql::set_vtab_error("types_members: type not found (" + ctx + ")");
                    return false;
                }
                const char* requested = new_comment ? new_comment : "";
                if (requested == row.comment) {
                    return true;
                }

                std::string error;
                const int idx = resolve_member_index(ref, row, error);
                if (idx < 0) {
                    xsql::set_vtab_error(error);
                    return false;
                }

                tinfo_code_t code = ref.tif.set_udm_cmt(static_cast<size_t>(idx), requested);
                bool ok = code == TERR_OK;
                if (ok) row.comment = new_comment ? new_comment : "";
                else xsql::set_vtab_error("types_members: failed to set comment (" + ctx +
                                          ", code=" + type_error_text(code) + ")");
                return ok;
            })
        .column_int("mt_is_struct", [](const MemberEntry& row) -> int {
            return row.mt_is_struct ? 1 : 0;
        })
        .column_int("mt_is_union", [](const MemberEntry& row) -> int {
            return row.mt_is_union ? 1 : 0;
        })
        .column_int("mt_is_enum", [](const MemberEntry& row) -> int {
            return row.mt_is_enum ? 1 : 0;
        })
        .column_int("mt_is_ptr", [](const MemberEntry& row) -> int {
            return row.mt_is_ptr ? 1 : 0;
        })
        .column_int("mt_is_array", [](const MemberEntry& row) -> int {
            return row.mt_is_array ? 1 : 0;
        })
        .column_int("member_type_ordinal", [](const MemberEntry& row) -> int {
            return row.member_type_ordinal;
        })
        .column_int("is_gap", [](const MemberEntry& row) -> int {
            return row.is_gap ? 1 : 0;
        })
        .deletable([](MemberEntry& row) -> bool {
            TypeMemberRef ref(row.type_ordinal);
            std::string error;
            const int idx = resolve_member_index(ref, row, error);
            if (idx < 0) {
                xsql::set_vtab_error(error);
                return false;
            }
            const bool fixed = !ref.tif.is_union() && ref.tif.is_fixed_struct();
            const size_t old_size = ref.tif.get_size();

            const tinfo_code_t code = idasql_udt_del_udm(ref.tif, static_cast<size_t>(idx));
            if (code != TERR_OK) {
                xsql::set_vtab_error("types_members: failed to delete member (" +
                                      member_context(row) + ", code=" + type_error_text(code) + ")");
                return false;
            }
            if (fixed && old_size != BADSIZE && ref.tif.get_size() != old_size) {
                ref.tif.set_struct_size(old_size);
            }
            return true;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            if (argc < 4
                || argv[0].is_null()
                || argv[3].is_null())
                return false;

            const auto ord = idasql::write_int(argv[0], "types_members", "type_ordinal", 1, UINT32_MAX);
            if (!ord) return false;
            uint32_t ordinal = static_cast<uint32_t>(*ord);
            const char* member_name = argv[3].as_c_str();
            if (!member_name || !member_name[0]) {
                xsql::set_vtab_error("types_members: INSERT needs a member_name");
                return false;
            }

            TypeMemberRef ref(ordinal);
            if (!ref.valid) {
                xsql::set_vtab_error("types_members: type ordinal not found or is not a struct/union: " +
                                      std::to_string(ordinal));
                return false;
            }

            std::string type_str = "int";
            if (argc > 8 && !argv[8].is_null()) {
                const char* mt = argv[8].as_c_str();
                if (mt && mt[0]) type_str = mt;
            }

            tinfo_t member_type;
            std::string parse_error;
            if (!parse_type_declarator(type_str, member_type, parse_error, "member_type")) {
                xsql::set_vtab_error("types_members: " + parse_error + " (type_ordinal=" +
                                      std::to_string(ordinal) + " member=" + member_name + ")");
                return false;
            }

            uint64_t offset_bits = 0;
            bool explicit_offset = false;
            if (argc > 5 && !argv[5].is_null()) {
                int64_t bits = 0;
                if (!parse_nonnegative_int64(argv[5], "offset_bits", bits)) {
                    return false;
                }
                offset_bits = static_cast<uint64_t>(bits);
                explicit_offset = true;
            } else if (argc > 4 && !argv[4].is_null()) {
                int64_t bytes = 0;
                if (!parse_nonnegative_int64(argv[4], "offset", bytes)) {
                    return false;
                }
                if (bytes > std::numeric_limits<int64_t>::max() / 8) {
                    xsql::set_vtab_error("types_members: offset is too large");
                    return false;
                }
                offset_bits = static_cast<uint64_t>(bytes) * 8;
                explicit_offset = true;
            } else if (!ref.tif.is_union()) {
                for (const udm_t& m : ref.udt) {
                    offset_bits = std::max<uint64_t>(offset_bits, m.offset + m.size);
                }
            }

            udm_t new_member;
            new_member.offset = offset_bits;
            new_member.size = type_size_bits(member_type);
            new_member.name = member_name;
            new_member.type = member_type;
            if (argc > 11 && !argv[11].is_null()) {
                const char* cmt = argv[11].as_c_str();
                if (cmt) new_member.cmt = cmt;
            }

            ssize_t insert_index = -1;
            if (argc > 2 && !argv[2].is_null()) {
                const auto exact = idasql::write_int(argv[2], "types_members", "member_index", INT64_MIN, INT_MAX);
                if (!exact) return false;
                const int idx = static_cast<int>(*exact);
                if (idx < 0) {
                    xsql::set_vtab_error("types_members: member_index cannot be negative on INSERT");
                    return false;
                }
                insert_index = static_cast<ssize_t>(idx);
            }

            const bool fixed = !ref.tif.is_union() && ref.tif.is_fixed_struct();
            uint etf_flags = 0;
            if (fixed && explicit_offset) {
                const size_t member_bytes = member_type.get_size();
                const uint64_t size_bits = (member_bytes == 0 || member_bytes == BADSIZE)
                    ? 8u
                    : static_cast<uint64_t>(member_bytes) * 8;
                if (range_overlaps_member(ordinal, offset_bits, offset_bits + size_bits)) {
                    xsql::set_vtab_error(
                        "types_members: offset range overlaps an existing member; insert "
                        "into a gap (see type_gaps) or omit offset to append (type_ordinal=" +
                        std::to_string(ordinal) + " member=" + member_name + ")");
                    return false;
                }
                etf_flags = ETF_MAY_DESTROY;
            }
            const size_t old_size = ref.tif.get_size();

            const tinfo_code_t code = idasql_udt_add_udm(ref.tif, new_member, etf_flags, 1, insert_index);
            if (code != TERR_OK) {
                xsql::set_vtab_error("types_members: failed to insert member (type_ordinal=" +
                                      std::to_string(ordinal) + " member=" + member_name +
                                      ", code=" + type_error_text(code) + ")");
                return false;
            }
            if (fixed && old_size != BADSIZE && ref.tif.get_size() != old_size) {
                ref.tif.set_struct_size(old_size);
            }
            return true;
        })
        .filter_eq("type_ordinal", [](int64_t ordinal) -> std::unique_ptr<xsql::RowIterator> {
            if (ordinal <= 0 || ordinal > static_cast<int64_t>(UINT32_MAX))
                return std::make_unique<MembersInTypeIterator>(0u);
            return std::make_unique<MembersInTypeIterator>(static_cast<uint32_t>(ordinal));
        }, 10.0, 5.0)
        .build();
}

}
}
