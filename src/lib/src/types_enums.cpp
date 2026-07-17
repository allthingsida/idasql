// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_enums.hpp"

namespace idasql {
namespace types {

void collect_enum_values(std::vector<EnumValueEntry>& rows) {
    rows.clear();

    til_t* ti = get_idati();
    if (!ti) return;

    uint32_t max_ord = get_ordinal_limit(ti);
    if (max_ord == 0 || max_ord == uint32_t(-1)) return;

    for (uint32_t ord = 1; ord < max_ord; ++ord) {
        const char* name = get_numbered_type_name(ti, ord);
        if (!name) continue;  // Skip gaps in ordinal space

        tinfo_t tif;
        if (tif.get_numbered_type(ti, ord)) {
            if (tif.is_enum()) {
                enum_type_data_t ei;
                if (tif.get_enum_details(&ei)) {
                    for (size_t i = 0; i < ei.size(); i++) {
                        const edm_t& e = ei[i];
                        EnumValueEntry entry;
                        entry.type_ordinal = ord;
                        entry.type_name = name;
                        entry.value_index = static_cast<int>(i);
                        entry.value_name = e.name.c_str();
                        entry.value = static_cast<int64_t>(e.value);
                        entry.uvalue = e.value;
                        entry.comment = e.cmt.c_str();
                        rows.push_back(std::move(entry));
                    }
                }
            }
        }
    }
}

// ============================================================================
// EnumValuesInTypeIterator
// ============================================================================

EnumValuesInTypeIterator::EnumValuesInTypeIterator(uint32_t ordinal) : type_ordinal_(ordinal) {
    til_t* ti = get_idati();
    if (!ti) return;

    const char* name = get_numbered_type_name(ti, type_ordinal_);
    if (!name) return;
    type_name_ = name;

    tinfo_t tif;
    if (tif.get_numbered_type(ti, type_ordinal_)) {
        if (tif.is_enum()) {
            has_data_ = tif.get_enum_details(&ei_);
        }
    }
}

bool EnumValuesInTypeIterator::next() {
    if (!has_data_) return false;
    ++idx_;
    valid_ = (idx_ >= 0 && static_cast<size_t>(idx_) < ei_.size());
    return valid_;
}

bool EnumValuesInTypeIterator::eof() const {
    return idx_ >= 0 && !valid_;
}

void EnumValuesInTypeIterator::column(xsql::FunctionContext& ctx, int col) {
    if (!valid_ || idx_ < 0 || static_cast<size_t>(idx_) >= ei_.size()) {
        ctx.result_null();
        return;
    }
    const edm_t& e = ei_[idx_];
    switch (col) {
        case 0: ctx.result_int(type_ordinal_); break;
        case 1: ctx.result_text(type_name_.c_str()); break;
        case 2: ctx.result_int(idx_); break;
        case 3: ctx.result_text(e.name.c_str()); break;
        case 4: ctx.result_int64(static_cast<int64_t>(e.value)); break;
        case 5: ctx.result_int64(static_cast<int64_t>(e.value)); break;  // uvalue
        case 6: ctx.result_text(e.cmt.c_str()); break;
        default: ctx.result_null(); break;
    }
}

int64_t EnumValuesInTypeIterator::rowid() const {
    return pack_type_rowid(type_ordinal_, static_cast<int>(idx_));
}

// ============================================================================
// EnumTypeRef
// ============================================================================

EnumTypeRef::EnumTypeRef(uint32_t ord) : valid(false), ordinal(ord) {
    til_t* ti = get_idati();
    if (!ti) return;
    if (tif.get_numbered_type(ti, ord)) {
        if (tif.is_enum()) {
            valid = tif.get_enum_details(&ei);
        }
    }
}

bool EnumTypeRef::save() {
    if (!valid) return false;
    tinfo_t new_tif;
    new_tif.create_enum(ei);
    return new_tif.set_numbered_type(get_idati(), ordinal, NTF_REPLACE, nullptr) == TERR_OK;
}

// ============================================================================
// build_enum_value_entry
// ============================================================================

bool build_enum_value_entry(uint32_t ordinal, int value_index, EnumValueEntry& entry) {
    til_t* ti = get_idati();
    if (!ti) return false;
    const char* type_name = get_numbered_type_name(ti, ordinal);
    if (!type_name) return false;

    tinfo_t tif;
    if (!tif.get_numbered_type(ti, ordinal)) return false;
    if (!tif.is_enum()) return false;

    enum_type_data_t ei;
    if (!tif.get_enum_details(&ei)) return false;
    if (value_index < 0 || static_cast<size_t>(value_index) >= ei.size()) return false;

    const edm_t& e = ei[value_index];
    entry.type_ordinal = ordinal;
    entry.type_name = type_name;
    entry.value_index = value_index;
    entry.value_name = e.name.c_str();
    entry.value = static_cast<int64_t>(e.value);
    entry.uvalue = e.value;
    entry.comment = e.cmt.c_str();
    return true;
}

// Resolve the LIVE index of the enum member identified by `row` against `ref`,
// preferring the cached index only when its name still matches. Mirrors
// resolve_member_index (types_members.cpp): with the pre-mutation snapshot a
// multi-row DELETE/UPDATE hands each handler its scan-time row, but earlier rows
// may have shifted live indices (an erase renumbers the flat edm list), so the
// live member MUST be relocated by name, never by the stale index. Returns -1 and
// sets `error` on not-found/ambiguous.
static int resolve_enum_value_index(const EnumTypeRef& ref, const EnumValueEntry& row,
                                    std::string& error) {
    const std::string ctx = "enum=" + row.type_name +
                            " value_index=" + std::to_string(row.value_index);
    if (!ref.valid) {
        error = "types_enum_values: enum type not found (" + ctx + ")";
        return -1;
    }
    if (row.value_index >= 0 && static_cast<size_t>(row.value_index) < ref.ei.size()
        && ref.ei[row.value_index].name == row.value_name.c_str()) {
        return row.value_index;
    }
    int found = -1;
    for (size_t i = 0; i < ref.ei.size(); ++i) {
        if (ref.ei[i].name == row.value_name.c_str()) {
            if (found != -1) {
                error = "types_enum_values: value name is ambiguous after a layout "
                        "change (" + ctx + ")";
                return -1;
            }
            found = static_cast<int>(i);
        }
    }
    if (found != -1) return found;
    error = "types_enum_values: value '" + row.value_name + "' no longer exists at its "
            "cached position (layout changed?); re-query types_enum_values (" + ctx + ")";
    return -1;
}

// ============================================================================
// TYPES_ENUM_VALUES Table Definition
// ============================================================================

CachedTableDef<EnumValueEntry> define_types_enum_values() {
    return cached_table<EnumValueEntry>("types_enum_values")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            til_t* ti = get_idati();
            return ti ? static_cast<size_t>(get_ordinal_limit(ti)) * 8 : 0;
        })
        .cache_builder([](std::vector<EnumValueEntry>& rows) {
            collect_enum_values(rows);
        })
        .row_populator([](EnumValueEntry& row, int argc, xsql::FunctionArg* argv) {
            if (argc > 2 && !argv[2].is_null()) row.type_ordinal = static_cast<uint32_t>(argv[2].as_int());
            if (argc > 4 && !argv[4].is_null()) row.value_index = argv[4].as_int();
        })
        // Stable rowid = pack_type_rowid(type_ordinal, value_index), matching the
        // iterator (EnumValuesInTypeIterator::rowid) and row_lookup. The
        // full-scan/index cursors and the filtered iterators MUST agree or an
        // unfiltered UPDATE/DELETE reconstructs the wrong value. See the packing
        // note in types_common.hpp.
        .rowid([](const EnumValueEntry& row) -> int64_t {
            return pack_type_rowid(row.type_ordinal, row.value_index);
        })
        .row_lookup([](EnumValueEntry& row, int64_t rowid) -> bool {
            uint32_t ordinal = 0;
            int value_index = 0;
            if (!unpack_type_rowid(rowid, ordinal, value_index)) return false;
            return build_enum_value_entry(ordinal, value_index, row);
        })
        // The packed (ordinal, value_index) rowid shifts when a multi-row DELETE
        // erases an earlier value (the flat edm list renumbers). Opt into the
        // pre-mutation snapshot so each rowid resolves to its scan-time row; the
        // handlers then relocate the live value by name (resolve_enum_value_index).
        .snapshot_mutations()
        .column_int("type_ordinal", [](const EnumValueEntry& row) -> int {
            return static_cast<int>(row.type_ordinal);
        })
        .column_text("type_name", [](const EnumValueEntry& row) -> std::string {
            return row.type_name;
        })
        .column_int("value_index", [](const EnumValueEntry& row) -> int {
            return row.value_index;
        })
        .column_text_rw("value_name",
            [](const EnumValueEntry& row) -> std::string {
                return row.value_name;
            },
            [](EnumValueEntry& row, const char* new_name) -> bool {
                const std::string ctx = "enum=" + row.type_name + " value_index=" + std::to_string(row.value_index);
                EnumTypeRef ref(row.type_ordinal);
                std::string error;
                const int idx = resolve_enum_value_index(ref, row, error);
                if (idx < 0) {
                    xsql::set_vtab_error(error);
                    return false;
                }
                ref.ei[idx].name = new_name ? new_name : "";
                bool ok = ref.save();
                if (ok) row.value_name = new_name ? new_name : "";
                else xsql::set_vtab_error("types_enum_values: failed to save (" + ctx + ")");
                return ok;
            })
        .column_int64_rw("value",
            [](const EnumValueEntry& row) -> int64_t {
                return row.value;
            },
            [](EnumValueEntry& row, int64_t new_value) -> bool {
                const std::string ctx = "enum=" + row.type_name + " value_index=" + std::to_string(row.value_index);
                EnumTypeRef ref(row.type_ordinal);
                std::string error;
                const int idx = resolve_enum_value_index(ref, row, error);
                if (idx < 0) {
                    xsql::set_vtab_error(error);
                    return false;
                }
                ref.ei[idx].value = static_cast<uint64_t>(new_value);
                bool ok = ref.save();
                if (ok) {
                    row.value = new_value;
                    row.uvalue = static_cast<uint64_t>(new_value);
                } else {
                    xsql::set_vtab_error("types_enum_values: failed to save (" + ctx + ")");
                }
                return ok;
            })
        .column_int64("uvalue", [](const EnumValueEntry& row) -> int64_t {
            return static_cast<int64_t>(row.uvalue);
        })
        .column_text_rw("comment",
            [](const EnumValueEntry& row) -> std::string {
                return row.comment;
            },
            [](EnumValueEntry& row, const char* new_comment) -> bool {
                const std::string ctx = "enum=" + row.type_name + " value_index=" + std::to_string(row.value_index);
                EnumTypeRef ref(row.type_ordinal);
                std::string error;
                const int idx = resolve_enum_value_index(ref, row, error);
                if (idx < 0) {
                    xsql::set_vtab_error(error);
                    return false;
                }
                ref.ei[idx].cmt = new_comment ? new_comment : "";
                bool ok = ref.save();
                if (ok) row.comment = new_comment ? new_comment : "";
                else xsql::set_vtab_error("types_enum_values: failed to save (" + ctx + ")");
                return ok;
            })
        .deletable([](EnumValueEntry& row) -> bool {
            const std::string ctx = "enum=" + row.type_name + " value_index=" + std::to_string(row.value_index);
            EnumTypeRef ref(row.type_ordinal);
            std::string error;
            const int idx = resolve_enum_value_index(ref, row, error);
            if (idx < 0) {
                xsql::set_vtab_error(error);
                return false;
            }
            // Delete via the tinfo API rather than erasing from the flat
            // enum_type_data_t + create_enum(): for a bitmask enum the details
            // carry group_sizes (each group must sum to the member count), and an
            // erase+rebuild that never shrinks group_sizes corrupts grouping or
            // fails to save. del_edm keeps the details consistent. Persist the
            // modified tif directly (mirrors the INSERT add_edm path).
            const tinfo_code_t code =
                ref.tif.del_edm(static_cast<size_t>(idx));
            if (code != TERR_OK) {
                xsql::set_vtab_error(
                    "types_enum_values: failed to delete member (" + ctx +
                    ", code=" + std::to_string(static_cast<int>(code)) + ")");
                return false;
            }
            const tinfo_code_t save_code =
                ref.tif.set_numbered_type(get_idati(), ref.ordinal, NTF_REPLACE, nullptr);
            if (save_code != TERR_OK) {
                xsql::set_vtab_error(
                    "types_enum_values: failed to persist delete (" + ctx +
                    ", code=" + std::to_string(static_cast<int>(save_code)) + ")");
                return false;
            }
            return true;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            if (argc < 4
                || argv[0].is_null()
                || argv[3].is_null()) {
                xsql::set_vtab_error(
                    "types_enum_values: INSERT requires type_ordinal and value_name");
                return false;
            }

            uint32_t ordinal = static_cast<uint32_t>(argv[0].as_int());
            const char* value_name = argv[3].as_c_str();
            if (!value_name || !value_name[0]) {
                xsql::set_vtab_error(
                    "types_enum_values: value_name cannot be empty (type_ordinal=" +
                    std::to_string(ordinal) + ")");
                return false;
            }

            EnumTypeRef ref(ordinal);
            if (!ref.valid) {
                xsql::set_vtab_error(
                    "types_enum_values: enum type ordinal not found or is not an enum: " +
                    std::to_string(ordinal));
                return false;
            }

            const bool is_bitmask = ref.tif.is_bitmask_enum();

            edm_t new_edm;
            new_edm.name = value_name;
            if (argc > 4 && !argv[4].is_null()) {
                new_edm.value = static_cast<uint64_t>(argv[4].as_int64());
            } else if (is_bitmask) {
                // Bitmask enums treat each member value as its own single-bit mask
                // (DEFMASK64 below). 0 is an invalid mask and a sequential back()+1
                // isn't a clean power of two, so pick the lowest unused single bit --
                // bounded to the enum's declared byte width (types.size): a 1-byte
                // bitmask only has bits 0x01..0x80, so we must not invent 0x100.
                uint64_t used = 0;
                for (size_t i = 0; i < ref.ei.size(); i++) used |= ref.ei[i].value;
                const size_t ebytes = ref.tif.get_size();
                const uint64_t width_mask =
                    (ebytes == 0 || ebytes == BADSIZE || ebytes >= 8)
                        ? ~uint64_t(0)
                        : ((uint64_t(1) << (ebytes * 8)) - 1);
                uint64_t mask = 1;
                while (mask != 0 && ((used & mask) != 0 || (mask & width_mask) == 0))
                    mask <<= 1;
                if (mask == 0 || (mask & width_mask) == 0) {
                    xsql::set_vtab_error(
                        "types_enum_values: no free single-bit mask remains within the "
                        "enum width; widen types.size or specify an explicit value "
                        "(type_ordinal=" + std::to_string(ordinal) + ")");
                    return false;
                }
                new_edm.value = mask;
            } else if (!ref.ei.empty()) {
                new_edm.value = ref.ei.back().value + 1;
            } else {
                new_edm.value = 0;
            }
            if (argc > 6 && !argv[6].is_null()) {
                const char* cmt = argv[6].as_c_str();
                if (cmt) new_edm.cmt = cmt;
            }

            // On a bitmask enum, add the member via add_edm so IDA forms the
            // bitmask group. DEFMASK64 means "the member's value is its own mask"
            // (flat flag) -- the common case.
            if (is_bitmask) {
                const tinfo_code_t code = ref.tif.add_edm(new_edm, DEFMASK64);
                if (code != TERR_OK) {
                    xsql::set_vtab_error(
                        "types_enum_values: failed to add bitmask member '" +
                        std::string(value_name) + "' (type_ordinal=" +
                        std::to_string(ordinal) + ", code=" +
                        std::to_string(static_cast<int>(code)) + ")");
                    return false;
                }
                // add_edm mutates the in-memory tinfo only; persist it back to the
                // IDB under the same ordinal. We must NOT call ref.save() here: it
                // rebuilds the type from ref.ei (the flat enum_type_data_t), which
                // the bitmask branch never updated, so it would clobber the new
                // member. Write the modified tif directly instead.
                const tinfo_code_t save_code =
                    ref.tif.set_numbered_type(get_idati(), ref.ordinal, NTF_REPLACE, nullptr);
                if (save_code != TERR_OK) {
                    xsql::set_vtab_error(
                        "types_enum_values: failed to persist bitmask member '" +
                        std::string(value_name) + "' (type_ordinal=" +
                        std::to_string(ordinal) + ", code=" +
                        std::to_string(static_cast<int>(save_code)) + ")");
                    return false;
                }
                return true;
            }

            ref.ei.push_back(new_edm);
            return ref.save();
        })
        .filter_eq("type_ordinal", [](int64_t ordinal) -> std::unique_ptr<xsql::RowIterator> {
            // Type ordinals are uint32; reject anything out of range rather than
            // truncating (e.g. 4294967297 -> 1 would return ordinal-1's members).
            // Ordinal 0 is always a gap, so the iterator yields no rows.
            if (ordinal <= 0 || ordinal > static_cast<int64_t>(UINT32_MAX))
                return std::make_unique<EnumValuesInTypeIterator>(0u);
            return std::make_unique<EnumValuesInTypeIterator>(static_cast<uint32_t>(ordinal));
        }, 10.0, 10.0)
        .build();
}

} // namespace types
} // namespace idasql
