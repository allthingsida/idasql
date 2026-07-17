// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_applied.hpp"

#include "address_resolution.hpp"
#include "decompiler.hpp"

namespace idasql {
namespace types {

namespace {

enum class AppliedTypeOrder { Asc, Desc };

struct AppliedTypeBounds {
    bool has_lower = false;
    ea_t lower = 0;
    bool lower_inclusive = true;
    bool has_upper = false;
    ea_t upper = 0;
    bool upper_inclusive = true;
};

bool applied_type_within_bounds(ea_t ea, const AppliedTypeBounds& bounds) {
    if (ea == BADADDR) return false;
    if (bounds.has_lower &&
        (ea < bounds.lower || (ea == bounds.lower && !bounds.lower_inclusive))) {
        return false;
    }
    if (bounds.has_upper &&
        (ea > bounds.upper || (ea == bounds.upper && !bounds.upper_inclusive))) {
        return false;
    }
    return true;
}

bool address_has_applied_type(ea_t ea) {
    tinfo_t tif;
    return ea != BADADDR && get_tinfo(&tif, ea);
}

bool is_mapped_address(ea_t ea) {
    return ea != BADADDR && is_mapped(ea);
}

void tighten_applied_lower(AppliedTypeBounds& bounds, ea_t ea, bool inclusive) {
    if (!bounds.has_lower || ea > bounds.lower ||
        (ea == bounds.lower && !inclusive && bounds.lower_inclusive)) {
        bounds.has_lower = true;
        bounds.lower = ea;
        bounds.lower_inclusive = inclusive;
    }
}

void tighten_applied_upper(AppliedTypeBounds& bounds, ea_t ea, bool inclusive) {
    if (!bounds.has_upper || ea < bounds.upper ||
        (ea == bounds.upper && !inclusive && bounds.upper_inclusive)) {
        bounds.has_upper = true;
        bounds.upper = ea;
        bounds.upper_inclusive = inclusive;
    }
}

class AppliedTypesGenerator : public xsql::Generator<AppliedTypeEntry> {
    AppliedTypeOrder order_;
    AppliedTypeBounds bounds_;
    bool include_untyped_point_ = false;
    bool started_ = false;
    ea_t current_ea_ = BADADDR;
    mutable AppliedTypeEntry row_{BADADDR};

    ea_t first_ascending() const {
        const ea_t max_ea = inf_get_max_ea();
        ea_t start = bounds_.has_lower ? bounds_.lower : inf_get_min_ea();
        if (start == BADADDR || start >= max_ea) return BADADDR;
        if (bounds_.has_lower && !bounds_.lower_inclusive) {
            start = next_head(start, max_ea);
        } else if (!is_head(get_flags(start))) {
            start = next_head(start, max_ea);
        }
        return start;
    }

    ea_t first_descending() const {
        const ea_t min_ea = inf_get_min_ea();
        ea_t start = bounds_.has_upper ? bounds_.upper : inf_get_max_ea();
        if (start == BADADDR) return BADADDR;
        if (bounds_.has_upper && bounds_.upper_inclusive && is_head(get_flags(start))) {
            return start;
        }
        if (start <= min_ea) return BADADDR;
        return prev_head(start, min_ea);
    }

public:
    AppliedTypesGenerator(AppliedTypeOrder order, AppliedTypeBounds bounds, bool include_untyped_point)
        : order_(order), bounds_(bounds), include_untyped_point_(include_untyped_point) {}

    bool next() override {
        if (include_untyped_point_) {
            if (started_) return false;
            started_ = true;
            if (!bounds_.has_lower || !bounds_.has_upper || bounds_.lower != bounds_.upper) {
                return false;
            }
            const ea_t ea = bounds_.lower;
            if (!is_mapped_address(ea)) return false;
            row_.ea = ea;
            current_ea_ = ea;
            return true;
        }

        ea_t next_ea = BADADDR;
        while (true) {
            if (!started_) {
                started_ = true;
                next_ea = order_ == AppliedTypeOrder::Asc ? first_ascending() : first_descending();
            } else if (order_ == AppliedTypeOrder::Asc) {
                next_ea = next_head(current_ea_, inf_get_max_ea());
            } else {
                next_ea = prev_head(current_ea_, inf_get_min_ea());
            }

            if (!applied_type_within_bounds(next_ea, bounds_)) {
                current_ea_ = BADADDR;
                return false;
            }

            current_ea_ = next_ea;
            if (address_has_applied_type(current_ea_)) {
                row_.ea = current_ea_;
                return true;
            }
        }
    }

    const AppliedTypeEntry& current() const override { return row_; }
    int64_t rowid() const override { return static_cast<int64_t>(row_.ea); }
};

bool apply_applied_type_constraint(
        AppliedTypeBounds& bounds,
        const xsql::GeneratorConstraintArg& arg,
        std::string* error) {
    switch (arg.op) {
    case xsql::ConstraintOp::Eq:
    {
        ea_t ea = BADADDR;
        if (!resolve_address_value(arg.value, "addr", ea, error)) return false;
        tighten_applied_lower(bounds, ea, true);
        tighten_applied_upper(bounds, ea, true);
        break;
    }
    case xsql::ConstraintOp::Gt:
    {
        ea_t ea = BADADDR;
        if (!resolve_address_value(arg.value, "addr", ea, error)) return false;
        tighten_applied_lower(bounds, ea, false);
        break;
    }
    case xsql::ConstraintOp::Ge:
    {
        ea_t ea = BADADDR;
        if (!resolve_address_value(arg.value, "addr", ea, error)) return false;
        tighten_applied_lower(bounds, ea, true);
        break;
    }
    case xsql::ConstraintOp::Lt:
    {
        ea_t ea = BADADDR;
        if (!resolve_address_value(arg.value, "addr", ea, error)) return false;
        tighten_applied_upper(bounds, ea, false);
        break;
    }
    case xsql::ConstraintOp::Le:
    {
        ea_t ea = BADADDR;
        if (!resolve_address_value(arg.value, "addr", ea, error)) return false;
        tighten_applied_upper(bounds, ea, true);
        break;
    }
    case xsql::ConstraintOp::Like:
        if (error) {
            *error = "applied_types: internal error: LIKE constraint routed to numeric addr bounds";
        }
        return false;
    }
    return true;
}

std::unique_ptr<xsql::Generator<AppliedTypeEntry>>
make_applied_types_generator(
        AppliedTypeOrder order,
        const std::vector<xsql::GeneratorConstraintArg>& args,
        bool include_untyped_point) {
    AppliedTypeBounds bounds;
    for (const auto& arg : args) {
        std::string error;
        if (!apply_applied_type_constraint(bounds, arg, &error)) {
            xsql::set_vtab_error(error);
            return nullptr;
        }
    }
    return std::make_unique<AppliedTypesGenerator>(order, bounds, include_untyped_point);
}

bool set_applied_type_decl(ea_t ea, xsql::FunctionArg val, bool allow_clear, bool reject_empty) {
    if (!is_mapped_address(ea)) {
        xsql::set_vtab_error("applied_types: address is not mapped: " + idasql::format_ea_hex(ea));
        return false;
    }

    const bool is_clear = val.is_null() || val.as_text().empty();
    if (is_clear) {
        if (reject_empty) {
            xsql::set_vtab_error("applied_types: decl must be non-empty for INSERT");
            return false;
        }
        if (!allow_clear) {
            xsql::set_vtab_error("applied_types: decl must be non-empty");
            return false;
        }
        del_tinfo(ea);
        decompiler::invalidate_decompiler_cache(ea);
        return true;
    }

    const std::string decl = val.as_text();
    const bool ok = apply_cdecl(nullptr, ea, decl.c_str(), 0);
    if (!ok) {
        xsql::set_vtab_error("applied_types: failed to apply declaration at " +
                             idasql::format_ea_hex(ea));
        return false;
    }
    decompiler::invalidate_decompiler_cache(ea);
    return true;
}

uint32_t applied_type_ordinal(ea_t ea) {
    tinfo_t tif;
    if (!get_tinfo(&tif, ea)) return 0;
    return tif.get_ordinal();
}

bool applied_type_name(ea_t ea, qstring& out) {
    out.clear();
    tinfo_t tif;
    if (!get_tinfo(&tif, ea)) return false;
    return tif.get_type_name(&out) && !out.empty();
}

} // namespace

GeneratorTableDef<AppliedTypeEntry> define_applied_types() {
    return generator_table<AppliedTypeEntry>("applied_types")
        .estimate_rows([]() -> size_t {
            return static_cast<size_t>(get_nlist_size());
        })
        .generator([]() -> std::unique_ptr<xsql::Generator<AppliedTypeEntry>> {
            return std::make_unique<AppliedTypesGenerator>(
                AppliedTypeOrder::Asc, AppliedTypeBounds{}, false);
        })
        .column_int64("addr", [](const AppliedTypeEntry& row) -> int64_t {
            return static_cast<int64_t>(row.ea);
        })
        .column_rw("decl", xsql::ColumnType::Text,
            [](xsql::FunctionContext& ctx, const AppliedTypeEntry& row) {
                qstring out;
                if (print_type(&out, row.ea, PRTYPE_1LINE | PRTYPE_SEMI)) {
                    ctx.result_text(out.c_str());
                } else {
                    ctx.result_null();
                }
            },
            [](AppliedTypeEntry& row, xsql::FunctionArg val) -> bool {
                if (val.is_nochange()) return true;
                return set_applied_type_decl(row.ea, val, true, false);
            })
        .column("ordinal", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const AppliedTypeEntry& row) {
                const uint32_t ordinal = applied_type_ordinal(row.ea);
                if (ordinal == 0) {
                    ctx.result_null();
                } else {
                    ctx.result_int(static_cast<int>(ordinal));
                }
            })
        .column("type_name", xsql::ColumnType::Text,
            [](xsql::FunctionContext& ctx, const AppliedTypeEntry& row) {
                qstring name;
                if (applied_type_name(row.ea, name)) {
                    ctx.result_text(name.c_str());
                } else {
                    ctx.result_null();
                }
            })
        .row_lookup([](AppliedTypeEntry& row, int64_t ea_val) -> bool {
            const ea_t ea = static_cast<ea_t>(static_cast<uint64_t>(ea_val));
            if (!is_mapped_address(ea)) return false;
            row.ea = ea;
            return true;
        })
        .constraint_filter(
            {xsql::required_eq("addr", "")},
            [](const std::vector<xsql::GeneratorConstraintArg>& args)
                -> std::unique_ptr<xsql::Generator<AppliedTypeEntry>> {
                return make_applied_types_generator(AppliedTypeOrder::Asc, args, true);
            },
            1.0, 1.0)
        .constraint_filter(
            {xsql::optional_ge("addr"), xsql::optional_gt("addr"),
             xsql::optional_lt("addr"), xsql::optional_le("addr")},
            [](const std::vector<xsql::GeneratorConstraintArg>& args)
                -> std::unique_ptr<xsql::Generator<AppliedTypeEntry>> {
                return make_applied_types_generator(AppliedTypeOrder::Asc, args, false);
            },
            10.0, 100.0)
        .order_by_consumed("addr")
        .constraint_filter(
            {xsql::optional_ge("addr"), xsql::optional_gt("addr"),
             xsql::optional_lt("addr"), xsql::optional_le("addr")},
            [](const std::vector<xsql::GeneratorConstraintArg>& args)
                -> std::unique_ptr<xsql::Generator<AppliedTypeEntry>> {
                return make_applied_types_generator(AppliedTypeOrder::Desc, args, false);
            },
            10.0, 100.0)
        .order_by_consumed("addr", true)
        .deletable([](AppliedTypeEntry& row) -> bool {
            if (!is_mapped_address(row.ea)) {
                xsql::set_vtab_error("applied_types: address is not mapped: " +
                                     idasql::format_ea_hex(row.ea));
                return false;
            }
            del_tinfo(row.ea);
            decompiler::invalidate_decompiler_cache(row.ea);
            return true;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            if (argc < 2 || argv[0].is_null()) {
                xsql::set_vtab_error("applied_types: INSERT requires address and non-empty decl");
                return false;
            }
            ea_t ea = BADADDR;
            std::string error;
            if (!resolve_address_value(argv[0], "addr", ea, &error)) {
                xsql::set_vtab_error(error);
                return false;
            }
            return set_applied_type_decl(ea, argv[1], false, true);
        })
        .build();
}

} // namespace types
} // namespace idasql
