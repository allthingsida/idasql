// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_applied.hpp"

#include "address_resolution.hpp"
#include "core_common.hpp"
#include "decompiler.hpp"

namespace idasql {
namespace types {

namespace {

enum class AppliedTypeOrder { Asc, Desc };

bool address_has_applied_type(ea_t ea) {
    tinfo_t tif;
    return ea != BADADDR && get_tinfo(&tif, ea);
}

bool is_mapped_address(ea_t ea) {
    return ea != BADADDR && is_mapped(ea);
}

// Yields the typed heads of an addr window in SQL order (core::HeadSpanWalker):
// an address >= 2^63 is a negative INTEGER, so with ORDER BY addr the high half
// comes first. `addr = X` also yields an untyped mapped X (the row an INSERT or
// UPDATE targets).
class AppliedTypesGenerator : public xsql::Generator<AppliedTypeEntry> {
    core::HeadSpanWalker walker_;
    std::optional<ea_t> point_;
    bool point_done_ = false;
    mutable AppliedTypeEntry row_{BADADDR};

public:
    AppliedTypesGenerator(AppliedTypeOrder order, const xsql::Int64KeyRange& range,
                          bool include_untyped_point)
        : walker_(range, order == AppliedTypeOrder::Desc) {
        if (include_untyped_point) {
            point_ = !range.empty() && range.lower() == range.upper()
                ? std::optional<ea_t>(core::normalize_sql_ea(range.lower()))
                : std::optional<ea_t>(BADADDR);
        }
    }

    bool next() override {
        if (point_) {
            if (point_done_ || !is_mapped_address(*point_)) return false;
            point_done_ = true;
            row_.ea = *point_;
            return true;
        }
        for (ea_t ea = walker_.next(); ea != BADADDR; ea = walker_.next()) {
            if (address_has_applied_type(ea)) {
                row_.ea = ea;
                return true;
            }
        }
        return false;
    }

    const AppliedTypeEntry& current() const override { return row_; }
    int64_t rowid() const override { return static_cast<int64_t>(row_.ea); }
};

// Narrow `range` by one addr constraint. The plan is omit=1, so a number (or
// NULL, or a blob) compares the way SQLite compares the INTEGER addr column:
// `addr >= 4096.5` keeps 4097 and up, `addr = NULL` keeps nothing. Text is
// the documented address spelling -- a numeric or '0x...' string, or a symbol
// name -- resolved to its address first; an unresolvable name is an error.
bool constrain_applied_type_addr(
        xsql::Int64KeyRange& range,
        const xsql::GeneratorConstraintArg& arg,
        std::string* error) {
    if (arg.op == xsql::ConstraintOp::Like) {
        if (error) {
            *error = "applied_types: internal error: LIKE constraint routed to numeric addr bounds";
        }
        return false;
    }
    if (arg.value.type() != SQLITE_TEXT) {
        range.constrain(arg.op, arg.value);
        return true;
    }
    std::optional<ea_t> ea;
    if (!resolve_address_key(arg.value, "addr", ea, error)) return false;
    if (ea) {
        range.constrain(arg.op, static_cast<int64_t>(static_cast<uint64_t>(*ea)));
    } else {
        range.constrain(arg.op, arg.value);
    }
    return true;
}

std::unique_ptr<xsql::Generator<AppliedTypeEntry>>
make_applied_types_generator(
        AppliedTypeOrder order,
        const std::vector<xsql::GeneratorConstraintArg>& args,
        bool include_untyped_point) {
    xsql::Int64KeyRange range;
    for (const auto& arg : args) {
        std::string error;
        if (!constrain_applied_type_addr(range, arg, &error)) {
            xsql::set_vtab_error(error);
            return nullptr;
        }
    }
    if (range.empty()) return nullptr;  // no address satisfies the constraints
    return std::make_unique<AppliedTypesGenerator>(order, range, include_untyped_point);
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
                AppliedTypeOrder::Asc, xsql::Int64KeyRange{}, false);
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
