// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "memory_heads.hpp"

using namespace idasql::core;

namespace idasql {
namespace memory {

// ============================================================================
// HEADS Table - All defined items in the database
// ============================================================================

const char *get_item_type_str(ea_t ea) {
  flags64_t f = get_flags(ea);
  if (is_code(f))
    return "code";
  if (is_strlit(f))
    return "string";
  if (is_struct(f))
    return "struct";
  if (is_align(f))
    return "align";
  if (is_data(f))
    return "data";
  if (is_unknown(f))
    return "unknown";
  return "other";
}

namespace {

enum class HeadOrder { Asc, Desc };

// Yields the heads of an addr window in SQL order (HeadSpanWalker): an address
// >= 2^63 is a negative INTEGER, so with ORDER BY addr the high half comes
// first. The unconstrained scan walks every address the same way.
class HeadsGenerator : public xsql::Generator<HeadRow> {
  HeadSpanWalker walker_;
  mutable HeadRow row_{BADADDR};

public:
  HeadsGenerator(HeadOrder order, const xsql::Int64KeyRange &range)
      : walker_(range, order == HeadOrder::Desc) {}

  bool next() override {
    row_.ea = walker_.next();
    return row_.ea != BADADDR;
  }

  const HeadRow &current() const override { return row_; }

  int64_t rowid() const override { return static_cast<int64_t>(row_.ea); }
};

// The addr constraints are omit=1, so they are compared the way SQLite
// compares the INTEGER addr column (xsql::Int64KeyRange): `addr = 4096.5` and
// `addr = NULL` match nothing, `addr >= 4095.5` starts at 4096.
std::unique_ptr<xsql::Generator<HeadRow>>
make_heads_generator(HeadOrder order,
                     const std::vector<xsql::GeneratorConstraintArg> &args) {
  xsql::Int64KeyRange range;
  for (const auto &arg : args) {
    if (arg.op == xsql::ConstraintOp::Like) {
      xsql::set_vtab_error(
          "heads: internal error: LIKE constraint routed to numeric addr bounds");
      return nullptr;
    }
    range.constrain(arg.op, arg.value);
  }
  if (range.empty())
    return nullptr;
  return std::make_unique<HeadsGenerator>(order, range);
}

} // namespace

GeneratorTableDef<HeadRow> define_heads() {
  return generator_table<HeadRow>("heads")
      .estimate_rows(
          []() -> size_t { return estimate_heads(); })
      .generator([]() -> std::unique_ptr<xsql::Generator<HeadRow>> {
        return std::make_unique<HeadsGenerator>(HeadOrder::Asc,
                                                xsql::Int64KeyRange{});
      })
      .column_int64("addr",
                    [](const HeadRow &row) -> int64_t {
                      return static_cast<int64_t>(row.ea);
                    })
      .column_int64("size",
                    [](const HeadRow &row) -> int64_t {
                      return static_cast<int64_t>(get_item_size(row.ea));
                    })
      .column_text("type",
                   [](const HeadRow &row) -> std::string {
                     return get_item_type_str(row.ea);
                   })
      .column_int64("flags",
                    [](const HeadRow &row) -> int64_t {
                      return static_cast<int64_t>(get_flags(row.ea));
                    })
      .column_text("disasm",
                   [](const HeadRow &row) -> std::string {
                     qstring line;
                     generate_disasm_line(&line, row.ea, GENDSM_FORCE_CODE);
                     tag_remove(&line);
                     return line.c_str();
                   })
      .constraint_filter(
          {xsql::required_eq("addr", "")},
          [](const std::vector<xsql::GeneratorConstraintArg> &args)
              -> std::unique_ptr<xsql::Generator<HeadRow>> {
            return make_heads_generator(HeadOrder::Asc, args);
          },
          1.0, 1.0)
      .constraint_filter(
          {xsql::optional_ge("addr"), xsql::optional_gt("addr"),
           xsql::optional_lt("addr"), xsql::optional_le("addr")},
          [](const std::vector<xsql::GeneratorConstraintArg> &args)
              -> std::unique_ptr<xsql::Generator<HeadRow>> {
            return make_heads_generator(HeadOrder::Asc, args);
          },
          10.0, 100.0)
      .order_by_consumed("addr")
      .constraint_filter(
          {xsql::optional_ge("addr"), xsql::optional_gt("addr"),
           xsql::optional_lt("addr"), xsql::optional_le("addr")},
          [](const std::vector<xsql::GeneratorConstraintArg> &args)
              -> std::unique_ptr<xsql::Generator<HeadRow>> {
            return make_heads_generator(HeadOrder::Desc, args);
          },
          10.0, 100.0)
      .order_by_consumed("addr", true)
      .build();
}

} // namespace memory
} // namespace idasql
