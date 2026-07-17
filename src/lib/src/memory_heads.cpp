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

void collect_head_rows(std::vector<HeadRow> &rows) {
  rows.clear();

  ea_t ea = inf_get_min_ea();
  ea_t max_ea = inf_get_max_ea();

  while (ea < max_ea && ea != BADADDR) {
    rows.push_back({ea});
    ea = next_head(ea, max_ea);
  }
}

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

struct HeadBounds {
  bool has_lower = false;
  ea_t lower = 0;
  bool lower_inclusive = true;
  bool has_upper = false;
  ea_t upper = 0;
  bool upper_inclusive = true;
};

bool is_defined_head(ea_t ea) {
  return ea != BADADDR && is_head(get_flags(ea));
}

void tighten_lower_bound(HeadBounds &bounds, ea_t ea, bool inclusive) {
  if (!bounds.has_lower || ea > bounds.lower ||
      (ea == bounds.lower && !inclusive && bounds.lower_inclusive)) {
    bounds.has_lower = true;
    bounds.lower = ea;
    bounds.lower_inclusive = inclusive;
  }
}

void tighten_upper_bound(HeadBounds &bounds, ea_t ea, bool inclusive) {
  if (!bounds.has_upper || ea < bounds.upper ||
      (ea == bounds.upper && !inclusive && bounds.upper_inclusive)) {
    bounds.has_upper = true;
    bounds.upper = ea;
    bounds.upper_inclusive = inclusive;
  }
}

bool head_within_bounds(ea_t ea, const HeadBounds &bounds) {
  if (ea == BADADDR)
    return false;
  if (bounds.has_lower &&
      (ea < bounds.lower ||
       (ea == bounds.lower && !bounds.lower_inclusive))) {
    return false;
  }
  if (bounds.has_upper &&
      (ea > bounds.upper ||
       (ea == bounds.upper && !bounds.upper_inclusive))) {
    return false;
  }
  return true;
}

class HeadsGenerator : public xsql::Generator<HeadRow> {
  HeadOrder order_;
  HeadBounds bounds_;
  bool started_ = false;
  ea_t current_ea_ = BADADDR;
  mutable HeadRow row_{BADADDR};

  ea_t first_ascending() const {
    const ea_t max_ea = inf_get_max_ea();
    ea_t start = bounds_.has_lower ? bounds_.lower : inf_get_min_ea();
    if (start == BADADDR || start >= max_ea)
      return BADADDR;
    if (bounds_.has_lower && !bounds_.lower_inclusive)
      return next_head(start, max_ea);
    if (is_defined_head(start))
      return start;
    return next_head(start, max_ea);
  }

  ea_t first_descending() const {
    const ea_t min_ea = inf_get_min_ea();
    ea_t start = bounds_.has_upper ? bounds_.upper : inf_get_max_ea();
    if (start == BADADDR)
      return BADADDR;
    if (bounds_.has_upper && bounds_.upper_inclusive &&
        is_defined_head(start)) {
      return start;
    }
    if (start <= min_ea)
      return BADADDR;
    return prev_head(start, min_ea);
  }

public:
  HeadsGenerator(HeadOrder order, HeadBounds bounds)
      : order_(order), bounds_(bounds) {}

  bool next() override {
    ea_t next_ea = BADADDR;
    if (!started_) {
      started_ = true;
      next_ea =
          order_ == HeadOrder::Asc ? first_ascending() : first_descending();
    } else if (order_ == HeadOrder::Asc) {
      next_ea = next_head(current_ea_, inf_get_max_ea());
    } else {
      next_ea = prev_head(current_ea_, inf_get_min_ea());
    }

    if (!head_within_bounds(next_ea, bounds_)) {
      current_ea_ = BADADDR;
      return false;
    }

    current_ea_ = next_ea;
    row_.ea = current_ea_;
    return true;
  }

  const HeadRow &current() const override { return row_; }

  int64_t rowid() const override { return static_cast<int64_t>(current_ea_); }
};

void apply_head_constraint(HeadBounds &bounds,
                           const xsql::GeneratorConstraintArg &arg) {
  switch (arg.op) {
  case xsql::ConstraintOp::Eq:
  {
    const ea_t ea = normalize_sql_ea(arg.value.as_int64());
    tighten_lower_bound(bounds, ea, true);
    tighten_upper_bound(bounds, ea, true);
    break;
  }
  case xsql::ConstraintOp::Gt:
  {
    const ea_t ea = normalize_sql_ea(arg.value.as_int64());
    tighten_lower_bound(bounds, ea, false);
    break;
  }
  case xsql::ConstraintOp::Ge:
  {
    const ea_t ea = normalize_sql_ea(arg.value.as_int64());
    tighten_lower_bound(bounds, ea, true);
    break;
  }
  case xsql::ConstraintOp::Lt:
  {
    const ea_t ea = normalize_sql_ea(arg.value.as_int64());
    tighten_upper_bound(bounds, ea, false);
    break;
  }
  case xsql::ConstraintOp::Le:
  {
    const ea_t ea = normalize_sql_ea(arg.value.as_int64());
    tighten_upper_bound(bounds, ea, true);
    break;
  }
  case xsql::ConstraintOp::Like:
    xsql::set_vtab_error(
        "heads: internal error: LIKE constraint routed to numeric addr bounds");
    break;
  }
}

std::unique_ptr<xsql::Generator<HeadRow>>
make_heads_generator(HeadOrder order,
                     const std::vector<xsql::GeneratorConstraintArg> &args) {
  HeadBounds bounds;
  for (const auto &arg : args) {
    apply_head_constraint(bounds, arg);
  }
  return std::make_unique<HeadsGenerator>(order, bounds);
}

} // namespace

GeneratorTableDef<HeadRow> define_heads() {
  return generator_table<HeadRow>("heads")
      .estimate_rows(
          []() -> size_t { return static_cast<size_t>(get_nlist_size()); })
      .generator([]() -> std::unique_ptr<xsql::Generator<HeadRow>> {
        return std::make_unique<HeadsGenerator>(HeadOrder::Asc, HeadBounds{});
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
