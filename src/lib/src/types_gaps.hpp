// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "types_common.hpp"

namespace idasql {
namespace types {

struct GapRow {
  uint32_t type_ordinal;
  std::string type_name;
  int64_t gap_offset;
  int64_t gap_size;
};

std::vector<GapRow> compute_type_gaps(uint32_t ordinal);

bool range_overlaps_member(uint32_t ordinal, uint64_t start_bit, uint64_t end_bit);

class GapsIterator : public xsql::RowIterator {
public:
  explicit GapsIterator(std::vector<GapRow> rows);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;

private:
  std::vector<GapRow> rows_;
  int idx_ = -1;
};

GeneratorTableDef<GapRow> define_type_gaps();

}
}
