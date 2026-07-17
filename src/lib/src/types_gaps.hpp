// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * types_gaps.hpp - `type_gaps` table: free byte ranges in a struct.
 *
 * One row per maximal byte range not occupied by a real (non-gap) member -- the
 * places a new field can be inserted. Explicit IDA gap members (is_gap) and
 * implicit holes both surface as free ranges, as does trailing space up to the
 * struct's total size. Requires a `type_ordinal` or `type_name` filter.
 */

#pragma once

#include "types_common.hpp"

namespace idasql {
namespace types {

struct GapRow {
  uint32_t type_ordinal;
  std::string type_name;
  int64_t gap_offset;  // byte offset where the free range starts
  int64_t gap_size;    // free range length in bytes
};

// Free byte ranges of the struct at `ordinal` (empty for unions / non-structs).
std::vector<GapRow> compute_type_gaps(uint32_t ordinal);

// True if the *bit* range [start_bit, end_bit) overlaps any *real* (non-gap)
// member of the struct at `ordinal`. Gap members (TAFLD_GAP) and trailing free
// space count as free, so a range landing wholly in a gap returns false. Bit
// precision matters: a non-byte-aligned `offset_bits` insert must not slip an
// overlap past a byte-rounded check. Used to gate destructive fixed-layout
// inserts; only ranges that don't overlap a real member may be absorbed. False
// for unions / non-structs / empty ranges.
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

CachedTableDef<GapRow> define_type_gaps();

} // namespace types
} // namespace idasql
