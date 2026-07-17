// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * types_member_xrefs.hpp - `struct_member_xrefs` table.
 *
 * Cross-references TO a specific struct/union member, resolved via the member's
 * IDA tid (`tinfo_t::get_udm_tid`) and enumerated with `xrefblk_t::first_to(tid,
 * XREF_ALL)` -- no disassembly-text scan. Supports full nested-member expansion
 * (dotted `member_path`) and reports function + best-effort operand/access
 * context. Requires a filter on `type_ordinal`, `type_name`, or `member_id`; an
 * unfiltered query returns an actionable error rather than scanning every type.
 */

#pragma once

#include "types_common.hpp"

namespace idasql {
namespace types {

// One emitted row: leaf-member identity joined with a single cross-reference.
// Only used to declare the table schema; the actual rows are produced by the
// filter iterators below (the unfiltered cache path errors out).
struct MemberXrefRow {
  uint32_t type_ordinal = 0;
  std::string type_name;
  int member_index = 0;
  std::string member_name;
  std::string member_path;
  int64_t member_offset = 0;
  int64_t member_offset_bits = 0;
  uint64_t member_id = 0;
  uint64_t xref_from = 0;
  uint64_t xref_to = 0;
  int xref_type = 0;
  std::string xref_kind;
  uint64_t function_address = 0;
  std::string function_name;
  int operand_index = -1;
  std::string instruction_text;
  int64_t access_offset = -1;
  int64_t access_size = -1;
};

CachedTableDef<MemberXrefRow> define_struct_member_xrefs();

} // namespace types
} // namespace idasql
