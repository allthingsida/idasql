// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "types_common.hpp"

namespace idasql {
namespace types {

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
  std::string access_root_type;
};

GeneratorTableDef<MemberXrefRow> define_struct_member_xrefs();

}
}
