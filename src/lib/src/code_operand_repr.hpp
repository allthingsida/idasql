// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_operand_repr.hpp - Operand representation engine: parse/apply of
 * operand format specs (enum, stroff, number base, offset, sizeof, ...) plus
 * the operand-rendering read helpers consumed by the instructions tables.
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace code {

enum class OperandApplyKind {
  None,
  Clear,
  Enum,
  Stroff,
  NumBase,   // hex / dec / oct / bin
  Char,      // character constant
  Float,     // floating-point
  Segment,   // segment selector
  StackVar,  // stack variable
  Offset,    // plain or user-base offset
  Sizeof,    // struct-size representation ("size STRUCT")
  Forced,    // forced (manual) operand text
  Modifiers, // change only sign/bnot of the current representation
};

// Tri-state for the ,signed/,unsigned and ,bnot/,nobnot modifiers.
enum class OperandModMode {
  Unchanged,
  On,
  Off,
};

struct OperandApplyRequest {
  OperandApplyKind kind = OperandApplyKind::None;
  std::string enum_name;
  std::string enum_member_name;
  uchar enum_serial = 0;
  std::vector<std::string> stroff_path_names;
  adiff_t stroff_delta = 0;
  int num_radix = 0;          // NumBase: 16/10/8/2
  std::string offset_base;    // Offset: symbol name or address ("" => plain base 0)
  std::string forced_text;    // Forced: literal operand text
  std::string sizeof_type;    // Sizeof: struct type name
  OperandModMode sign_mode = OperandModMode::Unchanged;
  OperandModMode bnot_mode = OperandModMode::Unchanged;
};

// Spec parsing / application
void split_path_names(const std::string &path_spec,
                      std::vector<std::string> &out_names);
bool resolve_ea_spec(const std::string &spec, ea_t &out_ea);
bool parse_operand_format_spec(const char *spec, OperandApplyRequest &out,
                               std::string *out_error = nullptr);
bool parse_operand_apply_spec(const char *spec, OperandApplyRequest &out);
bool decode_operand(ea_t ea, int opnum, insn_t &out_insn, op_t &out_op,
                    std::string *out_error = nullptr);
bool operand_numeric_value(ea_t ea, int opnum, uint64 &out_value,
                           std::string *out_error = nullptr);
bool resolve_enum_member_serial(const tinfo_t &enum_tif,
                                const std::string &member_name,
                                uchar &out_serial,
                                std::string *out_error = nullptr);
bool apply_operand_representation(ea_t ea, int opnum,
                                  const OperandApplyRequest &req,
                                  std::string *out_error = nullptr);

// Operand rendering / classification (read helpers)
const char *operand_type_name(optype_t type);
const char *operand_class_name(optype_t type);
std::string operand_kind_text(ea_t ea, int opnum);
std::string operand_type_text(ea_t ea, int opnum);
int operand_enum_serial(ea_t ea, int opnum);
int64_t operand_stroff_delta(ea_t ea, int opnum);
std::string operand_class_text(ea_t ea, int opnum);
std::string operand_repr_kind_text(ea_t ea, int opnum);
std::string operand_repr_type_name_text(ea_t ea, int opnum);
std::string operand_repr_member_name_text(ea_t ea, int opnum);
int operand_repr_serial(ea_t ea, int opnum);
int64_t operand_repr_delta(ea_t ea, int opnum);
std::string operand_format_spec_text(ea_t ea, int opnum);

} // namespace code
} // namespace idasql
