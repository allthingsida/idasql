// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"
#include "code_operand_repr.hpp"

namespace idasql {
namespace code {

struct InstructionRow {
  ea_t ea = BADADDR;
  ea_t owner = BADADDR;
  bool gone = false;
};

struct InstructionOperandRow {
  ea_t ea = BADADDR;
  int opnum = 0;
  ea_t owner = BADADDR;
};

void collect_instruction_rows(std::vector<InstructionRow> &rows);
void collect_instruction_operand_rows(std::vector<InstructionOperandRow> &rows);

void instruction_column_common(xsql::FunctionContext &ctx, ea_t ea,
                               ea_t func_addr, int col);
void instruction_operand_column_common(xsql::FunctionContext &ctx, ea_t ea,
                                       ea_t func_addr, int opnum, int col);

inline constexpr int kInstructionOperandCount = 8;
inline constexpr int kInstructionOperandBaseCol = 4;
inline constexpr int kInstructionDisasmCol =
    kInstructionOperandBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionFuncAddrCol = kInstructionDisasmCol + 1;
inline constexpr int kInstructionClassBaseCol = kInstructionFuncAddrCol + 1;
inline constexpr int kInstructionReprKindBaseCol =
    kInstructionClassBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionReprTypeBaseCol =
    kInstructionReprKindBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionReprMemberBaseCol =
    kInstructionReprTypeBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionReprSerialBaseCol =
    kInstructionReprMemberBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionReprDeltaBaseCol =
    kInstructionReprSerialBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionFormatSpecBaseCol =
    kInstructionReprDeltaBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionColumnCount =
    kInstructionFormatSpecBaseCol + kInstructionOperandCount;

class InstructionsInFuncIterator : public xsql::RowIterator {
  ea_t func_addr_;
  std::vector<ea_t> eas_;
  size_t idx_ = 0;
  bool started_ = false;
  bool valid_ = false;
  ea_t current_ea_ = BADADDR;

public:
  explicit InstructionsInFuncIterator(ea_t func_addr);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

class InstructionAtAddressIterator : public xsql::RowIterator {
  ea_t ea_;
  std::vector<ea_t> owners_;
  size_t idx_ = 0;
  bool started_ = false;
  bool valid_ = false;

public:
  explicit InstructionAtAddressIterator(ea_t ea);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

class InstructionOperandsAtAddressIterator : public xsql::RowIterator {
  ea_t ea_;
  std::vector<ea_t> owners_;
  size_t owner_idx_ = 0;
  insn_t insn_;
  int opnum_ = -1;
  bool started_ = false;
  bool decoded_ = false;
  bool valid_ = false;

  bool advance_to_next_operand();

public:
  explicit InstructionOperandsAtAddressIterator(ea_t ea);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

class InstructionOperandsInFuncIterator : public xsql::RowIterator {
  ea_t func_addr_;
  std::vector<ea_t> eas_;
  size_t ea_idx_ = 0;
  insn_t insn_;
  ea_t current_ea_ = BADADDR;
  int opnum_ = -1;
  bool started_ = false;
  bool decoded_ = false;
  bool valid_ = false;

  bool load_current_instruction();
  bool advance_to_next_operand();
  bool advance_to_next_instruction_with_operand();

public:
  explicit InstructionOperandsInFuncIterator(ea_t func_addr);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

CachedTableDef<InstructionRow> define_instructions();
CachedTableDef<InstructionOperandRow> define_instruction_operands();

}
}
