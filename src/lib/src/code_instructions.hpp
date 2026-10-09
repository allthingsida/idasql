// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_instructions.hpp - `instructions` and `instruction_operands` tables,
 * their constraint-pushdown iterators, column renderers, and column layout
 * constants. Builds on the operand-representation engine.
 */

#pragma once

#include "core_common.hpp"
#include "code_operand_repr.hpp"

namespace idasql {
namespace code {

// An instruction and the function it is reported under. An instruction in a
// tail shared by several functions is one row per owner; owner is BADADDR for
// code outside every function (func_addr 0).
struct InstructionRow {
  ea_t ea = BADADDR;
  ea_t owner = BADADDR;
  // Another owner's row of the same shared-tail instruction was deleted
  // earlier in this statement: the instruction is already gone.
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

// Column layout constants
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

// Iterator for instructions within a single function (constraint pushdown).
// The addresses are collected when the cursor opens: a live function item
// iterator locks the function for as long as it exists, and IDA
// refuses to undefine a locked function's instructions, so a cursor that kept
// one open failed `DELETE FROM instructions WHERE func_addr = X`.
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

// Iterator for a single instruction by exact address: one row per owning
// function (several for a shared tail), or one row outside every function.
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

// Iterator for operands at a single instruction address, once per owning
// function (see InstructionAtAddressIterator).
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

// Iterator for operands in instructions within a single function.
class InstructionOperandsInFuncIterator : public xsql::RowIterator {
  ea_t func_addr_;
  std::vector<ea_t> eas_;  // the function's code heads, collected up front
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

} // namespace code
} // namespace idasql
