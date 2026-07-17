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

struct InstructionRow {
  ea_t ea = BADADDR;
};

struct InstructionOperandRow {
  ea_t ea = BADADDR;
  int opnum = 0;
};

void collect_instruction_rows(std::vector<InstructionRow> &rows);
void collect_instruction_operand_rows(std::vector<InstructionOperandRow> &rows);

void instruction_column_common(xsql::FunctionContext &ctx, ea_t ea,
                               ea_t func_addr, int col);
void instruction_operand_column_common(xsql::FunctionContext &ctx, ea_t ea,
                                       int opnum, int col);

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

// Iterator for instructions within a single function (constraint pushdown)
class InstructionsInFuncIterator : public xsql::RowIterator {
  ea_t func_addr_;
  func_t *pfn_ = nullptr;
  func_item_iterator_t fii_;
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

// Iterator for a single instruction by exact address.
class InstructionAtAddressIterator : public xsql::RowIterator {
  ea_t ea_;
  bool started_ = false;
  bool valid_ = false;

public:
  explicit InstructionAtAddressIterator(ea_t ea);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

// Iterator for operands at a single instruction address.
class InstructionOperandsAtAddressIterator : public xsql::RowIterator {
  ea_t ea_;
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
  func_t *pfn_ = nullptr;
  func_item_iterator_t fii_;
  insn_t insn_;
  ea_t current_ea_ = BADADDR;
  int opnum_ = -1;
  bool started_ = false;
  bool fii_valid_ = false;
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
