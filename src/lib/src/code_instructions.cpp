// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_instructions.hpp"

using namespace idasql::core;

namespace idasql {
namespace code {

void instruction_column_common(xsql::FunctionContext &ctx, ea_t ea,
                               ea_t func_addr, int col) {
  if (col == 0) {
    ctx.result_int64(ea);
    return;
  }
  if (col == 1) {
    insn_t insn;
    if (decode_insn(&insn, ea) > 0)
      ctx.result_int(insn.itype);
    else
      ctx.result_int(0);
    return;
  }
  if (col == 2) {
    qstring mnem;
    print_insn_mnem(&mnem, ea);
    ctx.result_text(mnem.c_str());
    return;
  }
  if (col == 3) {
    ctx.result_int(static_cast<int>(get_item_size(ea)));
    return;
  }
  if (col >= kInstructionOperandBaseCol &&
      col < (kInstructionOperandBaseCol + kInstructionOperandCount)) {
    const int opnum = col - kInstructionOperandBaseCol;
    qstring op;
    print_operand(&op, ea, opnum);
    tag_remove(&op);
    ctx.result_text(op.c_str());
    return;
  }
  if (col == kInstructionDisasmCol) {
    qstring line;
    generate_disasm_line(&line, ea, 0);
    tag_remove(&line);
    ctx.result_text(line.c_str());
    return;
  }
  if (col == kInstructionFuncAddrCol) {
    ctx.result_int64(func_addr);
    return;
  }
  if (col >= kInstructionClassBaseCol &&
      col < (kInstructionClassBaseCol + kInstructionOperandCount)) {
    ctx.result_text(operand_class_text(ea, col - kInstructionClassBaseCol));
    return;
  }
  if (col >= kInstructionReprKindBaseCol &&
      col < (kInstructionReprKindBaseCol + kInstructionOperandCount)) {
    ctx.result_text(
        operand_repr_kind_text(ea, col - kInstructionReprKindBaseCol));
    return;
  }
  if (col >= kInstructionReprTypeBaseCol &&
      col < (kInstructionReprTypeBaseCol + kInstructionOperandCount)) {
    ctx.result_text(
        operand_repr_type_name_text(ea, col - kInstructionReprTypeBaseCol));
    return;
  }
  if (col >= kInstructionReprMemberBaseCol &&
      col < (kInstructionReprMemberBaseCol + kInstructionOperandCount)) {
    ctx.result_text(
        operand_repr_member_name_text(ea, col - kInstructionReprMemberBaseCol));
    return;
  }
  if (col >= kInstructionReprSerialBaseCol &&
      col < (kInstructionReprSerialBaseCol + kInstructionOperandCount)) {
    ctx.result_int(
        operand_repr_serial(ea, col - kInstructionReprSerialBaseCol));
    return;
  }
  if (col >= kInstructionReprDeltaBaseCol &&
      col < (kInstructionReprDeltaBaseCol + kInstructionOperandCount)) {
    ctx.result_int64(
        operand_repr_delta(ea, col - kInstructionReprDeltaBaseCol));
    return;
  }
  if (col >= kInstructionFormatSpecBaseCol &&
      col < (kInstructionFormatSpecBaseCol + kInstructionOperandCount)) {
    ctx.result_text(
        operand_format_spec_text(ea, col - kInstructionFormatSpecBaseCol));
    return;
  }
  ctx.result_null();
}

// ============================================================================
// INSTRUCTIONS Table - Iterators
// ============================================================================

InstructionsInFuncIterator::InstructionsInFuncIterator(ea_t func_addr)
    : func_addr_(func_addr) {
  pfn_ = get_func(func_addr_);
}

bool InstructionsInFuncIterator::next() {
  if (!pfn_)
    return false;

  if (!started_) {
    started_ = true;
    valid_ = fii_.set(pfn_);
    if (valid_)
      current_ea_ = fii_.current();
  } else if (valid_) {
    valid_ = fii_.next_code();
    if (valid_)
      current_ea_ = fii_.current();
  }
  return valid_;
}

bool InstructionsInFuncIterator::eof() const { return started_ && !valid_; }

void InstructionsInFuncIterator::column(xsql::FunctionContext &ctx, int col) {
  instruction_column_common(ctx, current_ea_, func_addr_, col);
}

int64_t InstructionsInFuncIterator::rowid() const {
  return static_cast<int64_t>(current_ea_);
}

InstructionAtAddressIterator::InstructionAtAddressIterator(ea_t ea) : ea_(ea) {}

bool InstructionAtAddressIterator::next() {
  if (!started_) {
    started_ = true;
    valid_ = (ea_ != BADADDR) && is_code(get_flags(ea_));
    return valid_;
  }
  valid_ = false;
  return false;
}

bool InstructionAtAddressIterator::eof() const { return started_ && !valid_; }

void InstructionAtAddressIterator::column(xsql::FunctionContext &ctx, int col) {
  func_t *f = get_func(ea_);
  ea_t func_addr = f ? f->start_ea : 0;
  instruction_column_common(ctx, ea_, func_addr, col);
}

int64_t InstructionAtAddressIterator::rowid() const {
  return static_cast<int64_t>(ea_);
}

// ============================================================================
// INSTRUCTIONS Table - Definition
// ============================================================================

void collect_instruction_rows(std::vector<InstructionRow> &rows) {
  rows.clear();

  ea_t ea = inf_get_min_ea();
  ea_t max_ea = inf_get_max_ea();
  uint64_t scanned = 0;
  while (ea < max_ea && ea != BADADDR) {
    // Cooperative cancellation -- this whole-program walk cannot be
    // interrupted by the SQLite progress handler, so poll the query deadline.
    if (((++scanned) & 4095u) == 0 && xsql::vtab_interrupted()) {
      xsql::set_vtab_error("query interrupted: timeout while building instructions");
      return;
    }
    if (is_code(get_flags(ea))) {
      rows.push_back({ea});
    }
    ea = next_head(ea, max_ea);
  }
}

CachedTableDef<InstructionRow> define_instructions() {
  auto builder =
      cached_table<InstructionRow>("instructions")
          .no_shared_cache()
          .estimate_rows(
              []() -> size_t { return static_cast<size_t>(get_nlist_size()); })
          .cache_builder([](std::vector<InstructionRow> &rows) {
            collect_instruction_rows(rows);
          })
          // Stable rowid = the instruction's address, matching the `addr` column
          // and both filter iterators (InstructionAtAddressIterator /
          // InstructionsInFuncIterator both report ea as rowid). This makes the
          // full-scan rowid agree with the filtered rowids, so a multi-row
          // UPDATE/DELETE resolves each row by its own address -- deleting the
          // instruction at one ea never shifts another row's rowid.
          .rowid([](const InstructionRow &row) -> int64_t {
            return static_cast<int64_t>(row.ea);
          })
          .row_lookup([](InstructionRow &row, int64_t rowid) -> bool {
            // rowid is an instruction address (see .rowid above): resolve by ea,
            // position-independent. No positional fallback -- with rowid_fn set,
            // every scan (full or filtered) produces an ea, never a cache index.
            if (rowid < 0)
              return false;
            const ea_t ea = static_cast<ea_t>(rowid);
            if (ea != BADADDR && is_code(get_flags(ea))) {
              row.ea = ea;
              return true;
            }
            return false;
          })
          .column_int64("addr",
                        [](const InstructionRow &row) -> int64_t {
                          return static_cast<int64_t>(row.ea);
                        })
          .column_int("itype",
                      [](const InstructionRow &row) -> int {
                        insn_t insn;
                        if (decode_insn(&insn, row.ea) > 0)
                          return insn.itype;
                        return 0;
                      })
          .column_text("mnemonic",
                       [](const InstructionRow &row) -> std::string {
                         qstring mnem;
                         print_insn_mnem(&mnem, row.ea);
                         return mnem.c_str();
                       })
          .column_int("size", [](const InstructionRow &row) -> int {
            return static_cast<int>(get_item_size(row.ea));
          });

  for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
    const std::string op_col = "operand" + std::to_string(opnum);
    builder.column_text(op_col.c_str(),
                        [opnum](const InstructionRow &row) -> std::string {
                          qstring op;
                          print_operand(&op, row.ea, opnum);
                          tag_remove(&op);
                          return op.c_str();
                        });
  }

  builder
      .column_text("disasm",
                   [](const InstructionRow &row) -> std::string {
                     qstring line;
                     generate_disasm_line(&line, row.ea, 0);
                     tag_remove(&line);
                     return line.c_str();
                   })
      .column_int64("func_addr", [](const InstructionRow &row) -> int64_t {
        func_t *f = get_func(row.ea);
        return f ? f->start_ea : 0;
      });

  for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
    const std::string class_col = "operand" + std::to_string(opnum) + "_class";
    builder.column_text(class_col.c_str(),
                        [opnum](const InstructionRow &row) -> std::string {
                          return operand_class_text(row.ea, opnum);
                        });
  }
  for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
    const std::string repr_kind_col =
        "operand" + std::to_string(opnum) + "_repr_kind";
    builder.column_text(repr_kind_col.c_str(),
                        [opnum](const InstructionRow &row) -> std::string {
                          return operand_repr_kind_text(row.ea, opnum);
                        });
  }
  for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
    const std::string repr_type_col =
        "operand" + std::to_string(opnum) + "_repr_type_name";
    builder.column_text(repr_type_col.c_str(),
                        [opnum](const InstructionRow &row) -> std::string {
                          return operand_repr_type_name_text(row.ea, opnum);
                        });
  }
  for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
    const std::string repr_member_col =
        "operand" + std::to_string(opnum) + "_repr_member_name";
    builder.column_text(repr_member_col.c_str(),
                        [opnum](const InstructionRow &row) -> std::string {
                          return operand_repr_member_name_text(row.ea, opnum);
                        });
  }
  for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
    const std::string repr_serial_col =
        "operand" + std::to_string(opnum) + "_repr_serial";
    builder.column_int(repr_serial_col.c_str(),
                       [opnum](const InstructionRow &row) -> int {
                         return operand_repr_serial(row.ea, opnum);
                       });
  }
  for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
    const std::string repr_delta_col =
        "operand" + std::to_string(opnum) + "_repr_delta";
    builder.column_int64(repr_delta_col.c_str(),
                         [opnum](const InstructionRow &row) -> int64_t {
                           return operand_repr_delta(row.ea, opnum);
                         });
  }
  for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
    const std::string format_col =
        "operand" + std::to_string(opnum) + "_format_spec";
    builder.column_text_rw(
        format_col.c_str(),
        [opnum](const InstructionRow &row) -> std::string {
          return operand_format_spec_text(row.ea, opnum);
        },
        [opnum](InstructionRow &row, xsql::FunctionArg val) -> bool {
          if (val.is_nochange() || val.is_null()) {
            return true;
          }
          const std::string spec = val.as_text();
          if (spec.empty()) {
            return true;
          }
          OperandApplyRequest req;
          std::string parse_error;
          if (!parse_operand_format_spec(spec.c_str(), req, &parse_error)) {
            xsql::set_vtab_error("invalid operand format spec '" + spec +
                                 "': " + parse_error);
            return false;
          }

          std::string apply_error;
          if (!apply_operand_representation(row.ea, opnum, req, &apply_error)) {
            const std::string err =
                apply_error.empty() ? "apply failed" : apply_error;
            xsql::set_vtab_error(
                "operand" + std::to_string(opnum) + " format apply failed at " +
                std::to_string(static_cast<uint64_t>(row.ea)) + ": " + err);
            return false;
          }

          const std::string actual_kind = operand_repr_kind_text(row.ea, opnum);
          if (req.kind == OperandApplyKind::Clear) {
            // clr_op_type removes the user-applied representation; the operand
            // may fall back to a default number or an auto stack variable,
            // which is an acceptable cleared state. Only the explicit
            // symbol/struct/offset/forced reps must be gone.
            const flags64_t f = get_flags(row.ea);
            const bool still_structured =
                is_enum(f, opnum) || is_stroff(f, opnum) || is_off(f, opnum) ||
                is_forced_operand(row.ea, opnum);
            if (still_structured) {
              xsql::set_vtab_error("post-apply verification failed: "
                                   "representation not cleared");
              return false;
            }
            return true;
          }

          if (req.kind == OperandApplyKind::Enum) {
            if (actual_kind != "enum") {
              xsql::set_vtab_error("post-apply verification failed: expected "
                                   "enum representation");
              return false;
            }
            const std::string actual_type =
                operand_repr_type_name_text(row.ea, opnum);
            if (!req.enum_name.empty() && actual_type != req.enum_name) {
              xsql::set_vtab_error(
                  "post-apply verification failed: enum type mismatch");
              return false;
            }
            if (!req.enum_member_name.empty()) {
              const std::string actual_member =
                  operand_repr_member_name_text(row.ea, opnum);
              if (actual_member.find(req.enum_member_name) ==
                  std::string::npos) {
                xsql::set_vtab_error(
                    "post-apply verification failed: enum member mismatch");
                return false;
              }
            }
            return true;
          }

          if (req.kind == OperandApplyKind::Stroff) {
            if (actual_kind != "stroff") {
              xsql::set_vtab_error("post-apply verification failed: expected "
                                   "stroff representation");
              return false;
            }
            const std::string actual_type =
                operand_repr_type_name_text(row.ea, opnum);
            if (!req.stroff_path_names.empty()) {
              const std::string &expected_root = req.stroff_path_names.front();
              if (!(actual_type == expected_root ||
                    actual_type.rfind(expected_root + "/", 0) == 0)) {
                xsql::set_vtab_error(
                    "post-apply verification failed: stroff type mismatch");
                return false;
              }
            }
            if (operand_repr_delta(row.ea, opnum) !=
                static_cast<int64_t>(req.stroff_delta)) {
              xsql::set_vtab_error(
                  "post-apply verification failed: stroff delta mismatch");
              return false;
            }
            return true;
          }

          // Expected read-back kind for the remaining representations.
          std::string expected_kind;
          switch (req.kind) {
          case OperandApplyKind::NumBase:
            expected_kind = req.num_radix == 16   ? "hex"
                            : req.num_radix == 10 ? "dec"
                            : req.num_radix == 8  ? "oct"
                                                  : "bin";
            break;
          case OperandApplyKind::Char:
            expected_kind = "char";
            break;
          case OperandApplyKind::Float:
            expected_kind = "float";
            break;
          case OperandApplyKind::Segment:
            expected_kind = "segment";
            break;
          case OperandApplyKind::StackVar:
            expected_kind = "stkvar";
            break;
          case OperandApplyKind::Offset:
            expected_kind = "offset";
            break;
          case OperandApplyKind::Sizeof:
            expected_kind = "sizeof";
            break;
          case OperandApplyKind::Forced:
            expected_kind = "forced";
            break;
          default:
            break;
          }

          if (!expected_kind.empty() && actual_kind != expected_kind) {
            xsql::set_vtab_error("post-apply verification failed: expected " +
                                 expected_kind + " representation, got " +
                                 actual_kind);
            return false;
          }

          if (req.kind == OperandApplyKind::Offset && !req.offset_base.empty()) {
            ea_t want_base = 0;
            const ea_t got_base = get_offbase(row.ea, opnum);
            if (!resolve_ea_spec(req.offset_base, want_base) ||
                got_base != want_base) {
              xsql::set_vtab_error(
                  "post-apply verification failed: offset base mismatch");
              return false;
            }
          }

          if (req.kind == OperandApplyKind::Sizeof) {
            const std::string actual_type =
                operand_repr_type_name_text(row.ea, opnum);
            if (actual_type != req.sizeof_type) {
              xsql::set_vtab_error(
                  "post-apply verification failed: sizeof type mismatch");
              return false;
            }
          }

          if (req.kind == OperandApplyKind::Forced) {
            const std::string actual_text =
                operand_repr_type_name_text(row.ea, opnum);
            if (actual_text != req.forced_text) {
              xsql::set_vtab_error(
                  "post-apply verification failed: forced operand text "
                  "mismatch");
              return false;
            }
          }

          // Verify sign/bnot modifiers landed (forced operands ignore them).
          if (req.kind != OperandApplyKind::Forced) {
            const flags64_t f = get_flags(row.ea);
            if (req.sign_mode != OperandModMode::Unchanged &&
                is_invsign(row.ea, f, opnum) !=
                    (req.sign_mode == OperandModMode::On)) {
              xsql::set_vtab_error(
                  "post-apply verification failed: sign modifier mismatch");
              return false;
            }
            if (req.bnot_mode != OperandModMode::Unchanged &&
                is_bnot(row.ea, f, opnum) !=
                    (req.bnot_mode == OperandModMode::On)) {
              xsql::set_vtab_error(
                  "post-apply verification failed: bnot modifier mismatch");
              return false;
            }
          }

          return true;
        });
  }

  builder
      .deletable([](InstructionRow &row) -> bool {
        idasql_auto_wait();
        asize_t sz = get_item_size(row.ea);
        bool ok = del_items(row.ea, DELIT_SIMPLE, sz);
        idasql_auto_wait();
        return ok;
      })
      .filter_eq(
          "addr",
          [](int64_t address) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<InstructionAtAddressIterator>(
                static_cast<ea_t>(address));
          },
          1.0, 1.0)
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<InstructionsInFuncIterator>(
                static_cast<ea_t>(func_addr));
          },
          100.0);

  return builder.build();
}

// ============================================================================
// INSTRUCTION_OPERANDS Table - One decoded operand per row
// ============================================================================

static int64_t instruction_operand_rowid(ea_t ea, int opnum) {
  return static_cast<int64_t>(ea) * kInstructionOperandCount + opnum;
}

static int64_t operand_value_for_row(const op_t &op) {
  switch (op.type) {
  case o_imm:
    return static_cast<int64_t>(op.value);
  case o_mem:
  case o_near:
  case o_far:
  case o_displ:
    return static_cast<int64_t>(op.addr);
  case o_reg:
    return static_cast<int64_t>(op.reg);
  default:
    return static_cast<int64_t>(op.value);
  }
}

void instruction_operand_column_common(xsql::FunctionContext &ctx, ea_t ea,
                                       int opnum, int col) {
  insn_t insn;
  op_t op;
  if (!decode_operand(ea, opnum, insn, op, nullptr)) {
    ctx.result_null();
    return;
  }

  switch (col) {
  case 0:
    ctx.result_int64(ea);
    break;
  case 1: {
    func_t *f = get_func(ea);
    ctx.result_int64(f ? f->start_ea : 0);
    break;
  }
  case 2:
    ctx.result_int(opnum);
    break;
  case 3: {
    qstring text;
    print_operand(&text, ea, opnum);
    tag_remove(&text);
    ctx.result_text(text.c_str());
    break;
  }
  case 4:
    ctx.result_int(static_cast<int>(op.type));
    break;
  case 5:
    ctx.result_text_static(operand_type_name(op.type));
    break;
  case 6:
    ctx.result_int(static_cast<int>(op.dtype));
    break;
  case 7:
    ctx.result_int(op.reg);
    break;
  case 8:
    ctx.result_int64(static_cast<int64_t>(op.addr));
    break;
  case 9:
    ctx.result_int64(static_cast<int64_t>(op.value));
    break;
  case 10:
    ctx.result_int64(operand_value_for_row(op));
    break;
  default:
    ctx.result_null();
    break;
  }
}

void collect_instruction_operand_rows(std::vector<InstructionOperandRow> &rows) {
  rows.clear();

  ea_t ea = inf_get_min_ea();
  ea_t max_ea = inf_get_max_ea();
  uint64_t scanned = 0;
  while (ea < max_ea && ea != BADADDR) {
    // Cooperative cancellation (whole-program decode walk).
    if (((++scanned) & 4095u) == 0 && xsql::vtab_interrupted()) {
      xsql::set_vtab_error(
          "query interrupted: timeout while building instruction_operands");
      return;
    }
    if (is_code(get_flags(ea))) {
      insn_t insn;
      if (decode_insn(&insn, ea) > 0) {
        for (int opnum = 0; opnum < UA_MAXOP; ++opnum) {
          // Skip void slots but keep scanning all UA_MAXOP operands: some IDPs
          // leave gaps (a real operand after a void), and the pushdown
          // iterators 'continue' past voids -- 'break' here would make
          // full-scan and filtered results disagree.
          if (insn.ops[opnum].type == o_void)
            continue;
          rows.push_back({ea, opnum});
        }
      }
    }
    ea = next_head(ea, max_ea);
  }
}

InstructionOperandsAtAddressIterator::InstructionOperandsAtAddressIterator(
    ea_t ea)
    : ea_(ea) {}

bool InstructionOperandsAtAddressIterator::advance_to_next_operand() {
  while (++opnum_ < UA_MAXOP) {
    if (insn_.ops[opnum_].type != o_void)
      return true;
  }
  return false;
}

bool InstructionOperandsAtAddressIterator::next() {
  if (!started_) {
    started_ = true;
    decoded_ = (ea_ != BADADDR) && is_code(get_flags(ea_)) &&
               decode_insn(&insn_, ea_) > 0;
    valid_ = decoded_ && advance_to_next_operand();
    return valid_;
  }

  valid_ = decoded_ && advance_to_next_operand();
  return valid_;
}

bool InstructionOperandsAtAddressIterator::eof() const {
  return started_ && !valid_;
}

void InstructionOperandsAtAddressIterator::column(xsql::FunctionContext &ctx,
                                                  int col) {
  instruction_operand_column_common(ctx, ea_, opnum_, col);
}

int64_t InstructionOperandsAtAddressIterator::rowid() const {
  return instruction_operand_rowid(ea_, opnum_);
}

InstructionOperandsInFuncIterator::InstructionOperandsInFuncIterator(
    ea_t func_addr)
    : func_addr_(func_addr) {
  pfn_ = get_func(func_addr_);
}

bool InstructionOperandsInFuncIterator::load_current_instruction() {
  if (!fii_valid_)
    return false;
  current_ea_ = fii_.current();
  decoded_ = decode_insn(&insn_, current_ea_) > 0;
  opnum_ = -1;
  return decoded_;
}

bool InstructionOperandsInFuncIterator::advance_to_next_operand() {
  while (++opnum_ < UA_MAXOP) {
    if (insn_.ops[opnum_].type != o_void)
      return true;
  }
  return false;
}

bool InstructionOperandsInFuncIterator::advance_to_next_instruction_with_operand() {
  while (fii_valid_) {
    if (load_current_instruction() && advance_to_next_operand())
      return true;
    fii_valid_ = fii_.next_code();
  }
  return false;
}

bool InstructionOperandsInFuncIterator::next() {
  if (!pfn_)
    return false;

  if (!started_) {
    started_ = true;
    fii_valid_ = fii_.set(pfn_);
    valid_ = advance_to_next_instruction_with_operand();
    return valid_;
  }

  if (valid_ && advance_to_next_operand())
    return true;

  if (fii_valid_)
    fii_valid_ = fii_.next_code();
  valid_ = advance_to_next_instruction_with_operand();
  return valid_;
}

bool InstructionOperandsInFuncIterator::eof() const {
  return started_ && !valid_;
}

void InstructionOperandsInFuncIterator::column(xsql::FunctionContext &ctx,
                                               int col) {
  instruction_operand_column_common(ctx, current_ea_, opnum_, col);
}

int64_t InstructionOperandsInFuncIterator::rowid() const {
  return instruction_operand_rowid(current_ea_, opnum_);
}

CachedTableDef<InstructionOperandRow> define_instruction_operands() {
  return cached_table<InstructionOperandRow>("instruction_operands")
      .no_shared_cache()
      .estimate_rows([]() -> size_t {
        return static_cast<size_t>(get_nlist_size()) * 2;
      })
      .cache_builder([](std::vector<InstructionOperandRow> &rows) {
        collect_instruction_operand_rows(rows);
      })
      .column_int64("addr",
                    [](const InstructionOperandRow &row) -> int64_t {
                      return static_cast<int64_t>(row.ea);
                    })
      .column_int64("func_addr", [](const InstructionOperandRow &row) -> int64_t {
        func_t *f = get_func(row.ea);
        return f ? f->start_ea : 0;
      })
      .column_int("opnum", [](const InstructionOperandRow &row) -> int {
        return row.opnum;
      })
      .column_text("text", [](const InstructionOperandRow &row) -> std::string {
        qstring text;
        print_operand(&text, row.ea, row.opnum);
        tag_remove(&text);
        return text.c_str();
      })
      .column_int("type_code", [](const InstructionOperandRow &row) -> int {
        insn_t insn;
        op_t op;
        if (!decode_operand(row.ea, row.opnum, insn, op, nullptr))
          return 0;
        return static_cast<int>(op.type);
      })
      .column_text("type_name",
                   [](const InstructionOperandRow &row) -> std::string {
                     insn_t insn;
                     op_t op;
                     if (!decode_operand(row.ea, row.opnum, insn, op, nullptr))
                       return "";
                     return operand_type_name(op.type);
                   })
      .column_int("dtype", [](const InstructionOperandRow &row) -> int {
        insn_t insn;
        op_t op;
        if (!decode_operand(row.ea, row.opnum, insn, op, nullptr))
          return 0;
        return static_cast<int>(op.dtype);
      })
      .column_int("reg", [](const InstructionOperandRow &row) -> int {
        insn_t insn;
        op_t op;
        if (!decode_operand(row.ea, row.opnum, insn, op, nullptr))
          return 0;
        return op.reg;
      })
      .column_int64("op_addr", [](const InstructionOperandRow &row) -> int64_t {
        insn_t insn;
        op_t op;
        if (!decode_operand(row.ea, row.opnum, insn, op, nullptr))
          return 0;
        return static_cast<int64_t>(op.addr);
      })
      .column_int64("raw_value",
                    [](const InstructionOperandRow &row) -> int64_t {
                      insn_t insn;
                      op_t op;
                      if (!decode_operand(row.ea, row.opnum, insn, op, nullptr))
                        return 0;
                      return static_cast<int64_t>(op.value);
                    })
      .column_int64("value", [](const InstructionOperandRow &row) -> int64_t {
        insn_t insn;
        op_t op;
        if (!decode_operand(row.ea, row.opnum, insn, op, nullptr))
          return 0;
        return operand_value_for_row(op);
      })
      .filter_eq(
          "addr",
          [](int64_t address) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<InstructionOperandsAtAddressIterator>(
                static_cast<ea_t>(address));
          },
          1.0, 4.0)
      .filter_eq(
          "func_addr",
          [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<InstructionOperandsInFuncIterator>(
                static_cast<ea_t>(func_addr));
          },
          200.0)
      .build();
}

} // namespace code
} // namespace idasql
