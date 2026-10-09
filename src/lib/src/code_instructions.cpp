// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_instructions.hpp"

#include "function_rowid.hpp"

#include <unordered_map>
#include <unordered_set>

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
    // NULL for code outside every function (as xrefs.from_func): 0 would be a
    // key no func_addr pushdown can find, and a real function may start at 0.
    if (func_addr != BADADDR)
      ctx.result_int64(static_cast<int64_t>(func_addr));
    else
      ctx.result_null();
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
// INSTRUCTIONS Table - Row identity
// ============================================================================

// The (owner, address) behind every rowid this table reported. A rowid packs
// the owner's function ordinal and the address's position in that function's
// chunk layout, and a DELETE changes both: once instructions are undefined IDA
// shrinks or drops the function, so the remaining rowids of the same statement
// stop decoding live ("row 6 not found in instructions" for a range DELETE over
// a whole function), and a decode against a renumbered function list could even
// land on another function's instruction. SQLite hands xUpdate only rowids its
// scan of the same statement just reported, so resolving through this map names
// exactly the row the scan saw. Refreshed on every report; cleared with
// deleted_instruction_heads() when a writing statement commits or rolls back
// (the table's transaction hooks), never by a scan: a statement can scan the
// table more than once (an IN subquery, a self-join).
static std::unordered_map<int64_t, std::pair<ea_t, ea_t>> &
reported_instruction_rows() {
  static std::unordered_map<int64_t, std::pair<ea_t, ea_t>> rows;
  return rows;
}

static int64_t report_instruction_rowid(ea_t owner, ea_t ea) {
  const int64_t rowid = idasql::detail::pack_owned_address_rowid(owner, ea);
  if (rowid >= 0)
    reported_instruction_rows()[rowid] = {owner, ea};
  return rowid;
}

// ============================================================================
// INSTRUCTIONS Table - Iterators
// ============================================================================

InstructionsInFuncIterator::InstructionsInFuncIterator(ea_t func_addr)
    : func_addr_(func_addr) {
  if (!idasql_is_func_start(func_addr_))
    return;
  // Scoped: the iterator's function lock is released before any row is used.
  idasql_func_item_iterator fii;
  for (bool ok = fii.set(func_addr_); ok; ok = fii.next_code()) {
    const ea_t ea = fii.current();
    if (is_code(get_flags(ea)))
      eas_.push_back(ea);
  }
}

bool InstructionsInFuncIterator::next() {
  if (!started_) {
    started_ = true;
    idx_ = 0;
  } else if (valid_) {
    ++idx_;
  }
  valid_ = idx_ < eas_.size();
  if (valid_)
    current_ea_ = eas_[idx_];
  return valid_;
}

bool InstructionsInFuncIterator::eof() const { return started_ && !valid_; }

void InstructionsInFuncIterator::column(xsql::FunctionContext &ctx, int col) {
  instruction_column_common(ctx, current_ea_, func_addr_, col);
}

int64_t InstructionsInFuncIterator::rowid() const {
  return report_instruction_rowid(func_addr_, current_ea_);
}

// The functions an instruction is reported under: every owner of its chunk, or
// a single BADADDR entry (func_addr NULL) for code outside every function.
static std::vector<ea_t> instruction_owners(ea_t ea) {
  std::vector<ea_t> owners;
  idasql_for_each_owner_of(ea, [&](ea_t owner) { owners.push_back(owner); });
  if (owners.empty())
    owners.push_back(BADADDR);
  return owners;
}

// func_addr as SQL sees it: the owner, or NULL outside every function.
static void result_owner(xsql::FunctionContext &ctx, ea_t owner) {
  if (owner != BADADDR)
    ctx.result_int64(static_cast<int64_t>(owner));
  else
    ctx.result_null();
}

// Instructions this table deleted. A shared-tail instruction is one row per
// owner, so `DELETE ... WHERE addr = X` deletes it through the first owner's
// row and then reaches the other owners' rows: those resolve as already gone
// (a no-op) instead of failing the statement. Cleared when the statement ends.
static std::unordered_set<ea_t> &deleted_instruction_heads() {
  static std::unordered_set<ea_t> heads;
  return heads;
}

InstructionAtAddressIterator::InstructionAtAddressIterator(ea_t ea) : ea_(ea) {
  if (ea_ != BADADDR && is_code(get_flags(ea_)))
    owners_ = instruction_owners(ea_);
}

bool InstructionAtAddressIterator::next() {
  if (!started_) {
    started_ = true;
    idx_ = 0;
  } else if (valid_) {
    ++idx_;
  }
  valid_ = idx_ < owners_.size();
  return valid_;
}

bool InstructionAtAddressIterator::eof() const { return started_ && !valid_; }

void InstructionAtAddressIterator::column(xsql::FunctionContext &ctx, int col) {
  if (!valid_) {
    ctx.result_null();
    return;
  }
  instruction_column_common(ctx, ea_, owners_[idx_], col);
}

int64_t InstructionAtAddressIterator::rowid() const {
  return valid_ ? report_instruction_rowid(owners_[idx_], ea_) : 0;
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
      for (ea_t owner : instruction_owners(ea))
        rows.push_back({ea, owner});
    }
    ea = next_head(ea, max_ea);
  }
}

CachedTableDef<InstructionRow> define_instructions() {
  auto builder =
      cached_table<InstructionRow>("instructions")
          .no_shared_cache()
          .estimate_rows([]() -> size_t { return estimate_code_heads(); })
          .cache_builder([](std::vector<InstructionRow> &rows) {
            collect_instruction_rows(rows);
          })
          // The row bookkeeping lives for one writing statement (or explicit
          // transaction): released when it commits or rolls back.
          .transaction_hooks([] {
            xsql::TransactionHooks hooks;
            hooks.commit = [](const xsql::TransactionHooks::State &) {
              reported_instruction_rows().clear();
              deleted_instruction_heads().clear();
            };
            hooks.rollback = hooks.commit;
            return hooks;
          }())
          // Stable rowid = (owning function, address): the full scan and both
          // filter iterators report the same key for the same row. The owner is
          // part of it because an instruction in a tail shared by functions A
          // and C is two rows, and SQLite de-duplicates a MULTI-INDEX OR plan by
          // rowid -- an address-only rowid dropped C's rows from
          // `func_addr = A OR (func_addr = C AND ...)`. The key is a byte
          // position, not an instruction ordinal, but a DELETE can still reshape
          // the function under it, so UPDATE/DELETE resolve it through
          // reported_instruction_rows() first.
          .rowid([](const InstructionRow &row) -> int64_t {
            return report_instruction_rowid(row.owner, row.ea);
          })
          .row_lookup([](InstructionRow &row, int64_t rowid) -> bool {
            // Resolve the key back to (owner, ea). No positional fallback --
            // with rowid_fn set, every scan reports a key, never a cache index.
            ea_t owner = BADADDR;
            ea_t ea = BADADDR;
            const auto &reported = reported_instruction_rows();
            if (auto it = reported.find(rowid); it != reported.end()) {
              owner = it->second.first;
              ea = it->second.second;
            } else {
              uint32_t sub = 0;
              if (!idasql::detail::unpack_owned_address_rowid(rowid, 0, owner,
                                                              ea, sub))
                return false;
            }
            if (ea != BADADDR && is_code(get_flags(ea)) &&
                get_item_head(ea) == ea) {
              row.ea = ea;
              row.owner = owner;
              row.gone = false;
              return true;
            }
            if (owner != BADADDR && deleted_instruction_heads().count(ea) != 0) {
              row.ea = ea;
              row.owner = owner;
              row.gone = true;
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
      .column("func_addr", xsql::ColumnType::Integer,
              [](xsql::FunctionContext &ctx, const InstructionRow &row) {
                result_owner(ctx, row.owner);
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
          if (row.gone) {
            xsql::set_vtab_error("instruction was deleted earlier in this statement");
            return false;
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
        if (row.gone)
          return true; // deleted through another owner's row of this statement
        idasql_auto_wait();
        asize_t sz = get_item_size(row.ea);
        bool ok = del_items(row.ea, DELIT_SIMPLE, sz);
        idasql_auto_wait();
        if (!ok) {
          char buf[64];
          qsnprintf(buf, sizeof(buf), "0x%llX",
                    static_cast<unsigned long long>(row.ea));
          xsql::set_vtab_error(
              std::string("IDA refused to undefine the instruction at ") + buf);
          return false;
        }
        // del_items succeeds, and auto-analysis re-creates an instruction that
        // code still flows into (the one before it falls through, or a jump
        // lands on it). Report that instead of a deleted row.
        if (is_code(get_flags(row.ea))) {
          char buf[64];
          qsnprintf(buf, sizeof(buf), "0x%llX",
                    static_cast<unsigned long long>(row.ea));
          xsql::set_vtab_error(
              std::string("instructions: the instruction at ") + buf +
              " was re-created by auto-analysis, because code still flows into "
              "it; delete the instructions that reach it in the same statement "
              "(e.g. the whole function's range) or undefine the function first");
          return false;
        }
        deleted_instruction_heads().insert(row.ea);
        return true;
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

// (owning function, address, operand number): see the instructions rowid.
static_assert(UA_MAXOP <= 8, "operand number must fit the 3-bit rowid field");
static int64_t instruction_operand_rowid(ea_t owner, ea_t ea, int opnum) {
  return idasql::detail::pack_owned_address_rowid(
      owner, ea, static_cast<uint32_t>(opnum), 3);
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
                                       ea_t func_addr, int opnum, int col) {
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
  case 1:
    result_owner(ctx, func_addr);
    break;
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
        const std::vector<ea_t> owners = instruction_owners(ea);
        for (int opnum = 0; opnum < UA_MAXOP; ++opnum) {
          // Skip void slots but keep scanning all UA_MAXOP operands: some IDPs
          // leave gaps (a real operand after a void), and the pushdown
          // iterators 'continue' past voids -- 'break' here would make
          // full-scan and filtered results disagree.
          if (insn.ops[opnum].type == o_void)
            continue;
          for (ea_t owner : owners)
            rows.push_back({ea, opnum, owner});
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

// Operands of the instruction once per owner: all operands under the first
// owner, then all under the next.
bool InstructionOperandsAtAddressIterator::next() {
  if (!started_) {
    started_ = true;
    decoded_ = (ea_ != BADADDR) && is_code(get_flags(ea_)) &&
               decode_insn(&insn_, ea_) > 0;
    if (decoded_)
      owners_ = instruction_owners(ea_);
    owner_idx_ = 0;
    valid_ = decoded_ && advance_to_next_operand();
    return valid_;
  }

  if (!decoded_) {
    valid_ = false;
    return false;
  }
  valid_ = advance_to_next_operand();
  if (!valid_ && owner_idx_ + 1 < owners_.size()) {
    ++owner_idx_;
    opnum_ = -1;
    valid_ = advance_to_next_operand();
  }
  return valid_;
}

bool InstructionOperandsAtAddressIterator::eof() const {
  return started_ && !valid_;
}

void InstructionOperandsAtAddressIterator::column(xsql::FunctionContext &ctx,
                                                  int col) {
  if (!valid_) {
    ctx.result_null();
    return;
  }
  instruction_operand_column_common(ctx, ea_, owners_[owner_idx_], opnum_, col);
}

int64_t InstructionOperandsAtAddressIterator::rowid() const {
  return valid_ ? instruction_operand_rowid(owners_[owner_idx_], ea_, opnum_)
                : 0;
}

InstructionOperandsInFuncIterator::InstructionOperandsInFuncIterator(
    ea_t func_addr)
    : func_addr_(func_addr) {
  if (!idasql_is_func_start(func_addr_))
    return;
  // Scoped: a live function item iterator locks the function, and a cursor
  // stays open until its statement ends (a subquery cursor of a DELETE would
  // keep IDA from undefining the function's instructions).
  idasql_func_item_iterator fii;
  for (bool ok = fii.set(func_addr_); ok; ok = fii.next_code())
    eas_.push_back(fii.current());
}

bool InstructionOperandsInFuncIterator::load_current_instruction() {
  if (ea_idx_ >= eas_.size())
    return false;
  current_ea_ = eas_[ea_idx_];
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
  while (ea_idx_ < eas_.size()) {
    if (load_current_instruction() && advance_to_next_operand())
      return true;
    ++ea_idx_;
  }
  return false;
}

bool InstructionOperandsInFuncIterator::next() {
  if (!started_) {
    started_ = true;
    valid_ = advance_to_next_instruction_with_operand();
    return valid_;
  }

  if (valid_ && advance_to_next_operand())
    return true;

  ++ea_idx_;
  valid_ = advance_to_next_instruction_with_operand();
  return valid_;
}

bool InstructionOperandsInFuncIterator::eof() const {
  return started_ && !valid_;
}

void InstructionOperandsInFuncIterator::column(xsql::FunctionContext &ctx,
                                               int col) {
  // The queried function, not the tail's primary owner: a shared tail's
  // operands belong to every owner, and the pushdown is asked for this one.
  instruction_operand_column_common(ctx, current_ea_, func_addr_, opnum_, col);
}

int64_t InstructionOperandsInFuncIterator::rowid() const {
  return instruction_operand_rowid(func_addr_, current_ea_, opnum_);
}

CachedTableDef<InstructionOperandRow> define_instruction_operands() {
  return cached_table<InstructionOperandRow>("instruction_operands")
      .no_shared_cache()
      .estimate_rows([]() -> size_t { return estimate_code_heads() * 2; })
      .cache_builder([](std::vector<InstructionOperandRow> &rows) {
        collect_instruction_operand_rows(rows);
      })
      .rowid([](const InstructionOperandRow &row) -> int64_t {
        return instruction_operand_rowid(row.owner, row.ea, row.opnum);
      })
      .column_int64("addr",
                    [](const InstructionOperandRow &row) -> int64_t {
                      return static_cast<int64_t>(row.ea);
                    })
      .column("func_addr", xsql::ColumnType::Integer,
              [](xsql::FunctionContext &ctx, const InstructionOperandRow &row) {
                result_owner(ctx, row.owner);
              })
      .column_int("operand_index", [](const InstructionOperandRow &row) -> int {
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
