// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_member_xrefs.hpp"

#include "types_members.hpp" // get_type_ordinal_by_name
#include "xrefs.hpp"

#include <algorithm>
#include <set>

namespace idasql {
namespace types {

namespace {

constexpr int kMaxNestDepth = 16;     // guard against pathological nesting
constexpr int kMaxStroffPath = 32;    // tid path buffer for get_stroff_path

// A resolved leaf member to enumerate xrefs for. `type_ordinal`/`type_name` are
// always the top-level queried type; `member_path` is the dotted path to the
// (possibly nested) member; `offset_bits` is cumulative within the top type.
struct LeafMember {
  uint32_t type_ordinal;
  std::string type_name;
  int member_index;        // index within the immediate containing type
  std::string member_name; // leaf name
  std::string member_path; // dotted path from the queried type
  int64_t offset_bits;     // cumulative bit offset within the queried type
  tid_t member_id;
};

// Recursively collect a type's members (and embedded value struct/union members)
// into `out`. `tif` is the type currently being walked; `top_*` stay constant.
void expand_members(const tinfo_t &tif, uint32_t top_ord,
                    const std::string &top_name, int64_t base_off_bits,
                    const std::string &path_prefix, std::set<uint32_t> &visited,
                    int depth, std::vector<LeafMember> &out) {
  if (depth > kMaxNestDepth) return;
  udt_type_data_t udt;
  if (!tif.get_udt_details(&udt)) return;

  til_t *ti = get_idati();
  for (size_t i = 0; i < udt.size(); ++i) {
    const udm_t &m = udt[i];
    LeafMember lm;
    lm.type_ordinal = top_ord;
    lm.type_name = top_name;
    lm.member_index = static_cast<int>(i);
    lm.member_name = m.name.c_str();
    lm.member_path = path_prefix.empty() ? lm.member_name
                                         : path_prefix + lm.member_name;
    lm.offset_bits = base_off_bits + static_cast<int64_t>(m.offset);
    lm.member_id = tif.get_udm_tid(i);
    out.push_back(lm);

    // Recurse into embedded value struct/union members (not pointers/arrays --
    // those are references, not containment).
    if (m.type.is_struct() || m.type.is_union()) {
      qstring nested_name;
      uint32_t nested_ord = 0;
      const bool named = m.type.get_type_name(&nested_name) && !nested_name.empty();
      if (named) {
        const int ord = get_type_ordinal_by_name(ti, nested_name.c_str());
        nested_ord = ord > 0 ? static_cast<uint32_t>(ord) : 0;
        if (nested_ord != 0 && visited.count(nested_ord)) {
          continue; // cycle guard (self-referential by value)
        }
        if (nested_ord != 0) visited.insert(nested_ord);
      }
      expand_members(m.type, top_ord, top_name, lm.offset_bits,
                     lm.member_path + ".", visited, depth + 1, out);
      if (named && nested_ord != 0) visited.erase(nested_ord);
    }
  }
}

std::vector<LeafMember> resolve_by_ordinal(uint32_t ordinal) {
  std::vector<LeafMember> leaves;
  til_t *ti = get_idati();
  if (!ti) return leaves;
  const char *name = get_numbered_type_name(ti, ordinal);
  if (!name) return leaves;
  tinfo_t tif;
  if (!tif.get_numbered_type(ti, ordinal)) return leaves;
  if (!(tif.is_struct() || tif.is_union())) return leaves;
  std::set<uint32_t> visited{ordinal};
  expand_members(tif, ordinal, name, 0, "", visited, 0, leaves);
  return leaves;
}

std::vector<LeafMember> resolve_by_name(const char *type_name) {
  til_t *ti = get_idati();
  const int ord = get_type_ordinal_by_name(ti, type_name);
  if (ord <= 0) return {};
  return resolve_by_ordinal(static_cast<uint32_t>(ord));
}

std::vector<LeafMember> resolve_by_member_id(tid_t tid) {
  std::vector<LeafMember> leaves;
  tinfo_t owner;
  udm_t udm;
  const ssize_t idx = get_udm_by_tid(&owner, &udm, tid);
  if (idx < 0) return leaves;
  qstring oname;
  owner.get_type_name(&oname);
  const int ord = get_type_ordinal_by_name(get_idati(), oname.c_str());
  LeafMember lm;
  lm.type_ordinal = ord > 0 ? static_cast<uint32_t>(ord) : 0;
  lm.type_name = oname.c_str();
  lm.member_index = static_cast<int>(idx);
  lm.member_name = udm.name.c_str();
  lm.member_path = lm.member_name;
  lm.offset_bits = static_cast<int64_t>(udm.offset);
  lm.member_id = tid;
  leaves.push_back(lm);
  return leaves;
}

// The structure offset an operand's value encodes: the immediate for o_imm, the
// displacement for o_displ/o_mem, 0 for a bare register phrase.
adiff_t stroff_operand_value(const op_t &op) {
  switch (op.type) {
    case o_imm: return static_cast<adiff_t>(op.value);
    case o_phrase: return 0;
    default: return static_cast<adiff_t>(op.addr);
  }
}

// From byte offset `off` inside `cur`, walk member offsets down to member
// `want`. A union member is chosen by the next selector (`sel`, `nsel`: the
// stroff path's union selections); a union with no selector left is ambiguous.
// Fills the byte offset of the access inside `want`.
bool walk_to_member(tinfo_t cur, int64_t off, const tid_t *sel, int nsel, tid_t want,
                    int64_t &off_in_member) {
  for (int depth = 0; depth <= kMaxNestDepth && off >= 0; ++depth) {
    udm_t udm;
    tid_t member_tid = BADADDR;
    if (cur.is_union()) {
      if (nsel <= 0) return false;
      tinfo_t owner;
      if (get_udm_by_tid(&owner, &udm, *sel) < 0) return false;
      member_tid = *sel++;
      --nsel;
    } else {
      udm.offset = static_cast<uint64>(off) * 8;
      const int idx = cur.find_udm(&udm, STRMEM_OFFSET);
      if (idx < 0) return false;
      member_tid = cur.get_udm_tid(idx);
    }
    const int64_t member_byte = static_cast<int64_t>(udm.offset / 8);
    if (member_tid == want) {
      off_in_member = off - member_byte;
      return true;
    }
    if (!(udm.type.is_struct() || udm.type.is_union())) return false;
    off -= member_byte;
    cur = udm.type;
  }
  return false;
}

// Does operand n's struct-offset expression land on member `want`? The path
// IDA stores starts at the accessed structure (get_stroff_path: ids[0] is the
// structure; further ids only select union members), so the member is found by
// walking offsets down from that root: value + delta is the offset inside it.
// Fills the byte offset of the access inside the member and the root type's name.
bool stroff_hits_member(const insn_t &insn, int n, tid_t want, int64_t &off_in_member,
                        qstring &root_name) {
  tid_t path[kMaxStroffPath];
  adiff_t delta = 0;
  const int cnt = get_stroff_path(path, &delta, insn.ea, n);
  if (cnt <= 0) return false;
  tinfo_t root;
  if (!root.get_type_by_tid(path[0])) return false;
  root.get_type_name(&root_name);
  const int64_t off =
      static_cast<int64_t>(stroff_operand_value(insn.ops[n])) + static_cast<int64_t>(delta);
  return walk_to_member(root, off, path + 1, std::min(cnt, kMaxStroffPath) - 1, want, off_in_member);
}

// Does stack-variable operand n land on member `want`? The operand names a
// frame location (calc_stkvar_struc_offset); the frame member there is the
// variable, and when its type is a structure the walk continues inside it
// (`[ebp+entry.balance]`). Fills the access's offset inside the member and the
// variable's type name.
bool stkvar_hits_member(const insn_t &insn, int n, tid_t want, int64_t &off_in_member,
                        qstring &root_name) {
  tinfo_t frame;
#if IDASQL_HAS_EA_API
  const ea_t start = get_func_start(insn.ea);
  if (start == BADADDR || !get_func_frame_ea(&frame, start)) return false;
  const ea_t frame_off = calc_stkvar_struc_offset_ea(start, insn, n);
#else
  func_t *pfn = get_func(insn.ea);
  if (pfn == nullptr || !get_func_frame(&frame, pfn)) return false;
  const ea_t frame_off = calc_stkvar_struc_offset(pfn, insn, n);
#endif
  if (frame_off == BADADDR) return false;
  udm_t var;
  var.offset = static_cast<uint64>(frame_off) * 8;
  if (frame.find_udm(&var, STRMEM_OFFSET) < 0) return false;
  if (!(var.type.is_struct() || var.type.is_union())) return false;
  var.type.get_type_name(&root_name);
  return walk_to_member(var.type, static_cast<int64_t>(frame_off) - static_cast<int64_t>(var.offset / 8),
                        nullptr, 0, want, off_in_member);
}

// Iterator: walks the resolved leaf members, and for each enumerates xrefs to
// its member tid. Leaves with no xrefs are skipped (produce no rows).
class MemberXrefsIterator : public xsql::RowIterator {
public:
  explicit MemberXrefsIterator(std::vector<LeafMember> leaves)
      : leaves_(std::move(leaves)) {}

  bool next() override {
    if (!started_) {
      started_ = true;
      leaf_idx_ = 0;
      return advance_to_leaf();
    }
    if (valid_ && xb_.next_to()) {
      ++row_counter_;
      populate_row();
      return true;
    }
    ++leaf_idx_;
    return advance_to_leaf();
  }

  bool eof() const override { return started_ && !valid_; }

  void column(xsql::FunctionContext &ctx, int col) override {
    if (!valid_) { ctx.result_null(); return; }
    const LeafMember &lm = leaves_[leaf_idx_];
    switch (col) {
      case 0:  ctx.result_int(static_cast<int>(lm.type_ordinal)); break;
      case 1:  ctx.result_text(lm.type_name.c_str()); break;
      case 2:  ctx.result_int(lm.member_index); break;
      case 3:  ctx.result_text(lm.member_name.c_str()); break;
      case 4:  ctx.result_text(lm.member_path.c_str()); break;
      case 5:  ctx.result_int64(lm.offset_bits / 8); break;
      case 6:  ctx.result_int64(lm.offset_bits); break;
      case 7:  ctx.result_int64(static_cast<int64_t>(lm.member_id)); break;
      case 8:  ctx.result_int64(static_cast<int64_t>(frm_)); break;
      case 9:  ctx.result_int64(static_cast<int64_t>(lm.member_id)); break; // xref_to
      case 10: ctx.result_int(static_cast<int>(xb_.type)); break;
      case 11: ctx.result_text(kind_.c_str()); break;
      case 12: func_ea_ != BADADDR ? ctx.result_int64(static_cast<int64_t>(func_ea_))
                                   : ctx.result_null(); break;
      case 13: func_ea_ != BADADDR ? ctx.result_text(func_name_.c_str())
                                   : ctx.result_null(); break;
      case 14: op_ok_ ? ctx.result_int(op_index_) : ctx.result_null(); break;
      case 15: insn_ok_ ? ctx.result_text(insn_text_.c_str()) : ctx.result_null(); break;
      case 16: op_ok_ ? ctx.result_int64(access_off_) : ctx.result_null(); break;
      case 17: op_ok_ && access_size_ >= 0 ? ctx.result_int64(access_size_) : ctx.result_null(); break;
      case 18: op_ok_ && !access_root_.empty() ? ctx.result_text(access_root_.c_str())
                                               : ctx.result_null(); break;
      default: ctx.result_null(); break;
    }
  }

  int64_t rowid() const override { return row_counter_; }

private:
  bool advance_to_leaf() {
    while (leaf_idx_ < leaves_.size()) {
      const tid_t tid = leaves_[leaf_idx_].member_id;
      if (tid != 0 && tid != BADADDR &&
          xb_.first_to(static_cast<ea_t>(tid), XREF_ALL)) {
        valid_ = true;
        ++row_counter_;
        populate_row();
        return true;
      }
      ++leaf_idx_;
    }
    valid_ = false;
    return false;
  }

  // Compute per-row context (function + best-effort operand/access/disasm).
  void populate_row() {
    frm_ = xb_.from;
    func_ea_ = idasql_func_start(frm_);
    func_name_.qclear();
    if (func_ea_ != BADADDR) get_func_name(&func_name_, frm_);
    kind_ = xref_kind_str(xb_.iscode, xb_.type);

    insn_ok_ = false;
    op_ok_ = false;
    op_index_ = -1;
    access_off_ = -1;
    access_size_ = -1;
    access_root_.qclear();
    insn_text_.qclear();

    insn_t insn;
    if (decode_insn(&insn, frm_) > 0) {
      insn_ok_ = true;
      generate_disasm_line(&insn_text_, frm_, 0);
      tag_remove(&insn_text_);

      const tid_t mtid = leaves_[leaf_idx_].member_id;
      const flags64_t flags = get_flags(frm_);
      for (int n = 0; n < UA_MAXOP && insn.ops[n].type != o_void; ++n) {
        int64_t in_member = 0;
        const bool hit =
            (is_stroff(flags, n) && stroff_hits_member(insn, n, mtid, in_member, access_root_)) ||
            (is_stkvar(flags, n) && stkvar_hits_member(insn, n, mtid, in_member, access_root_));
        if (hit) {
          op_ok_ = true;
          op_index_ = n;
          access_off_ = in_member;
          // Taking the member's address (an offset-of immediate, an lea) touches
          // no memory: no access size.
          access_size_ = insn.ops[n].type == o_imm || xb_.type == dr_O
                             ? -1
                             : static_cast<int64_t>(get_dtype_size(insn.ops[n].dtype));
          break;
        }
        access_root_.qclear();
      }
    }
  }

  std::vector<LeafMember> leaves_;
  size_t leaf_idx_ = 0;
  bool started_ = false;
  bool valid_ = false;
  xrefblk_t xb_{};
  int64_t row_counter_ = 0;

  // current-row context
  ea_t frm_ = BADADDR;
  ea_t func_ea_ = BADADDR;
  qstring func_name_;
  std::string kind_;
  bool insn_ok_ = false;
  bool op_ok_ = false;
  int op_index_ = -1;
  int64_t access_off_ = -1;
  int64_t access_size_ = -1;
  qstring access_root_;
  qstring insn_text_;
};

} // namespace

GeneratorTableDef<MemberXrefRow> define_struct_member_xrefs() {
  return generator_table<MemberXrefRow>("struct_member_xrefs")
      .estimate_rows([]() -> size_t { return 64; })
      // Unfiltered full scan is rejected: enumerating every member of every type
      // is the expensive pattern this table's filters exist to avoid. Require an entry filter.
      .full_scan_error(
          "struct_member_xrefs requires a filter on type_ordinal, type_name, "
          "or member_id (e.g. WHERE type_name = 'MyStruct').")
      .column_int("type_ordinal",
                  [](const MemberXrefRow &r) { return static_cast<int>(r.type_ordinal); })
      .column_text("type_name", [](const MemberXrefRow &r) { return r.type_name; })
      .column_int("member_index", [](const MemberXrefRow &r) { return r.member_index; })
      .column_text("member_name", [](const MemberXrefRow &r) { return r.member_name; })
      .column_text("member_path", [](const MemberXrefRow &r) { return r.member_path; })
      .column_int64("member_offset", [](const MemberXrefRow &r) { return r.member_offset; })
      .column_int64("member_offset_bits", [](const MemberXrefRow &r) { return r.member_offset_bits; })
      .column_int64("member_id", [](const MemberXrefRow &r) { return static_cast<int64_t>(r.member_id); })
      .column_int64("xref_from", [](const MemberXrefRow &r) { return static_cast<int64_t>(r.xref_from); })
      .column_int64("xref_to", [](const MemberXrefRow &r) { return static_cast<int64_t>(r.xref_to); })
      .column_int("xref_type", [](const MemberXrefRow &r) { return r.xref_type; })
      .column_text("xref_kind", [](const MemberXrefRow &r) { return r.xref_kind; })
      .column_int64("function_addr", [](const MemberXrefRow &r) { return static_cast<int64_t>(r.function_address); })
      .column_text("function_name", [](const MemberXrefRow &r) { return r.function_name; })
      .column_int("operand_index", [](const MemberXrefRow &r) { return r.operand_index; })
      .column_text("instruction_text", [](const MemberXrefRow &r) { return r.instruction_text; })
      .column_int64("access_offset", [](const MemberXrefRow &r) { return r.access_offset; })
      .column_int64("access_size", [](const MemberXrefRow &r) { return r.access_size; })
      // The structure the operand's offset expression starts from. A nested row
      // (member_path a.b) is an access through the queried type only when this
      // equals type_name; otherwise it is an xref to the embedded type's member
      // from elsewhere.
      .column_text("access_root_type", [](const MemberXrefRow &r) { return r.access_root_type; })
      .filter_eq(
          "type_ordinal",
          [](int64_t ord) -> std::unique_ptr<xsql::RowIterator> {
            // Type ordinals are uint32; reject anything out of range rather than
            // truncating (e.g. 4294967297 -> 1 would resolve ordinal-1's members).
            if (ord <= 0 || ord > static_cast<int64_t>(UINT32_MAX))
              return std::make_unique<MemberXrefsIterator>(std::vector<LeafMember>{});
            return std::make_unique<MemberXrefsIterator>(
                resolve_by_ordinal(static_cast<uint32_t>(ord)));
          },
          1.0, 20.0)
      .filter_eq_text(
          "type_name",
          [](const char *name) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<MemberXrefsIterator>(
                resolve_by_name(name ? name : ""));
          },
          1.0, 20.0)
      .filter_eq(
          "member_id",
          [](int64_t tid) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<MemberXrefsIterator>(
                resolve_by_member_id(static_cast<tid_t>(tid)));
          },
          0.5, 10.0)
      .build();
}

} // namespace types
} // namespace idasql
