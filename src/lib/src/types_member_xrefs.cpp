// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types_member_xrefs.hpp"

#include "types_members.hpp" // get_type_ordinal_by_name

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

// Human-readable xref kind from xrefblk_t's iscode + (masked) type.
std::string xref_kind_str(bool iscode, uchar type) {
  const uchar t = static_cast<uchar>(type & XREF_MASK);
  if (iscode) {
    switch (t) {
      case fl_CF: case fl_CN: return "call";
      case fl_JF: case fl_JN: return "jump";
      case fl_F:              return "flow";
      default:                return "code";
    }
  }
  switch (t) {
    case dr_O: return "offset";
    case dr_W: return "write";
    case dr_R: return "read";
    case dr_T: return "text";
    case dr_I: return "info";
    default:   return "data";
  }
}

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
      case 17: op_ok_ ? ctx.result_int64(access_size_) : ctx.result_null(); break;
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
    func_t *f = get_func(frm_);
    func_ea_ = f ? f->start_ea : BADADDR;
    func_name_.qclear();
    if (f) get_func_name(&func_name_, frm_);
    kind_ = xref_kind_str(xb_.iscode, xb_.type);

    insn_ok_ = false;
    op_ok_ = false;
    op_index_ = -1;
    access_off_ = -1;
    access_size_ = -1;
    insn_text_.qclear();

    insn_t insn;
    if (decode_insn(&insn, frm_) > 0) {
      insn_ok_ = true;
      generate_disasm_line(&insn_text_, frm_, 0);
      tag_remove(&insn_text_);

      const tid_t mtid = leaves_[leaf_idx_].member_id;
      for (int n = 0; n < UA_MAXOP; ++n) {
        if (insn.ops[n].type == o_void) break;
        tid_t path[kMaxStroffPath];
        adiff_t delta = 0;
        const int cnt = get_stroff_path(path, &delta, frm_, n);
        for (int k = 0; k < cnt && k < kMaxStroffPath; ++k) {
          if (path[k] == mtid) {
            op_ok_ = true;
            op_index_ = n;
            access_off_ = static_cast<int64_t>(delta);
            access_size_ = static_cast<int64_t>(get_dtype_size(insn.ops[n].dtype));
            break;
          }
        }
        if (op_ok_) break;
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
  qstring insn_text_;
};

} // namespace

CachedTableDef<MemberXrefRow> define_struct_member_xrefs() {
  return cached_table<MemberXrefRow>("struct_member_xrefs")
      .no_shared_cache()
      .estimate_rows([]() -> size_t { return 64; })
      // Unfiltered full scan is rejected: enumerating every member of every type
      // is the expensive pattern this table's filters exist to avoid. Require an entry filter.
      .cache_builder([](std::vector<MemberXrefRow> &) {
        xsql::set_vtab_error(
            "struct_member_xrefs requires a filter on type_ordinal, type_name, "
            "or member_id (e.g. WHERE type_name = 'MyStruct').");
      })
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
