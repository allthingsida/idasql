// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "code_operand_repr.hpp"

#include "decompiler.hpp"

using namespace idasql::core;

namespace idasql {
namespace code {

// ============================================================================
// INSTRUCTIONS Table helpers and parsing
// ============================================================================

// trim_copy is now in <idasql/string_utils.hpp>

void split_path_names(const std::string &path_spec,
                      std::vector<std::string> &out_names) {
  out_names.clear();
  size_t start = 0;
  while (start <= path_spec.size()) {
    const size_t slash = path_spec.find('/', start);
    const size_t end = (slash == std::string::npos) ? path_spec.size() : slash;
    std::string piece = trim_copy(path_spec.substr(start, end - start));
    if (!piece.empty()) {
      out_names.push_back(piece);
    }
    if (slash == std::string::npos)
      break;
    start = slash + 1;
  }
}

// Resolve an offset base spec: either a symbol name or a numeric address.
bool resolve_ea_spec(const std::string &spec, ea_t &out_ea) {
  const std::string trimmed = trim_copy(spec);
  if (trimmed.empty())
    return false;
  const ea_t named = get_name_ea(BADADDR, trimmed.c_str());
  if (named != BADADDR) {
    out_ea = named;
    return true;
  }
  int64_t value = 0;
  if (parse_int64(trimmed, value)) {
    out_ea = static_cast<ea_t>(value);
    return true;
  }
  return false;
}

// Recognize a standalone sign/bnot modifier token (,signed / ,unsigned /
// ,bnot / ,nobnot). Sets the matching mode and returns true on a match.
bool match_operand_modifier(const std::string &token, OperandModMode &sign_mode,
                            OperandModMode &bnot_mode) {
  if (equals_ci(token, "signed")) {
    sign_mode = OperandModMode::On;
    return true;
  }
  if (equals_ci(token, "unsigned")) {
    sign_mode = OperandModMode::Off;
    return true;
  }
  if (equals_ci(token, "bnot")) {
    bnot_mode = OperandModMode::On;
    return true;
  }
  if (equals_ci(token, "nobnot")) {
    bnot_mode = OperandModMode::Off;
    return true;
  }
  return false;
}

// Strip trailing ,signed/,unsigned/,bnot/,nobnot tokens from the spec so the
// remaining text is the base representation. Base options such as ",serial="
// and ",delta=" are not modifiers and stop the scan.
void strip_trailing_modifiers(std::string &text, OperandModMode &sign_mode,
                              OperandModMode &bnot_mode) {
  for (;;) {
    const size_t comma = text.rfind(',');
    const std::string tail =
        trim_copy(comma == std::string::npos ? text : text.substr(comma + 1));
    if (!match_operand_modifier(tail, sign_mode, bnot_mode))
      break;
    if (comma == std::string::npos) {
      text.clear();
      break;
    }
    text = trim_copy(text.substr(0, comma));
  }
}

bool parse_operand_format_spec(const char *spec, OperandApplyRequest &out,
                               std::string *out_error) {
  if (out_error)
    out_error->clear();
  out = OperandApplyRequest{};
  if (!spec) {
    if (out_error)
      *out_error = "format spec is required";
    return false;
  }

  std::string text = trim_copy(spec);
  if (text.empty()) {
    if (out_error)
      *out_error = "format spec is empty";
    return false;
  }

  // Pull off any trailing sign/bnot modifiers; they combine with the base spec
  // or, when alone, modify the operand's current representation in place.
  strip_trailing_modifiers(text, out.sign_mode, out.bnot_mode);
  if (text.empty()) {
    out.kind = OperandApplyKind::Modifiers;
    return true;
  }

  if (equals_ci(text, "clear") || equals_ci(text, "plain") ||
      equals_ci(text, "none")) {
    out.kind = OperandApplyKind::Clear;
    return true;
  }

  if (equals_ci(text, "hex") || equals_ci(text, "dec") ||
      equals_ci(text, "oct") || equals_ci(text, "bin")) {
    out.kind = OperandApplyKind::NumBase;
    out.num_radix = equals_ci(text, "hex")   ? 16
                    : equals_ci(text, "dec") ? 10
                    : equals_ci(text, "oct") ? 8
                                             : 2;
    return true;
  }

  if (equals_ci(text, "char")) {
    out.kind = OperandApplyKind::Char;
    return true;
  }
  if (equals_ci(text, "float")) {
    out.kind = OperandApplyKind::Float;
    return true;
  }
  if (equals_ci(text, "segment") || equals_ci(text, "seg")) {
    out.kind = OperandApplyKind::Segment;
    return true;
  }
  if (equals_ci(text, "stkvar")) {
    out.kind = OperandApplyKind::StackVar;
    return true;
  }

  if (equals_ci(text, "offset")) {
    out.kind = OperandApplyKind::Offset;
    return true;
  }
  if (starts_with_ci(text, "offset:")) {
    out.offset_base = trim_copy(text.substr(7));
    if (out.offset_base.empty()) {
      if (out_error)
        *out_error = "offset spec requires a base symbol or address";
      return false;
    }
    out.kind = OperandApplyKind::Offset;
    return true;
  }

  if (starts_with_ci(text, "forced:")) {
    out.forced_text = trim_copy(text.substr(7));
    if (out.forced_text.empty()) {
      if (out_error)
        *out_error = "forced spec requires operand text";
      return false;
    }
    out.kind = OperandApplyKind::Forced;
    return true;
  }

  if (starts_with_ci(text, "sizeof:")) {
    out.sizeof_type = trim_copy(text.substr(7));
    if (out.sizeof_type.empty()) {
      if (out_error)
        *out_error = "sizeof spec requires a struct type name";
      return false;
    }
    out.kind = OperandApplyKind::Sizeof;
    return true;
  }

  if (starts_with_ci(text, "enum:")) {
    const std::string rest = trim_copy(text.substr(5));
    if (rest.empty()) {
      if (out_error)
        *out_error = "enum spec requires a type name";
      return false;
    }

    std::string enum_name = rest;
    std::string member_name;
    uchar serial = 0;
    bool has_serial = false;

    const size_t serial_pos = rest.find(",serial=");
    if (serial_pos != std::string::npos) {
      enum_name = trim_copy(rest.substr(0, serial_pos));
      const std::string serial_text = trim_copy(rest.substr(serial_pos + 8));
      int64_t serial64 = 0;
      if (!parse_int64(serial_text, serial64)) {
        if (out_error)
          *out_error = "enum serial must be an integer";
        return false;
      }
      if (serial64 < 0 || serial64 > 255) {
        if (out_error)
          *out_error = "enum serial must be in range [0,255]";
        return false;
      }
      serial = static_cast<uchar>(serial64);
      has_serial = true;
    }

    const size_t member_pos = enum_name.rfind("::");
    if (member_pos != std::string::npos) {
      member_name = trim_copy(enum_name.substr(member_pos + 2));
      enum_name = trim_copy(enum_name.substr(0, member_pos));
      if (member_name.empty()) {
        if (out_error)
          *out_error = "enum member name is empty";
        return false;
      }
      if (has_serial) {
        if (out_error)
          *out_error = "enum spec cannot use both member name and serial";
        return false;
      }
    }

    if (enum_name.empty()) {
      if (out_error)
        *out_error = "enum type name is empty";
      return false;
    }
    out.kind = OperandApplyKind::Enum;
    out.enum_name = enum_name;
    out.enum_member_name = member_name;
    out.enum_serial = serial;
    return true;
  }

  if (starts_with_ci(text, "stroff:")) {
    const std::string rest = trim_copy(text.substr(7));
    if (rest.empty()) {
      if (out_error)
        *out_error = "stroff spec requires a type path";
      return false;
    }

    std::string path_part = rest;
    adiff_t delta = 0;

    const size_t delta_pos = rest.find(",delta=");
    if (delta_pos != std::string::npos) {
      path_part = trim_copy(rest.substr(0, delta_pos));
      const std::string delta_text = trim_copy(rest.substr(delta_pos + 7));
      int64_t delta64 = 0;
      if (!parse_int64(delta_text, delta64)) {
        if (out_error)
          *out_error = "stroff delta must be an integer";
        return false;
      }
      delta = static_cast<adiff_t>(delta64);
    }

    std::vector<std::string> path_names;
    split_path_names(path_part, path_names);
    if (path_names.empty()) {
      if (out_error)
        *out_error = "stroff type path is empty";
      return false;
    }

    out.kind = OperandApplyKind::Stroff;
    out.stroff_path_names = std::move(path_names);
    out.stroff_delta = delta;
    return true;
  }

  if (out_error)
    *out_error = "unknown format spec mode";
  return false;
}

bool parse_operand_apply_spec(const char *spec, OperandApplyRequest &out) {
  return parse_operand_format_spec(spec, out, nullptr);
}

bool decode_operand(ea_t ea, int opnum, insn_t &out_insn, op_t &out_op,
                    std::string *out_error) {
  if (out_error)
    out_error->clear();
  if (ea == BADADDR || !is_code(get_flags(ea))) {
    if (out_error)
      *out_error = "address is not code";
    return false;
  }
  if (opnum < 0 || opnum >= UA_MAXOP) {
    if (out_error)
      *out_error = "operand index out of range";
    return false;
  }
  if (decode_insn(&out_insn, ea) <= 0) {
    if (out_error)
      *out_error = "failed to decode instruction";
    return false;
  }
  out_op = out_insn.ops[opnum];
  if (out_op.type == o_void) {
    if (out_error)
      *out_error = "operand slot is empty";
    return false;
  }
  return true;
}

bool operand_numeric_value(ea_t ea, int opnum, uint64 &out_value,
                           std::string *out_error) {
  if (out_error)
    out_error->clear();
  insn_t insn;
  op_t op;
  if (!decode_operand(ea, opnum, insn, op, out_error))
    return false;

  switch (op.type) {
  case o_imm:
    out_value = static_cast<uint64>(op.value);
    return true;
  case o_mem:
  case o_near:
  case o_far:
  case o_displ:
    out_value = static_cast<uint64>(op.addr);
    return true;
  default:
    if (out_error)
      *out_error = "operand is not numeric";
    return false;
  }
}

ssize_t find_enum_member_by_name(const tinfo_t &enum_tif, edm_t *out,
                                 const char *name) {
#if IDASQL_HAS_GET_EDM
  return enum_tif.get_edm(out, name);
#else
  return enum_tif.find_edm(out, name);
#endif
}

ssize_t find_enum_member_by_value(const tinfo_t &enum_tif, edm_t *out,
                                  uint64 value, bmask64_t bmask,
                                  uchar serial) {
#if IDASQL_HAS_GET_EDM
  return enum_tif.get_edm_by_value(out, value, bmask, serial);
#else
  return enum_tif.find_edm(out, value, bmask, serial);
#endif
}

bool resolve_enum_member_serial(const tinfo_t &enum_tif,
                                const std::string &member_name,
                                uchar &out_serial, std::string *out_error) {
  if (out_error)
    out_error->clear();
  edm_t target;
  const ssize_t idx =
      find_enum_member_by_name(enum_tif, &target, member_name.c_str());
  if (idx < 0) {
    if (out_error)
      *out_error = "enum member not found";
    return false;
  }

  for (int s = 0; s <= 255; ++s) {
    edm_t candidate;
    const ssize_t by_val = find_enum_member_by_value(
        enum_tif, &candidate, target.value, DEFMASK64, static_cast<uchar>(s));
    if (by_val < 0)
      break;
    if (candidate.name == target.name) {
      out_serial = static_cast<uchar>(s);
      return true;
    }
  }

  if (out_error)
    *out_error = "failed to resolve enum member serial";
  return false;
}

// Apply the ,signed/,bnot modifiers idempotently to the current operand
// representation. toggle_sign/toggle_bnot flip state, so only toggle when the
// current state differs from the requested one.
bool apply_operand_modifiers(ea_t ea, int opnum, const OperandApplyRequest &req,
                             std::string *out_error) {
  if (req.sign_mode != OperandModMode::Unchanged) {
    const bool want = (req.sign_mode == OperandModMode::On);
    if (is_invsign(ea, get_flags(ea), opnum) != want) {
      if (!toggle_sign(ea, opnum)) {
        if (out_error)
          *out_error = "toggle_sign failed";
        return false;
      }
    }
  }
  if (req.bnot_mode != OperandModMode::Unchanged) {
    const bool want = (req.bnot_mode == OperandModMode::On);
    if (is_bnot(ea, get_flags(ea), opnum) != want) {
      if (!toggle_bnot(ea, opnum)) {
        if (out_error)
          *out_error = "toggle_bnot failed";
        return false;
      }
    }
  }
  return true;
}

bool apply_operand_representation(ea_t ea, int opnum,
                                  const OperandApplyRequest &req,
                                  std::string *out_error) {
  if (out_error)
    out_error->clear();
  if (ea == BADADDR || !is_code(get_flags(ea))) {
    if (out_error)
      *out_error = "address is not code";
    return false;
  }
  if (opnum < 0 || opnum >= UA_MAXOP) {
    if (out_error)
      *out_error = "operand index out of range";
    return false;
  }
  if (req.kind == OperandApplyKind::None) {
    if (out_error)
      *out_error = "format spec mode is none";
    return false;
  }

  bool ok = false;
  idasql_auto_wait();

  switch (req.kind) {
  case OperandApplyKind::Clear:
    ok = clr_op_type(ea, opnum);
    if (!ok) {
      const flags64_t flags = get_flags(ea);
      ok = !is_enum(flags, opnum) && !is_stroff(flags, opnum);
    }
    if (!ok && out_error)
      *out_error = "failed to clear operand representation";
    break;

  case OperandApplyKind::Enum: {
    insn_t insn;
    op_t op;
    if (!decode_operand(ea, opnum, insn, op, out_error)) {
      idasql_auto_wait();
      return false;
    }

    tid_t enum_tid = BADNODE;
    tinfo_t enum_tif;
    if (!resolve_named_type_tid(req.enum_name, enum_tid, &enum_tif) ||
        !enum_tif.is_enum()) {
      if (out_error)
        *out_error = "enum type not found";
      idasql_auto_wait();
      return false;
    }

    uchar serial = req.enum_serial;
    if (!req.enum_member_name.empty()) {
      uint64 operand_value = 0;
      std::string value_err;
      if (!operand_numeric_value(ea, opnum, operand_value, &value_err)) {
        if (out_error)
          *out_error =
              "enum member apply requires numeric operand: " + value_err;
        idasql_auto_wait();
        return false;
      }

      edm_t member;
      if (find_enum_member_by_name(enum_tif, &member,
                                   req.enum_member_name.c_str()) < 0) {
        if (out_error)
          *out_error = "enum member not found";
        idasql_auto_wait();
        return false;
      }
      if (member.value != operand_value) {
        if (out_error)
          *out_error = "enum member value does not match operand value";
        idasql_auto_wait();
        return false;
      }

      std::string serial_err;
      if (!resolve_enum_member_serial(enum_tif, req.enum_member_name, serial,
                                      &serial_err)) {
        if (out_error)
          *out_error = serial_err;
        idasql_auto_wait();
        return false;
      }
    }

    ok = op_enum(ea, opnum, enum_tid, serial);
    if (!ok && out_error)
      *out_error = "op_enum failed";
    break;
  }

  case OperandApplyKind::Stroff: {
    insn_t insn;
    op_t op;
    if (!decode_operand(ea, opnum, insn, op, out_error)) {
      idasql_auto_wait();
      return false;
    }

    std::vector<tid_t> path;
    path.reserve(req.stroff_path_names.size());
    for (const std::string &name : req.stroff_path_names) {
      tid_t tid = BADNODE;
      tinfo_t tif;
      if (!resolve_named_type_tid(name, tid, &tif) || !tif.is_udt()) {
        if (out_error)
          *out_error = "stroff type path contains unknown or non-udt type";
        idasql_auto_wait();
        return false;
      }
      path.push_back(tid);
    }

    if (path.empty()) {
      if (out_error)
        *out_error = "stroff type path is empty";
      idasql_auto_wait();
      return false;
    }
    ok = op_stroff(insn, opnum, path.data(), static_cast<int>(path.size()),
                   req.stroff_delta);
    if (!ok && out_error)
      *out_error = "op_stroff failed";
    break;
  }

  case OperandApplyKind::NumBase:
    switch (req.num_radix) {
    case 16:
      ok = op_hex(ea, opnum);
      break;
    case 10:
      ok = op_dec(ea, opnum);
      break;
    case 8:
      ok = op_oct(ea, opnum);
      break;
    case 2:
      ok = op_bin(ea, opnum);
      break;
    default:
      ok = false;
      break;
    }
    if (!ok && out_error)
      *out_error = "failed to set number base representation";
    break;

  case OperandApplyKind::Char:
    ok = op_chr(ea, opnum);
    if (!ok && out_error)
      *out_error = "op_chr failed";
    break;

  case OperandApplyKind::Float:
    ok = op_flt(ea, opnum);
    if (!ok && out_error)
      *out_error = "op_flt failed";
    break;

  case OperandApplyKind::Segment:
    ok = op_seg(ea, opnum);
    if (!ok && out_error)
      *out_error = "op_seg failed";
    break;

  case OperandApplyKind::StackVar:
    ok = op_stkvar(ea, opnum);
    if (!ok && out_error)
      *out_error = "op_stkvar failed (operand is not a stack variable)";
    break;

  case OperandApplyKind::Offset: {
    ea_t base = 0;
    if (!req.offset_base.empty() && !resolve_ea_spec(req.offset_base, base)) {
      if (out_error)
        *out_error = "offset base symbol or address not found";
      idasql_auto_wait();
      return false;
    }
    ok = op_plain_offset(ea, opnum, base);
    if (!ok && out_error)
      *out_error = "op_offset failed";
    break;
  }

  case OperandApplyKind::Sizeof: {
    insn_t insn;
    op_t op;
    if (!decode_operand(ea, opnum, insn, op, out_error)) {
      idasql_auto_wait();
      return false;
    }
    tid_t tid = BADNODE;
    tinfo_t tif;
    if (!resolve_named_type_tid(req.sizeof_type, tid, &tif) || !tif.is_udt()) {
      if (out_error)
        *out_error = "sizeof type is unknown or not a struct/union";
      idasql_auto_wait();
      return false;
    }
    // "size STRUCT" is the struct-offset representation applied to an operand
    // whose value sits at the end of the structure (value == sizeof). op_stroff
    // renders this past-end offset as "size STRUCT".
    tid_t path[1] = {tid};
    ok = op_stroff(insn, opnum, path, 1, 0);
    if (!ok && out_error)
      *out_error = "op_stroff (sizeof) failed";
    break;
  }

  case OperandApplyKind::Forced:
    ok = set_forced_operand(ea, opnum, req.forced_text.c_str());
    if (!ok && out_error)
      *out_error = "set_forced_operand failed";
    break;

  case OperandApplyKind::Modifiers:
    // No base-representation change; sign/bnot applied below.
    ok = true;
    break;

  case OperandApplyKind::None:
    ok = false;
    break;
  }

  if (ok && req.kind != OperandApplyKind::Clear &&
      (req.sign_mode != OperandModMode::Unchanged ||
       req.bnot_mode != OperandModMode::Unchanged)) {
    if (!apply_operand_modifiers(ea, opnum, req, out_error))
      ok = false;
  }

  if (ok) {
    decompiler::invalidate_decompiler_cache(ea);
  }
  idasql_auto_wait();
  return ok;
}

const char *operand_type_name(optype_t type) {
  switch (type) {
  case o_void:
    return "void";
  case o_reg:
    return "reg";
  case o_mem:
    return "mem";
  case o_phrase:
    return "phrase";
  case o_displ:
    return "displ";
  case o_imm:
    return "imm";
  case o_far:
    return "far";
  case o_near:
    return "near";
  case o_idpspec0:
  case o_idpspec1:
  case o_idpspec2:
  case o_idpspec3:
  case o_idpspec4:
  case o_idpspec5:
    return "idpspec";
  default:
    return "idpspec";
  }
}

const char *operand_class_name(optype_t type) {
  switch (type) {
  case o_void:
    return "";
  case o_reg:
  case o_mem:
  case o_phrase:
  case o_displ:
  case o_imm:
  case o_far:
  case o_near:
  case o_idpspec0:
  case o_idpspec1:
  case o_idpspec2:
  case o_idpspec3:
  case o_idpspec4:
  case o_idpspec5:
    return operand_type_name(type);
  default:
    return "unknown";
  }
}

std::string operand_class_text(ea_t ea, int opnum) {
  insn_t insn;
  op_t op;
  if (!decode_operand(ea, opnum, insn, op, nullptr))
    return "";
  return operand_class_name(op.type);
}

// Dependency-free lowercase hex formatter for offset bases.
std::string to_hex_string(uint64_t value) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  do {
    out.insert(out.begin(), digits[value & 0xF]);
    value >>= 4;
  } while (value != 0);
  return "0x" + out;
}

// True when a struct-offset operand renders as "size STRUCT" (the operand value
// sits at the end of the structure). Distinguishes the sizeof representation
// from a regular member struct-offset on read-back.
bool operand_renders_as_sizeof(ea_t ea, int opnum) {
  qstring buf;
  print_operand(&buf, ea, opnum);
  tag_remove(&buf);
  return starts_with_ci(trim_copy(buf.c_str()), "size ");
}

std::string operand_repr_kind_text(ea_t ea, int opnum) {
  if (opnum >= 0 && opnum < UA_MAXOP && is_forced_operand(ea, opnum))
    return "forced";
  const flags64_t flags = get_flags(ea);
  if (is_enum(flags, opnum))
    return "enum";
  if (is_stroff(flags, opnum))
    return operand_renders_as_sizeof(ea, opnum) ? "sizeof" : "stroff";
  if (is_off(flags, opnum))
    return "offset";
  if (is_stkvar(flags, opnum))
    return "stkvar";
  if (is_seg(flags, opnum))
    return "segment";
  if (is_char(flags, opnum))
    return "char";
  if (is_fltnum(flags, opnum))
    return "float";
  if (is_numop(flags, opnum)) {
    switch (get_radix(flags, opnum)) {
    case 16:
      return "hex";
    case 8:
      return "oct";
    case 2:
      return "bin";
    case 10:
    default:
      return "dec";
    }
  }
  return "plain";
}

std::string operand_repr_type_name_text(ea_t ea, int opnum) {
  const flags64_t flags = get_flags(ea);
  if (opnum >= 0 && opnum < UA_MAXOP && is_forced_operand(ea, opnum)) {
    qstring buf;
    if (get_forced_operand(&buf, ea, opnum) > 0)
      return buf.c_str();
    return "";
  }
  if (is_enum(flags, opnum)) {
    uchar serial = 0;
    const tid_t enum_tid = get_enum_id(&serial, ea, opnum);
    if (enum_tid != BADNODE) {
      return tid_name_or_fallback(enum_tid);
    }
    return "";
  }

  if (is_off(flags, opnum)) {
    const ea_t base = get_offbase(ea, opnum);
    if (base != 0 && base != BADADDR)
      return to_hex_string(static_cast<uint64_t>(base));
    return "";
  }

  if (is_stroff(flags, opnum)) {
    std::array<tid_t, MAXSTRUCPATH> path{};
    adiff_t delta = 0;
    int path_len = get_stroff_path(path.data(), &delta, ea, opnum);
    if (path_len <= 0)
      return "";
    if (path_len > static_cast<int>(path.size())) {
      path_len = static_cast<int>(path.size());
    }

    std::string joined;
    for (int i = 0; i < path_len; ++i) {
      const std::string name =
          tid_name_or_fallback(path[static_cast<size_t>(i)]);
      if (name.empty())
        continue;
      if (!joined.empty())
        joined += "/";
      joined += name;
    }
    return joined;
  }

  return "";
}

std::string operand_repr_member_name_text(ea_t ea, int opnum) {
  if (!is_enum(get_flags(ea), opnum))
    return "";

  uchar serial = 0;
  const tid_t enum_tid = get_enum_id(&serial, ea, opnum);
  if (enum_tid == BADNODE)
    return "";

  uint64 value = 0;
  if (!operand_numeric_value(ea, opnum, value, nullptr))
    return "";

  tinfo_t enum_tif;
  if (!enum_tif.get_type_by_tid(enum_tid) || !enum_tif.is_enum())
    return "";

  qstring expr;
  if (!get_enum_member_expr(&expr, enum_tif, static_cast<int>(serial), value)) {
    return "";
  }
  return expr.c_str();
}

int operand_repr_serial(ea_t ea, int opnum) {
  if (!is_enum(get_flags(ea), opnum))
    return 0;
  uchar serial = 0;
  get_enum_id(&serial, ea, opnum);
  return static_cast<int>(serial);
}

int64_t operand_repr_delta(ea_t ea, int opnum) {
  if (!is_stroff(get_flags(ea), opnum))
    return 0;
  std::array<tid_t, MAXSTRUCPATH> path{};
  adiff_t delta = 0;
  get_stroff_path(path.data(), &delta, ea, opnum);
  return static_cast<int64_t>(delta);
}

std::string operand_format_spec_text(ea_t ea, int opnum) {
  const flags64_t flags = get_flags(ea);
  const std::string kind = operand_repr_kind_text(ea, opnum);
  const std::string type_name = operand_repr_type_name_text(ea, opnum);

  std::string base;
  if (kind == "enum") {
    const int serial = operand_repr_serial(ea, opnum);
    base = type_name.empty()
               ? "enum"
               : ("enum:" + type_name + ",serial=" + std::to_string(serial));
  } else if (kind == "stroff") {
    const int64_t delta = operand_repr_delta(ea, opnum);
    base = type_name.empty()
               ? "stroff"
               : ("stroff:" + type_name + ",delta=" + std::to_string(delta));
  } else if (kind == "sizeof") {
    base = type_name.empty() ? "sizeof" : ("sizeof:" + type_name);
  } else if (kind == "offset") {
    base = type_name.empty() ? "offset" : ("offset:" + type_name);
  } else if (kind == "forced") {
    return "forced:" + type_name; // forced text ignores sign/bnot display
  } else {
    base = kind; // hex/dec/oct/bin/char/float/segment/stkvar/plain
  }

  if (kind != "plain" && opnum >= 0 && opnum < UA_MAXOP) {
    if (is_invsign(ea, flags, opnum))
      base += ",signed";
    if (is_bnot(ea, flags, opnum))
      base += ",bnot";
  }
  return base;
}

// Legacy wrappers kept for compatibility with older call sites.
std::string operand_kind_text(ea_t ea, int opnum) {
  return operand_repr_kind_text(ea, opnum);
}
std::string operand_type_text(ea_t ea, int opnum) {
  return operand_repr_type_name_text(ea, opnum);
}
int operand_enum_serial(ea_t ea, int opnum) {
  return operand_repr_serial(ea, opnum);
}
int64_t operand_stroff_delta(ea_t ea, int opnum) {
  return operand_repr_delta(ea, opnum);
}

} // namespace code
} // namespace idasql
