// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "core_common.hpp"

namespace idasql {
namespace core {

// Convert a SQL int64 address value to ea_t (wrap-around cast). Shared by the
// heads/bytes generator tables.
ea_t normalize_sql_ea(int64_t value) {
  return static_cast<ea_t>(static_cast<uint64_t>(value));
}

// ============================================================================
// Helper: Safe string extraction from IDA
// ============================================================================

std::string safe_func_name(ea_t ea) {
  qstring name;
  get_func_name(&name, ea);
  return std::string(name.c_str());
}

std::string safe_func_prototype(ea_t ea) {
  qstring out;
  if (print_type(&out, ea, PRTYPE_1LINE | PRTYPE_SEMI)) {
    return std::string(out.c_str());
  }
  return "";
}

std::string safe_func_comment(ea_t ea, bool repeatable) {
  func_t *f = get_func(ea);
  if (!f)
    return "";

  qstring out;
  const ssize_t len = get_func_cmt(&out, f, repeatable);
  if (len <= 0)
    return "";
  return std::string(out.c_str());
}

std::string safe_segm_name(segment_t *seg) {
  if (!seg)
    return "";
  qstring name;
  get_segm_name(&name, seg);
  return std::string(name.c_str());
}

std::string safe_segm_class(segment_t *seg) {
  if (!seg)
    return "";
  qstring cls;
  get_segm_class(&cls, seg);
  return std::string(cls.c_str());
}

std::string safe_name(ea_t ea) {
  qstring name;
  get_name(&name, ea);
  return std::string(name.c_str());
}

std::string safe_entry_name(size_t idx) {
  uval_t ord = get_entry_ordinal(idx);
  qstring name;
  get_entry_name(&name, ord);
  return std::string(name.c_str());
}

std::string name_or_fallback(ea_t ea) {
  std::string name = safe_name(ea);
  if (!name.empty()) {
    return name;
  }

  qstring fallback;
  fallback.sprnt("sub_%llX", static_cast<unsigned long long>(ea));
  return std::string(fallback.c_str());
}

// ============================================================================
// Function type helpers
// ============================================================================

bool get_func_tinfo(ea_t ea, tinfo_t &tif) { return get_tinfo(&tif, ea); }

const char *get_cc_name(callcnv_t cc) {
  switch (cc) {
  case CM_CC_CDECL:
    return "cdecl";
  case CM_CC_STDCALL:
    return "stdcall";
  case CM_CC_FASTCALL:
    return "fastcall";
  case CM_CC_THISCALL:
    return "thiscall";
  case CM_CC_PASCAL:
    return "pascal";
  case CM_CC_SPECIAL:
    return "special";
  case CM_CC_SPECIALE:
    return "speciale";
  case CM_CC_SPECIALP:
    return "specialp";
  case CM_CC_ELLIPSIS:
    return "ellipsis";
  default:
    return "unknown";
  }
}

// ============================================================================
// Helper: get function type details (rettype, calling conv, etc.)
// ============================================================================

bool get_func_type_details(ea_t ea, func_type_data_t &fi) {
  tinfo_t tif;
  if (!get_func_tinfo(ea, tif) || !tif.is_func())
    return false;
  return tif.get_func_details(&fi);
}

bool starts_with_ci(const std::string &text, const char *prefix) {
  if (!prefix)
    return false;
  const size_t prefix_len = std::strlen(prefix);
  if (text.size() < prefix_len)
    return false;
  for (size_t i = 0; i < prefix_len; ++i) {
    const unsigned char a = static_cast<unsigned char>(text[i]);
    const unsigned char b = static_cast<unsigned char>(prefix[i]);
    if (std::tolower(a) != std::tolower(b))
      return false;
  }
  return true;
}

bool equals_ci(const std::string &text, const char *token) {
  if (!token)
    return false;
  const size_t token_len = std::strlen(token);
  if (text.size() != token_len)
    return false;
  return starts_with_ci(text, token);
}

bool parse_int64(const std::string &text, int64_t &out_value) {
  const std::string trimmed = trim_copy(text);
  if (trimmed.empty())
    return false;
  char *end_ptr = nullptr;
  const long long value = std::strtoll(trimmed.c_str(), &end_ptr, 0);
  if (end_ptr == nullptr || *end_ptr != '\0')
    return false;
  out_value = static_cast<int64_t>(value);
  return true;
}

bool resolve_named_type_tid(const std::string &name, tid_t &out_tid,
                            tinfo_t *out_tif) {
  if (name.empty())
    return false;
  tinfo_t tif;
  if (!tif.get_named_type(nullptr, name.c_str())) {
    return false;
  }
  const tid_t tid = tif.get_tid();
  if (tid == BADNODE) {
    return false;
  }
  if (out_tif) {
    *out_tif = tif;
  }
  out_tid = tid;
  return true;
}

std::string tid_name_or_fallback(tid_t tid) {
  qstring out;
  if (get_tid_name(&out, tid)) {
    return std::string(out.c_str());
  }
  return "";
}

} // namespace core
} // namespace idasql
