// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <idasql/platform.hpp>

#include <idasql/string_utils.hpp>
#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "dirtree_utils.hpp"
#include "ida_headers.hpp"

namespace idasql {
namespace core {

std::string safe_func_name(ea_t ea);
std::string safe_func_prototype(ea_t ea);
std::string safe_func_comment(ea_t ea, bool repeatable);
std::string safe_segm_name(ea_t ea);
std::string safe_segm_class(ea_t ea);

size_t estimate_heads();
size_t estimate_code_heads();
std::string safe_name(ea_t ea);
std::string safe_entry_name(size_t idx);
std::string name_or_fallback(ea_t ea);

bool get_func_tinfo(ea_t ea, tinfo_t &tif);
bool get_func_type_details(ea_t ea, func_type_data_t &fi);
const char *get_cc_name(callcnv_t cc);

using idasql::trim_copy;

ea_t normalize_sql_ea(int64_t value);

class HeadSpanWalker {
public:
  HeadSpanWalker(const xsql::Int64KeyRange &range, bool descending);
  ea_t next();

private:
  ea_t first_in_span(const xsql::U64Span &span) const;
  ea_t next_in_span(const xsql::U64Span &span, ea_t from) const;

  std::vector<xsql::U64Span> spans_;
  size_t span_ = 0;
  bool descending_ = false;
  bool in_span_ = false;
  ea_t current_ = BADADDR;
};

bool starts_with_ci(const std::string &text, const char *prefix);
bool equals_ci(const std::string &text, const char *token);
bool parse_int64(const std::string &text, int64_t &out_value);
bool resolve_named_type_tid(const std::string &name, tid_t &out_tid,
                            tinfo_t *out_tif = nullptr);
std::string tid_name_or_fallback(tid_t tid);

}
}
