// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "memory_strings.hpp"

using namespace idasql::core;

namespace idasql {
namespace memory {

int get_string_width(int strtype) {
  return strtype & 0x03;
}

const char *get_string_width_name(int strtype) {
  int width = get_string_width(strtype);
  switch (width) {
  case 0:
    return "1-byte";
  case 1:
    return "2-byte";
  case 2:
    return "4-byte";
  default:
    return "unknown";
  }
}

const char *get_string_type_name(int strtype) {
  int width = get_string_width(strtype);
  switch (width) {
  case 0:
    return "ascii";
  case 1:
    return "utf16";
  case 2:
    return "utf32";
  default:
    return "unknown";
  }
}

int get_string_layout(int strtype) {
  return (strtype >> 2) & 0x3F;
}

const char *get_string_layout_name(int strtype) {
  int layout = get_string_layout(strtype);
  switch (layout) {
  case 0:
    return "termchr";
  case 1:
    return "pascal1";
  case 2:
    return "pascal2";
  case 3:
    return "pascal4";
  default:
    return "unknown";
  }
}

int get_string_encoding(int strtype) {
  return (strtype >> 24) & 0xFF;
}

std::string get_string_content(const string_info_t &si) {
  qstring content;
  get_strlit_contents(&content, si.ea, si.length, si.type);
  return std::string(content.c_str());
}

CachedTableDef<string_info_t> define_strings() {
  return cached_table<string_info_t>("strings")
      .no_shared_cache()
      .estimate_rows([]() -> size_t { return get_strlist_qty(); })
      .row_count([]() -> size_t { return get_strlist_qty(); })
      .cache_builder([](std::vector<string_info_t> &cache) {
        size_t n = get_strlist_qty();
        for (size_t i = 0; i < n; i++) {
          string_info_t si;
          if (get_strlist_item(&si, i)) {
            cache.push_back(si);
          }
        }
      })
      .column_int64("addr",
                    [](const string_info_t &r) -> int64_t {
                      return static_cast<int64_t>(r.ea);
                    })
      .index_on("addr",
                [](const string_info_t &r) -> int64_t {
                  return static_cast<int64_t>(r.ea);
                })
      .column_int("length",
                  [](const string_info_t &r) -> int {
                    return static_cast<int>(r.length);
                  })
      .column_int("type",
                  [](const string_info_t &r) -> int {
                    return static_cast<int>(r.type);
                  })
      .column_text("type_name",
                   [](const string_info_t &r) -> std::string {
                     return get_string_type_name(r.type);
                   })
      .column_int("width",
                  [](const string_info_t &r) -> int {
                    return get_string_width(r.type);
                  })
      .column_text("width_name",
                   [](const string_info_t &r) -> std::string {
                     return get_string_width_name(r.type);
                   })
      .column_int("layout",
                  [](const string_info_t &r) -> int {
                    return get_string_layout(r.type);
                  })
      .column_text("layout_name",
                   [](const string_info_t &r) -> std::string {
                     return get_string_layout_name(r.type);
                   })
      .column_int("encoding",
                  [](const string_info_t &r) -> int {
                    return get_string_encoding(r.type);
                  })
      .column_text("content",
                   [](const string_info_t &r) -> std::string {
                     return get_string_content(r);
                   })
      .build();
}

}
}
