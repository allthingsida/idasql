// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * cfg_parser.hpp - a reader for IDA's shipped option files (ida.cfg,
 * hexrays.cfg, idagui.cfg), standard library only.
 *
 * It lists the top-level `KEY = value` directives of a file, following the
 * preprocessor subset those files use: #ifdef / #ifndef / #if (the forms
 * `defined(X)`, `!defined(X)` and `__IDAVER__ <op> N`) / #else / #endif,
 * object-like #define (expanded in values), and #include / #softinclude
 * (searched in the given cfg directories). Comments (// and / * * /) are
 * stripped outside strings. A value runs to the end of its line, or until its
 * {..} / [..] / (..) brackets balance and a `;` ends it. Keys in an inactive
 * branch are still listed, with active = false, and so are `// KEY = value`
 * lines (commented = true): the files document defaults that way.
 */

#pragma once

#include <map>
#include <set>
#include <string>
#include <vector>

namespace idasql {
namespace cfgparse {

struct Entry {
    std::string key;
    std::string file;        // file name, no directory
    std::string value;       // value text, comments stripped, macros expanded
    bool active = false;     // every enclosing condition holds
    bool commented = false;  // a `// KEY = value` line
    bool terminated = false; // the statement ended with ';' (list-valued keys)
};

struct Context {
    std::set<std::string> defines;  // e.g. "__NT__", "____", "__PC__"
    int idaver = 0;                 // for #if __IDAVER__ >= N
    std::vector<std::string> dirs;  // cfg search dirs for #include / #softinclude
};

// Parse one file (path) and append its directives to out. `macros` carries
// #defines across includes and files.
bool parse_file(const std::string& path, const Context& ctx,
                std::vector<Entry>& out,
                std::map<std::string, std::string>& macros, int depth = 0);

}  // namespace cfgparse
}  // namespace idasql
