// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <map>
#include <set>
#include <string>
#include <vector>

namespace idasql {
namespace cfgparse {

struct Entry {
    std::string key;
    std::string file;
    std::string value;
    bool active = false;
    bool commented = false;
    bool terminated = false;
};

struct Context {
    std::set<std::string> defines;
    int idaver = 0;
    std::vector<std::string> dirs;
};

bool parse_file(const std::string& path, const Context& ctx,
                std::vector<Entry>& out,
                std::map<std::string, std::string>& macros, int depth = 0);

}
}
