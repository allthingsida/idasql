// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace idasql {
namespace cli {

enum Exit : int {
    kOk = 0,
    kFailed = 1,
    kUsage = 2,
    kTimeout = 3,
    kFirstSpecific = 4,
};

struct ArgSpec {
    std::vector<std::string> flags;
    std::vector<std::string> options;
};

struct Args {
    std::set<std::string> flags;
    std::map<std::string, std::string> options;
    std::vector<std::string> positionals;
    std::string error;

    bool ok() const { return error.empty(); }
    bool has(const std::string& flag) const { return flags.count(flag) != 0; }
    std::string value(const std::string& option, const std::string& fallback = "") const {
        const auto it = options.find(option);
        return it == options.end() ? fallback : it->second;
    }
};

inline Args parse_args(const std::vector<std::string>& in, const ArgSpec& spec) {
    const auto listed = [](const std::vector<std::string>& names, const std::string& name) {
        return std::find(names.begin(), names.end(), name) != names.end();
    };
    Args a;
    bool rest = false;
    for (size_t i = 0; i < in.size(); ++i) {
        const std::string& s = in[i];
        if (rest || s.size() < 2 || s[0] != '-') {
            a.positionals.push_back(s);
            continue;
        }
        if (s == "--") {
            rest = true;
            continue;
        }
        std::string name = s;
        std::string val;
        bool inline_value = false;
        const size_t eq = s.find('=');
        if (s.rfind("--", 0) == 0 && eq != std::string::npos) {
            name = s.substr(0, eq);
            val = s.substr(eq + 1);
            inline_value = true;
        }
        if (listed(spec.flags, name)) {
            if (inline_value) {
                a.error = "option " + name + " takes no value";
                return a;
            }
            a.flags.insert(name);
        } else if (listed(spec.options, name)) {
            if (!inline_value) {
                if (i + 1 >= in.size()) {
                    a.error = "option " + name + " needs a value";
                    return a;
                }
                val = in[++i];
            }
            a.options[name] = val;
        } else {
            a.error = "unknown option " + s;
            return a;
        }
    }
    return a;
}

inline bool wants_help(const std::vector<std::string>& in) {
    for (const auto& s : in) {
        if (s == "--") return false;
        if (s == "-h" || s == "--help") return true;
    }
    return false;
}

}
}
