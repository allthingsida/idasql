// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <functional>
#include <ostream>
#include <string>
#include <vector>

namespace idasql {
namespace cli {

struct Command {
    std::string name;
    std::string synopsis;
    std::string summary;
    std::string usage;
    std::function<int(const std::vector<std::string>&)> run;
    std::string unavailable;
};

struct BuildInfo {
    int ida_sdk_version = 0;
    bool deep_links = false;
};

std::vector<Command> build_command_table(const BuildInfo& build);

bool dispatch(const std::vector<Command>& table, const std::vector<std::string>& args, int& rc,
              std::ostream& out, std::ostream& err);

void print_command_list(const std::vector<Command>& table, std::ostream& out);

}
}
