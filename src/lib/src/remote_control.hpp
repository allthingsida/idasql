// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "instances.hpp"

namespace idasql {
namespace remote {

constexpr int kRemoteOff = 4;
constexpr int kDefaultTimeoutS = 10;

struct Result {
    int exit = 1;
    std::string message;
    uint64_t pid = 0;
    std::string idb_path;
    std::string url;
    bool already = false;
    bool auth = false;
    bool ok() const { return exit == 0; }
};

bool find_target(const std::string& target, instances::Record& out, std::string& error);

Result server(const instances::Record& target, const std::string& service, bool start,
              int timeout_s = kDefaultTimeoutS);
Result set_remote(const instances::Record& target, bool on, int timeout_s = kDefaultTimeoutS);

int run_server_cli(const std::string& service, const std::vector<std::string>& args);
int run_remote_cli(const std::vector<std::string>& args);

extern const char* const kHttpUsage;
extern const char* const kMcpUsage;
extern const char* const kRemoteUsage;

}
}
