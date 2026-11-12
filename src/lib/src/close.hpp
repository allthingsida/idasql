// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <string>
#include <vector>

namespace idasql {
namespace close_cmd {

constexpr int kDefaultTimeoutS = 60;

extern const char* const kUsage;

bool is_url(const std::string& target);

int run_cli(const std::vector<std::string>& args);

}
}
