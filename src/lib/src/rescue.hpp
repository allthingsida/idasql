// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <ctime>
#include <optional>
#include <string>
#include <vector>

namespace idasql {
namespace rescue {

constexpr int kDefaultTimeoutS = 120;

std::optional<std::string> derive_rescued_path(const std::string& db_path, const std::tm& when);
std::optional<std::string> derive_rescued_path(const std::string& db_path);

std::optional<std::string> unique_rescued_path(const std::string& db_path, const std::tm& when);
std::optional<std::string> unique_rescued_path(const std::string& db_path);

int run_cli(const std::vector<std::string>& args);

extern const char* const kUsage;

}
}
