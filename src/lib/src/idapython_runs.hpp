// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace idasql {
namespace idapython_runs {

struct RunRow {
    int64_t id = 0;
    std::optional<std::string> code;
    std::optional<std::string> path;
    std::optional<std::string> sandbox;
    int show_output = 0;
    std::string output;
    int success = 0;
    std::optional<std::string> error;
    std::string started;
    int64_t duration_ms = 0;
};

constexpr size_t kKeptRuns = 100;

struct Registry {
    CachedTableDef<RunRow> runs;

    Registry();
    void register_all(xsql::Database& db);
};

}
}
