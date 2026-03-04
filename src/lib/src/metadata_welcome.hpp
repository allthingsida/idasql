// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <string>

#include <idasql/vtable.hpp>

namespace idasql {
namespace metadata {

struct WelcomeRow {
    std::string summary;

    std::string processor;
    int is_64bit = 0;
    std::string min_ea;
    std::string max_ea;
    std::string start_ea;
    std::string entry_name;
    int funcs_count = 0;
    int segments_count = 0;
    int names_count = 0;
};

CachedTableDef<WelcomeRow> define_welcome();

} // namespace metadata
} // namespace idasql
