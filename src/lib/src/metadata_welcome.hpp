// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
