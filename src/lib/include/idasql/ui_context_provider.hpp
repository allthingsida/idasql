// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <cstdint>
#include <string>

#include <xsql/json.hpp>

namespace idasql {
namespace ui_context {

bool initialize_capture_helper(std::string* error = nullptr);
void shutdown_capture_helper();

xsql::json get_ui_context_json();

} // namespace ui_context
} // namespace idasql
