// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

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
