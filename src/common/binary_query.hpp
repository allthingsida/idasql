// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <string>

namespace idasql {

const char* default_binary_query();
std::string format_query_curl_example(const std::string& base_url);

} // namespace idasql
