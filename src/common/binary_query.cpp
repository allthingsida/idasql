// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "binary_query.hpp"

namespace idasql {

const char* default_binary_query() {
    return "SELECT * FROM binary";
}

std::string format_query_curl_example(const std::string& base_url) {
    return "curl -X POST " + base_url + "/query -d \"" + std::string(default_binary_query()) + "\"";
}

} // namespace idasql
