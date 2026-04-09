// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "welcome_query.hpp"

namespace idasql {

const char* default_welcome_query() {
    return "SELECT * FROM welcome";
}

std::string format_query_curl_example(const std::string& base_url) {
    return "curl -X POST " + base_url + "/query -d \"" + std::string(default_welcome_query()) + "\"";
}

std::string format_http_clipboard_payload(const std::string& base_url) {
    return "IDASQL HTTP server: " + base_url;
}

} // namespace idasql
