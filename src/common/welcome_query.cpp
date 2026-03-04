// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

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
