// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

#pragma once

#include <string>

namespace idasql {

const char* default_welcome_query();
std::string format_query_curl_example(const std::string& base_url);
std::string format_http_clipboard_payload(const std::string& base_url);

} // namespace idasql
