// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * json_utils.hpp - JSON escaping and query result serialization helpers
 */

#pragma once

#include <idasql/database.hpp>

#include <string>
#include <string_view>

namespace idasql {

inline void append_json_hex_escape(std::string& out, unsigned char byte) {
    static const char kHex[] = "0123456789ABCDEF";
    out += "\\u00";
    out.push_back(kHex[(byte >> 4) & 0x0F]);
    out.push_back(kHex[byte & 0x0F]);
}

inline bool is_utf8_continuation(unsigned char ch) {
    return (ch & 0xC0U) == 0x80U;
}

inline bool is_valid_utf8_sequence(std::string_view input, size_t pos, size_t& seq_len) {
    seq_len = 0;
    if (pos >= input.size()) {
        return false;
    }

    const unsigned char c0 = static_cast<unsigned char>(input[pos]);
    if (c0 < 0x80U) {
        seq_len = 1;
        return true;
    }

    if (c0 >= 0xC2U && c0 <= 0xDFU) {
        if (pos + 1 >= input.size()) return false;
        const unsigned char c1 = static_cast<unsigned char>(input[pos + 1]);
        if (!is_utf8_continuation(c1)) return false;
        seq_len = 2;
        return true;
    }

    if (c0 == 0xE0U) {
        if (pos + 2 >= input.size()) return false;
        const unsigned char c1 = static_cast<unsigned char>(input[pos + 1]);
        const unsigned char c2 = static_cast<unsigned char>(input[pos + 2]);
        if (c1 < 0xA0U || c1 > 0xBFU || !is_utf8_continuation(c2)) return false;
        seq_len = 3;
        return true;
    }
    if ((c0 >= 0xE1U && c0 <= 0xECU) || (c0 >= 0xEEU && c0 <= 0xEFU)) {
        if (pos + 2 >= input.size()) return false;
        const unsigned char c1 = static_cast<unsigned char>(input[pos + 1]);
        const unsigned char c2 = static_cast<unsigned char>(input[pos + 2]);
        if (!is_utf8_continuation(c1) || !is_utf8_continuation(c2)) return false;
        seq_len = 3;
        return true;
    }
    if (c0 == 0xEDU) {
        if (pos + 2 >= input.size()) return false;
        const unsigned char c1 = static_cast<unsigned char>(input[pos + 1]);
        const unsigned char c2 = static_cast<unsigned char>(input[pos + 2]);
        if (c1 < 0x80U || c1 > 0x9FU || !is_utf8_continuation(c2)) return false;
        seq_len = 3;
        return true;
    }

    if (c0 == 0xF0U) {
        if (pos + 3 >= input.size()) return false;
        const unsigned char c1 = static_cast<unsigned char>(input[pos + 1]);
        const unsigned char c2 = static_cast<unsigned char>(input[pos + 2]);
        const unsigned char c3 = static_cast<unsigned char>(input[pos + 3]);
        if (c1 < 0x90U || c1 > 0xBFU
                || !is_utf8_continuation(c2)
                || !is_utf8_continuation(c3)) {
            return false;
        }
        seq_len = 4;
        return true;
    }
    if (c0 >= 0xF1U && c0 <= 0xF3U) {
        if (pos + 3 >= input.size()) return false;
        const unsigned char c1 = static_cast<unsigned char>(input[pos + 1]);
        const unsigned char c2 = static_cast<unsigned char>(input[pos + 2]);
        const unsigned char c3 = static_cast<unsigned char>(input[pos + 3]);
        if (!is_utf8_continuation(c1)
                || !is_utf8_continuation(c2)
                || !is_utf8_continuation(c3)) {
            return false;
        }
        seq_len = 4;
        return true;
    }
    if (c0 == 0xF4U) {
        if (pos + 3 >= input.size()) return false;
        const unsigned char c1 = static_cast<unsigned char>(input[pos + 1]);
        const unsigned char c2 = static_cast<unsigned char>(input[pos + 2]);
        const unsigned char c3 = static_cast<unsigned char>(input[pos + 3]);
        if (c1 < 0x80U || c1 > 0x8FU
                || !is_utf8_continuation(c2)
                || !is_utf8_continuation(c3)) {
            return false;
        }
        seq_len = 4;
        return true;
    }

    return false;
}

inline void append_json_string(std::string& out, std::string_view input) {
    out.push_back('"');
    for (size_t i = 0; i < input.size();) {
        const unsigned char c = static_cast<unsigned char>(input[i]);
        switch (c) {
            case '"':
                out += "\\\"";
                ++i;
                break;
            case '\\':
                out += "\\\\";
                ++i;
                break;
            case '\b':
                out += "\\b";
                ++i;
                break;
            case '\f':
                out += "\\f";
                ++i;
                break;
            case '\n':
                out += "\\n";
                ++i;
                break;
            case '\r':
                out += "\\r";
                ++i;
                break;
            case '\t':
                out += "\\t";
                ++i;
                break;
            default:
                if (c < 0x20) {
                    append_json_hex_escape(out, c);
                    ++i;
                    break;
                }

                if (c < 0x80U) {
                    out.push_back(static_cast<char>(c));
                    ++i;
                } else {
                    size_t seq_len = 0;
                    if (is_valid_utf8_sequence(input, i, seq_len)) {
                        out.append(input.data() + i, seq_len);
                        i += seq_len;
                    } else {
                        // Preserve non-UTF8 byte values as JSON escapes.
                        append_json_hex_escape(out, c);
                        ++i;
                    }
                }
                break;
        }
    }
    out.push_back('"');
}

inline std::string escape_json(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 8);
    append_json_string(out, input);
    if (out.size() < 2) {
        return {};
    }
    return out.substr(1, out.size() - 2);
}

inline void append_json_string_array(std::string& out, const std::vector<std::string>& values) {
    out.push_back('[');
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0) out.push_back(',');
        append_json_string(out, values[i]);
    }
    out.push_back(']');
}

inline std::string query_result_to_json_safe(const QueryResult& result) {
    std::string out;
    out.reserve(256);
    out += "{\"success\":";
    out += result.success ? "true" : "false";

    if (result.success) {
        out += ",\"columns\":";
        append_json_string_array(out, result.columns);

        out += ",\"rows\":[";
        for (size_t i = 0; i < result.rows.size(); ++i) {
            if (i != 0) out.push_back(',');
            append_json_string_array(out, result.rows[i].values);
        }
        out.push_back(']');

        out += ",\"row_count\":";
        out += std::to_string(result.rows.size());

        if (!result.warnings.empty()) {
            out += ",\"warnings\":";
            append_json_string_array(out, result.warnings);
        }
        if (result.timed_out) {
            out += ",\"timed_out\":true";
        }
        if (result.partial) {
            out += ",\"partial\":true";
        }
        if (result.elapsed_ms > 0) {
            out += ",\"elapsed_ms\":";
            out += std::to_string(result.elapsed_ms);
        }
    } else {
        out += ",\"error\":";
        append_json_string(out, result.error);
    }

    out.push_back('}');
    return out;
}

} // namespace idasql
