// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * string_utils.hpp - Shared string utility functions
 */

#pragma once

#include <cctype>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <string>

namespace idasql {

inline std::string format_ea_hex(uint64_t ea) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%" PRIX64, ea);
    return std::string(buf);
}

// Lowercase hex-encode a byte buffer (e.g. MD5/SHA-256 digests). Reads exactly
// `len` bytes and builds the result via std::string, so it cannot overflow.
inline std::string to_hex(const uint8_t* data, size_t len) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

inline std::string trim_copy(const std::string& s) {
    size_t begin = 0;
    size_t end = s.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(s[begin])) != 0) {
        ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(s[end - 1])) != 0) {
        --end;
    }
    return s.substr(begin, end - begin);
}

} // namespace idasql
