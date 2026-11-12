// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <cstdint>

namespace idasql {
namespace config {

inline constexpr const char *NODE_NAME = "$ idasql config";

inline constexpr uint32_t SCHEMA_VERSION = 3;

namespace alt {
inline constexpr uint32_t SCHEMA_VERSION = 0x00;

inline constexpr uint32_t AUTOSTART_BASE = 0x10;
inline constexpr uint32_t AUTOSTART_HTTP_PORT = AUTOSTART_BASE + 0;
inline constexpr uint32_t AUTOSTART_MCP_PORT = AUTOSTART_BASE + 1;
inline constexpr uint32_t AUTOSTART_FLAGS = AUTOSTART_BASE + 2;

inline constexpr uint32_t REMOTE_BASE = 0x20;
inline constexpr uint32_t REMOTE_ENABLED = REMOTE_BASE + 0;
}

namespace sup {
inline constexpr uint32_t AUTOSTART_BASE = 0x10;
inline constexpr uint32_t AUTOSTART_HTTP_HOST = AUTOSTART_BASE + 0;
inline constexpr uint32_t AUTOSTART_MCP_HOST = AUTOSTART_BASE + 1;
inline constexpr uint32_t AUTOSTART_HTTP_TOKEN = AUTOSTART_BASE + 2;
inline constexpr uint32_t AUTOSTART_MCP_TOKEN = AUTOSTART_BASE + 3;
}

namespace autostart_flags {
inline constexpr uint64_t HTTP_ENABLED = 1ull << 0;
inline constexpr uint64_t MCP_ENABLED = 1ull << 1;
inline constexpr uint64_t HTTP_CONFIGURED = 1ull << 2;
inline constexpr uint64_t MCP_CONFIGURED = 1ull << 3;
}

}
}
