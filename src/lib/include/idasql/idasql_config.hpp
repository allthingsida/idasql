// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * idasql_config.hpp - Layout of the generic idasql per-database config netnode.
 *
 * idasql stores its own persistent, per-IDB configuration in a single reserved
 * netnode named "$ idasql config" (distinct from "$ idasql netnode_kv", which
 * is the user-facing key-value surface and must NOT be reused for tool config).
 *
 * This header defines ONLY the on-disk layout: the node name, a schema version,
 * and the reserved altval (integer) / supval (string) index constants. It is
 * intentionally free of any IDA SDK dependency so it can be included anywhere;
 * all netnode access lives in autostart_pin.cpp.
 *
 * Index allocation convention
 * ---------------------------
 *   altval and supval are independent index spaces. Indices 0x00..0x0F are
 *   reserved for node-global metadata; each feature gets its own 16-slot block
 *   starting at 0x10, 0x20, ... Add new features in a fresh block so older
 *   IDBs keep working and blocks never collide.
 */

#pragma once

#include <cstdint>

namespace idasql {
namespace config {

// Reserved netnode name for idasql's own per-IDB configuration.
inline constexpr const char *NODE_NAME = "$ idasql config";

// Bumped when the on-disk layout below changes in an incompatible way.
inline constexpr uint32_t SCHEMA_VERSION = 3;

// altval (integer) index map.
namespace alt {
// 0x00..0x0F: node-global metadata.
inline constexpr uint32_t SCHEMA_VERSION = 0x00;

// 0x10..0x1F: autostart feature block.
inline constexpr uint32_t AUTOSTART_BASE = 0x10;
inline constexpr uint32_t AUTOSTART_HTTP_PORT = AUTOSTART_BASE + 0; // 0x10
inline constexpr uint32_t AUTOSTART_MCP_PORT = AUTOSTART_BASE + 1;  // 0x11
inline constexpr uint32_t AUTOSTART_FLAGS = AUTOSTART_BASE + 2;     // 0x12
// 0x20.. reserved for the next feature.
} // namespace alt

// supval (string) index map (independent from altval).
namespace sup {
// 0x10..0x1F: autostart feature block.
inline constexpr uint32_t AUTOSTART_BASE = 0x10;
inline constexpr uint32_t AUTOSTART_HTTP_HOST = AUTOSTART_BASE + 0; // 0x10
inline constexpr uint32_t AUTOSTART_MCP_HOST = AUTOSTART_BASE + 1;  // 0x11
// Per-service auth token (v3+). Empty/absent == no authentication required.
// Only the HTTP server enforces a token; MCP has no auth path.
inline constexpr uint32_t AUTOSTART_HTTP_TOKEN = AUTOSTART_BASE + 2; // 0x12
inline constexpr uint32_t AUTOSTART_MCP_TOKEN = AUTOSTART_BASE + 3;  // 0x13
// 0x20.. reserved for the next feature.
} // namespace sup

// Bit positions stored in alt::AUTOSTART_FLAGS.
namespace autostart_flags {
inline constexpr uint64_t HTTP_ENABLED = 1ull << 0;
inline constexpr uint64_t MCP_ENABLED = 1ull << 1;
// CONFIGURED marks that a pin record exists for the service. It is independent
// of the stored port value, so port 0 ("autostart with a fresh random port")
// is a real pin rather than "unset". (Pre-v2 IDBs lack these bits; load() treats
// a nonzero stored port as configured for back-compat.)
inline constexpr uint64_t HTTP_CONFIGURED = 1ull << 2;
inline constexpr uint64_t MCP_CONFIGURED = 1ull << 3;
} // namespace autostart_flags

} // namespace config
} // namespace idasql
