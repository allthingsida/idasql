// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * autostart_pin.hpp - Persisted "pin" preferences for autostarting servers.
 *
 * First consumer of the "$ idasql config" netnode (see idasql_config.hpp). A
 * pin records, per server kind (HTTP / MCP), a bind host, a port, and whether
 * the server should auto-start when the IDB is opened in the IDA plugin.
 *
 * Storage semantics:
 *   - configured           -> a pin record exists for the service.
 *   - port == 0            -> autostart with a fresh random port each launch
 *                             (only meaningful when configured).
 *   - port  > 0            -> autostart on that fixed port.
 *   - enabled (flag bit)   -> autostart-on-load (plugin only).
 *   host/port act as the remembered defaults for ".http start" / ".mcp start"
 *   with no explicit port; the enabled bit only governs autostart-on-load.
 *
 * This header is intentionally free of any IDA SDK dependency; the netnode
 * implementation lives in autostart_pin.cpp.
 */

#pragma once

#include <string>

namespace idasql {
namespace autostart {

enum class Service {
    Http,
    Mcp,
};

struct ServicePin {
    bool configured = false;       // a pin record exists for this service
    bool enabled = false;          // autostart-on-load
    int port = 0;                  // 0 == random port each launch (if configured)
    std::string host = "127.0.0.1";
    std::string token;             // auth token (HTTP only); empty == no auth
};

struct PinConfig {
    ServicePin http;
    ServicePin mcp;
};

// Read the autostart block from "$ idasql config". Returns defaults (port 0,
// disabled, host 127.0.0.1) when the node or a slot is absent.
PinConfig load();

// Store host+port (+optional auth token) for a service, mark it configured, and
// enable its autostart bit. port 0 is valid and means "random port each launch".
// An empty token clears any previously stored token (no auth). Creates the config
// node if needed and stamps the schema version.
void set(Service service, const std::string &host, int port,
         const std::string &token = "");

// Toggle only the autostart-on-load bit (host/port preserved). Enabling
// requires the service to already be configured (via set()); otherwise no-op.
void set_enabled(Service service, bool enabled);

// Clear one service's port, host, and enabled bit (other config preserved).
void clear(Service service);

// Clear the entire autostart block (both services). The config node itself and
// any other (future) config blocks are preserved.
void clear_all();

// Apply a service pin as the fallback for a ".http/.mcp start" issued with no
// explicit port. Pure (no IDA/netnode dependency) so it can be
// shared by the CLI and plugin start paths. Rules:
//   - An explicit port (req_port != 0) is kept; the pin is NOT consulted.
//   - Otherwise, a CONFIGURED pin is honored even at port 0 (a random-port pin
//     still carries a host); the pinned port replaces the (zero) request port.
//   - The pinned host replaces `addr` ONLY when `addr` is the default loopback
//     "127.0.0.1", so an explicit `.http start 0.0.0.0` (or any other bind) is
//     preserved rather than overridden by the pin.
//   - When `token` is non-null and currently empty, it is filled from the pin.
inline void apply_pin_fallback(const ServicePin& pin, int& req_port,
                               std::string& addr, std::string* token = nullptr) {
    if (req_port != 0 || !pin.configured) {
        return;
    }
    req_port = pin.port;  // may be 0 -> random port each launch
    if (addr == "127.0.0.1") {
        addr = pin.host;
    }
    if (token != nullptr && token->empty()) {
        *token = pin.token;
    }
}

} // namespace autostart
} // namespace idasql
