// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * autostart_pin.cpp - netnode-backed implementation of the autostart pins.
 *
 * All access to the "$ idasql config" netnode is confined to this TU so the
 * public headers stay free of the IDA SDK. Layout constants come from
 * idasql_config.hpp.
 */

#include "ida_headers.hpp"

#include <idasql/autostart_pin.hpp>
#include <idasql/idasql_config.hpp>

namespace idasql {
namespace autostart {

namespace {

// Open the shared config node. When create is false and the node does not yet
// exist, the returned netnode compares equal to BADNODE.
netnode open_config_node(bool create) {
    return netnode(config::NODE_NAME, 0, create);
}

// Read a string supval, falling back to def when the slot is absent/empty.
std::string read_host(netnode &node, uint32_t idx, const char *def) {
    qstring buf;
    if (node.supstr(&buf, idx) > 0 && !buf.empty())
        return buf.c_str();
    return def;
}

uint64_t flag_for(Service service) {
    return service == Service::Http ? config::autostart_flags::HTTP_ENABLED
                                     : config::autostart_flags::MCP_ENABLED;
}

uint64_t configured_flag_for(Service service) {
    return service == Service::Http ? config::autostart_flags::HTTP_CONFIGURED
                                     : config::autostart_flags::MCP_CONFIGURED;
}

uint32_t port_alt_for(Service service) {
    return service == Service::Http ? config::alt::AUTOSTART_HTTP_PORT
                                    : config::alt::AUTOSTART_MCP_PORT;
}

uint32_t host_sup_for(Service service) {
    return service == Service::Http ? config::sup::AUTOSTART_HTTP_HOST
                                    : config::sup::AUTOSTART_MCP_HOST;
}

uint32_t token_sup_for(Service service) {
    return service == Service::Http ? config::sup::AUTOSTART_HTTP_TOKEN
                                    : config::sup::AUTOSTART_MCP_TOKEN;
}

// Read a string supval; empty string when the slot is absent/empty.
std::string read_str(netnode &node, uint32_t idx) {
    qstring buf;
    if (node.supstr(&buf, idx) > 0 && !buf.empty())
        return buf.c_str();
    return {};
}

void stamp_version(netnode &node) {
    node.altset(config::alt::SCHEMA_VERSION, config::SCHEMA_VERSION);
}

} // namespace

PinConfig load() {
    PinConfig cfg;

    netnode node = open_config_node(/*create=*/false);
    if (node == BADNODE)
        return cfg;

    const uint64_t flags = node.altval(config::alt::AUTOSTART_FLAGS);

    cfg.http.port = static_cast<int>(node.altval(config::alt::AUTOSTART_HTTP_PORT));
    cfg.http.enabled = (flags & config::autostart_flags::HTTP_ENABLED) != 0;
    // configured: explicit bit (v2+), or a nonzero stored port (pre-v2 IDBs).
    cfg.http.configured = (flags & config::autostart_flags::HTTP_CONFIGURED) != 0
                          || cfg.http.port != 0;
    cfg.http.host = read_host(node, config::sup::AUTOSTART_HTTP_HOST, "127.0.0.1");
    cfg.http.token = read_str(node, config::sup::AUTOSTART_HTTP_TOKEN);

    cfg.mcp.port = static_cast<int>(node.altval(config::alt::AUTOSTART_MCP_PORT));
    cfg.mcp.enabled = (flags & config::autostart_flags::MCP_ENABLED) != 0;
    cfg.mcp.configured = (flags & config::autostart_flags::MCP_CONFIGURED) != 0
                         || cfg.mcp.port != 0;
    cfg.mcp.host = read_host(node, config::sup::AUTOSTART_MCP_HOST, "127.0.0.1");
    cfg.mcp.token = read_str(node, config::sup::AUTOSTART_MCP_TOKEN);

    return cfg;
}

void set(Service service, const std::string &host, int port,
         const std::string &token) {
    netnode node = open_config_node(/*create=*/true);
    stamp_version(node);

    node.altset(port_alt_for(service), static_cast<nodeidx_t>(port));

    const std::string h = host.empty() ? "127.0.0.1" : host;
    node.supset(host_sup_for(service), h.c_str());

    // Store or clear the auth token (empty == no auth). Kept in the config node,
    // never the user-facing netnode_kv surface.
    if (token.empty())
        node.supdel(token_sup_for(service));
    else
        node.supset(token_sup_for(service), token.c_str());

    uint64_t flags = node.altval(config::alt::AUTOSTART_FLAGS);
    flags |= flag_for(service);             // enabled
    flags |= configured_flag_for(service);  // configured (port may be 0 == random)
    node.altset(config::alt::AUTOSTART_FLAGS, static_cast<nodeidx_t>(flags));
}

void set_enabled(Service service, bool enabled) {
    // Disabling a service whose node doesn't exist is a no-op.
    netnode node = open_config_node(/*create=*/enabled);
    if (node == BADNODE)
        return;

    const uint64_t cur_flags = node.altval(config::alt::AUTOSTART_FLAGS);
    const bool configured = (cur_flags & configured_flag_for(service)) != 0
                            || node.altval(port_alt_for(service)) != 0;
    if (enabled && !configured)
        return; // nothing configured to enable

    stamp_version(node);
    uint64_t flags = node.altval(config::alt::AUTOSTART_FLAGS);
    if (enabled)
        flags |= flag_for(service);
    else
        flags &= ~static_cast<uint64_t>(flag_for(service));
    node.altset(config::alt::AUTOSTART_FLAGS, static_cast<nodeidx_t>(flags));
}

void clear(Service service) {
    netnode node = open_config_node(/*create=*/false);
    if (node == BADNODE)
        return;

    node.altdel(port_alt_for(service));
    node.supdel(host_sup_for(service));
    node.supdel(token_sup_for(service));

    uint64_t flags = node.altval(config::alt::AUTOSTART_FLAGS);
    flags &= ~static_cast<uint64_t>(flag_for(service));
    flags &= ~static_cast<uint64_t>(configured_flag_for(service));
    node.altset(config::alt::AUTOSTART_FLAGS, static_cast<nodeidx_t>(flags));
}

void clear_all() {
    netnode node = open_config_node(/*create=*/false);
    if (node == BADNODE)
        return;

    node.altdel(config::alt::AUTOSTART_HTTP_PORT);
    node.altdel(config::alt::AUTOSTART_MCP_PORT);
    node.altdel(config::alt::AUTOSTART_FLAGS);
    node.supdel(config::sup::AUTOSTART_HTTP_HOST);
    node.supdel(config::sup::AUTOSTART_MCP_HOST);
    node.supdel(config::sup::AUTOSTART_HTTP_TOKEN);
    node.supdel(config::sup::AUTOSTART_MCP_TOKEN);
}

} // namespace autostart
} // namespace idasql
