// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * pin_commands.hpp - Wire the ".pin" dot-command callbacks to the autostart
 * pin store. Shared by the CLI and the plugin so the command behaves
 * identically in both. IDA-free (the netnode work lives in autostart_pin.cpp).
 *
 * Note: the autostart *behavior* (auto-launching servers on database open)
 * lives only in the plugin; the CLI uses these callbacks purely to read/write
 * pins persisted in the IDB.
 */

#pragma once

#include <iomanip>
#include <sstream>
#include <string>

#include <idasql/autostart_pin.hpp>

#include "idasql_commands.hpp"

namespace idasql {

namespace pin_detail {

// Map a service token to the enum. Rejects "mcp" when MCP isn't compiled in.
inline bool resolve_service(const std::string& s,
                            autostart::Service& svc,
                            std::string& err) {
    if (s == "http") {
        svc = autostart::Service::Http;
        return true;
    }
    if (s == "mcp") {
#ifdef IDASQL_HAS_MCP
        svc = autostart::Service::Mcp;
        return true;
#else
        err = "MCP support is not compiled in (build with -DIDASQL_WITH_MCP=ON).";
        return false;
#endif
    }
    err = "Unknown service: " + s + " (expected 'http' or 'mcp').";
    return false;
}

inline std::string format_service_pin(const char* name,
                                      const autostart::ServicePin& p) {
    std::ostringstream os;
    os << "  " << std::left << std::setw(5) << name;
    if (!p.configured) {
        os << "(not set)";
    } else {
        os << p.host << ":";
        if (p.port == 0)
            os << "<random port each launch>";
        else
            os << p.port;
        os << "  (autostart: " << (p.enabled ? "on" : "off") << ")";
    }
    os << "\n";
    return os.str();
}

inline std::string format_pin_list() {
    autostart::PinConfig cfg = autostart::load();
    std::string out = "Autostart pins:\n";
    out += format_service_pin("http", cfg.http);
#ifdef IDASQL_HAS_MCP
    out += format_service_pin("mcp", cfg.mcp);
#endif
    return out;
}

} // namespace pin_detail

// Install the .pin command callbacks on a CommandCallbacks set.
inline void wire_pin_callbacks(CommandCallbacks& cb) {
    cb.pin_list = []() -> std::string { return pin_detail::format_pin_list(); };

    cb.pin_set = [](const std::string& service, const std::string& bind,
                    int port, const std::string& token) -> std::string {
        autostart::Service svc;
        std::string err;
        if (!pin_detail::resolve_service(service, svc, err))
            return err;

        const std::string host = bind.empty() ? "127.0.0.1" : bind;
        autostart::set(svc, host, port, token);

        std::ostringstream os;
        os << "Pinned " << service << " -> " << host << ":";
        if (port == 0)
            os << "<random port each launch>";
        else
            os << port;
        os << (token.empty() ? " (autostart on)." : " (autostart on, auth token set).") << "\n"
           << "The plugin auto-starts this when the database is opened; '."
           << service << " start' with no port reuses it.";
        return os.str();
    };

    cb.pin_enable = [](const std::string& service, bool enable) -> std::string {
        autostart::Service svc;
        std::string err;
        if (!pin_detail::resolve_service(service, svc, err))
            return err;

        if (enable) {
            autostart::PinConfig cfg = autostart::load();
            const autostart::ServicePin& p =
                (svc == autostart::Service::Http) ? cfg.http : cfg.mcp;
            if (!p.configured)
                return "No " + service + " pin set. Use '.pin set " + service
                       + " [bindinterface] [port]' first.";
        }
        autostart::set_enabled(svc, enable);
        return std::string("Autostart ") + (enable ? "enabled" : "disabled")
               + " for " + service + ".";
    };

    cb.pin_clear = [](const std::string& service) -> std::string {
        if (service == "all") {
            autostart::clear_all();
            return "Cleared all autostart pins.";
        }
        autostart::Service svc;
        std::string err;
        if (!pin_detail::resolve_service(service, svc, err))
            return err;
        autostart::clear(svc);
        return "Cleared " + service + " autostart pin.";
    };
}

} // namespace idasql
