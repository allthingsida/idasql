// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <string>

namespace idasql {
namespace autostart {

enum class Service {
    Http,
    Mcp,
};

struct ServicePin {
    bool configured = false;
    bool enabled = false;
    int port = 0;
    std::string host = "127.0.0.1";
    std::string token;
};

struct PinConfig {
    ServicePin http;
    ServicePin mcp;
};

PinConfig load();

void set(Service service, const std::string &host, int port,
         const std::string &token = "");

void set_enabled(Service service, bool enabled);

void clear(Service service);

void clear_all();

inline void apply_pin_fallback(const ServicePin& pin, int& req_port,
                               std::string& addr, std::string* token = nullptr) {
    if (req_port != 0 || !pin.configured) {
        return;
    }
    req_port = pin.port;
    if (addr == "127.0.0.1") {
        addr = pin.host;
    }
    if (token != nullptr && token->empty()) {
        *token = pin.token;
    }
}

}
}
