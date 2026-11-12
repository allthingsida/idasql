// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <xsql/thinclient/http_query_server.hpp>

#include <atomic>
#include <cstdint>
#include <string>
#include <functional>
#include <memory>
#include <utility>

namespace idasql {

using HTTPQueryCallback = std::function<xsql::ScriptResult(
    const std::string& sql, const xsql::ScriptOptions& options)>;

using CancelCounter = std::shared_ptr<std::atomic<std::uint64_t>>;

inline void arm_cancel_at_start(xsql::ScriptOptions& options, CancelCounter counter) {
    if (!counter) return;
    const std::uint64_t armed = counter->load();
    options.should_cancel = [counter = std::move(counter), armed]() {
        return counter->load() != armed;
    };
}

class IDAHTTPServer {
public:
    IDAHTTPServer() = default;
    ~IDAHTTPServer() { stop(); }

    IDAHTTPServer(const IDAHTTPServer&) = delete;
    IDAHTTPServer& operator=(const IDAHTTPServer&) = delete;

    int start(int port, HTTPQueryCallback query_cb,
              const std::string& bind_addr = "127.0.0.1",
              bool use_queue = false,
              const std::string& auth_token = "");

    void run_until_stopped();

    void stop();

    void abandon();

    CancelCounter cancel_counter() const { return cancel_counter_; }

    bool is_running() const;

    int port() const;

    std::string url() const;

    const std::string& bind_addr() const { return bind_addr_; }

    void set_interrupt_check(std::function<bool()> check);

private:
    std::unique_ptr<xsql::thinclient::http_query_server> impl_;
    std::string bind_addr_{"127.0.0.1"};
    CancelCounter cancel_counter_ = std::make_shared<std::atomic<std::uint64_t>>(0);
};

std::string format_http_info(int port, const std::string& stop_hint = "Press Ctrl+C to stop and return to REPL.");
std::string format_http_info(int port, const std::string& bind_addr, const std::string& stop_hint);

std::string format_http_status(int port, bool running);
std::string format_http_status(int port, bool running, const std::string& bind_addr);

}
