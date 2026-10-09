// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

/**
 * http_server.hpp - HTTP REST server wrapper for IDASQL
 *
 * IDAHTTPServer - HTTP REST server for IDASQL REPL
 *
 * Thin wrapper over xsql::thinclient::http_query_server.
 * Keeps a stable API for CLI and plugin callers.
 *
 * Usage modes:
 * 1. CLI (idalib): Call run_until_stopped() to process commands on main thread
 * 2. Plugin: Use execute_sync() wrapper in callbacks (no run_until_stopped() needed)
 */

#include <xsql/thinclient/http_query_server.hpp>

#include <atomic>
#include <cstdint>
#include <string>
#include <functional>
#include <memory>
#include <utility>

namespace idasql {

// Callback for handling SQL scripts with the request's timeout/cancellation
// options intact.
using HTTPQueryCallback = std::function<xsql::ScriptResult(
    const std::string& sql, const xsql::ScriptOptions& options)>;

// Counts the POST /cancel requests a server has answered (see cancel_counter()).
using CancelCounter = std::shared_ptr<std::atomic<std::uint64_t>>;

// Arm a request's cancellation when it actually STARTS executing: it is cancelled
// only by a /cancel that arrives after this point. A request that waits for the
// main thread (execute_sync) is not running yet, so a /cancel aimed at the query
// ahead of it must not reach it -- libxsql's own queue re-arms the same way.
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

    // Non-copyable
    IDAHTTPServer(const IDAHTTPServer&) = delete;
    IDAHTTPServer& operator=(const IDAHTTPServer&) = delete;

    /**
     * Start HTTP server on given port with callbacks
     *
     * @param port Port to listen on (0 = random port 8100-8999)
     * @param query_cb SQL script callback (returns the canonical result envelope)
     * @param bind_addr Address to bind to (default: localhost only)
     * @param use_queue If true, callbacks are queued for main thread (CLI mode)
     *                  If false, callbacks called directly (plugin mode with execute_sync)
     * @param auth_token Optional bearer token. Empty == no authentication (the
     *                  loopback default); non-empty makes /query, /status,
     *                  /cancel, and /shutdown require `Authorization: Bearer <token>`.
     * @return Actual port used, or -1 on failure
     */
    int start(int port, HTTPQueryCallback query_cb,
              const std::string& bind_addr = "127.0.0.1",
              bool use_queue = false,
              const std::string& auth_token = "");

    /**
     * Block until server stops, processing commands on the calling thread.
     * Only needed when use_queue=true (CLI mode).
     */
    void run_until_stopped();

    /** Stop the server */
    void stop();

    /**
     * Close the listening socket without joining the server's threads, and leak
     * the server to process exit. New connections are refused and keep-alive
     * loops end; the request already running finishes on its own. Only for
     * teardown on the thread a request is waiting on, where stop() would join
     * that request's worker forever.
     */
    void abandon();

    /**
     * Bumped on every POST /cancel this server answers. Shared, so a counter
     * captured by a request outlives a restart or an abandoned server.
     */
    CancelCounter cancel_counter() const { return cancel_counter_; }

    /** Check if server is running */
    bool is_running() const;

    /** Get the port the server is listening on */
    int port() const;

    /** Get the server URL */
    std::string url() const;

    /** Get bind address configured at startup */
    const std::string& bind_addr() const { return bind_addr_; }

    /** Set interrupt check function (called during wait loop) */
    void set_interrupt_check(std::function<bool()> check);

private:
    std::unique_ptr<xsql::thinclient::http_query_server> impl_;
    std::string bind_addr_{"127.0.0.1"};
    CancelCounter cancel_counter_ = std::make_shared<std::atomic<std::uint64_t>>(0);
};

/**
 * Format HTTP server info for display
 */
std::string format_http_info(int port, const std::string& stop_hint = "Press Ctrl+C to stop and return to REPL.");
std::string format_http_info(int port, const std::string& bind_addr, const std::string& stop_hint);

/**
 * Format HTTP server status
 */
std::string format_http_status(int port, bool running);
std::string format_http_status(int port, bool running, const std::string& bind_addr);

} // namespace idasql
