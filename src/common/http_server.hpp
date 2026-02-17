#pragma once

/**
 * IDAHTTPServer - HTTP REST server for IDASQL REPL
 *
 * Thin wrapper over xsql::thinclient::http_query_server.
 * Preserves the existing API for backward compatibility.
 *
 * Usage modes:
 * 1. CLI (idalib): Call run_until_stopped() to process commands on main thread
 * 2. Plugin: Use execute_sync() wrapper in callbacks (no run_until_stopped() needed)
 */

#include <xsql/thinclient/http_query_server.hpp>

#include <string>
#include <functional>
#include <memory>

namespace idasql {

// Callback for handling SQL queries
using HTTPQueryCallback = std::function<std::string(const std::string& sql)>;

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
     * @param port Port to listen on (0 = random port 8100-8199)
     * @param query_cb SQL query callback (returns JSON string)
     * @param bind_addr Address to bind to (default: localhost only)
     * @param use_queue If true, callbacks are queued for main thread (CLI mode)
     *                  If false, callbacks called directly (plugin mode with execute_sync)
     * @return Actual port used, or -1 on failure
     */
    int start(int port, HTTPQueryCallback query_cb,
              const std::string& bind_addr = "127.0.0.1",
              bool use_queue = false);

    /**
     * Block until server stops, processing commands on the calling thread.
     * Only needed when use_queue=true (CLI mode).
     */
    void run_until_stopped();

    /** Stop the server */
    void stop();

    /** Check if server is running */
    bool is_running() const;

    /** Get the port the server is listening on */
    int port() const;

    /** Get the server URL */
    std::string url() const;

    /** Set interrupt check function (called during wait loop) */
    void set_interrupt_check(std::function<bool()> check);

private:
    std::unique_ptr<xsql::thinclient::http_query_server> impl_;
};

/**
 * Format HTTP server info for display
 */
std::string format_http_info(int port, const std::string& stop_hint = "Press Ctrl+C to stop and return to REPL.");

/**
 * Format HTTP server status
 */
std::string format_http_status(int port, bool running);

} // namespace idasql
