#pragma once

/**
 * IDAHTTPServer - HTTP REST server for IDASQL REPL
 *
 * Thread-safe HTTP server using command queue pattern (same as IDAMCPServer).
 * Provides REST endpoints for SQL queries.
 *
 * Usage modes:
 * 1. CLI (idalib): Call run_until_stopped() to process commands on main thread
 * 2. Plugin: Use execute_sync() wrapper in callbacks (no run_until_stopped() needed)
 */

#ifdef IDASQL_HAS_HTTP

#include <string>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <memory>

namespace idasql {

// Callback for handling SQL queries
using HTTPQueryCallback = std::function<std::string(const std::string& sql)>;

// Internal command structure for cross-thread execution
struct HTTPPendingCommand {
    std::string sql;
    std::string result;
    bool completed = false;
    std::mutex done_mutex;
    std::condition_variable done_cv;
};

class IDAHTTPServer {
public:
    IDAHTTPServer();
    ~IDAHTTPServer();

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
     * This is where query_cb gets called on the main thread.
     */
    void run_until_stopped();

    /**
     * Stop the server
     */
    void stop();

    /**
     * Check if server is running
     */
    bool is_running() const { return running_.load(); }

    /**
     * Get the port the server is listening on
     */
    int port() const { return port_; }

    /**
     * Get the server URL
     */
    std::string url() const;

    /**
     * Set interrupt check function (called during wait loop)
     */
    void set_interrupt_check(std::function<bool()> check);

private:
    std::function<bool()> interrupt_check_;
    std::atomic<bool> running_{false};
    std::atomic<bool> use_queue_{false};
    std::string bind_addr_{"127.0.0.1"};
    int port_{0};

    // Command queue for cross-thread execution (CLI mode)
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<std::shared_ptr<HTTPPendingCommand>> pending_commands_;

    // Callback stored for execution
    HTTPQueryCallback query_cb_;

    // Forward declaration - impl hides httplib
    class Impl;
    std::unique_ptr<Impl> impl_;

    // Queue a command and wait for main thread to execute it
    std::string queue_and_wait(const std::string& sql);

    // Complete all pending commands with an error message
    void complete_pending_commands(const std::string& result);
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

#endif // IDASQL_HAS_HTTP
