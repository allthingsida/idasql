#pragma once

/**
 * IDAMCPServer - MCP server for IDASQL
 *
 * Thread-safe MCP server using command queue pattern.
 * Tool handlers queue commands for execution on the main thread.
 *
 * Usage modes:
 * 1. CLI (idalib): Call wait() to process commands on main thread
 * 2. Plugin: Use execute_sync() wrapper in callbacks (no wait() needed)
 *
 * For CLI, start() returns immediately. Call wait() to block and process
 * commands. For plugin, the callback itself uses execute_sync() to marshal
 * to IDA's main thread, so no wait() is needed.
 */

#include <string>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <memory>

namespace idasql {

// Callbacks for handling requests
// QueryCallback: Direct SQL execution
// AskCallback: Natural language query (requires AI agent)
using QueryCallback = std::function<std::string(const std::string& sql)>;
using AskCallback = std::function<std::string(const std::string& question)>;

// Internal command structure for cross-thread execution
struct MCPPendingCommand {
    enum class Type { Query, Ask };
    Type type;
    std::string input;
    std::string result;
    bool completed = false;
    std::mutex* done_mutex = nullptr;
    std::condition_variable* done_cv = nullptr;
};

struct MCPQueueResult {
    bool success;
    std::string payload;
};

class IDAMCPServer {
public:
    IDAMCPServer();
    ~IDAMCPServer();

    // Non-copyable
    IDAMCPServer(const IDAMCPServer&) = delete;
    IDAMCPServer& operator=(const IDAMCPServer&) = delete;

    /**
     * Start MCP server on given port with callbacks
     *
     * @param port Port to listen on (0 = random port 9000-9999)
     * @param query_cb SQL query callback
     * @param ask_cb Natural language callback (optional)
     * @param bind_addr Address to bind to (default: localhost only)
     * @param use_queue If true, callbacks are queued for main thread (CLI mode)
     *                  If false, callbacks called directly (plugin mode with execute_sync)
     * @return Actual port used, or -1 on failure
     */
    int start(int port, QueryCallback query_cb, AskCallback ask_cb = nullptr,
              const std::string& bind_addr = "127.0.0.1", bool use_queue = false);

    /**
     * Block until server stops, processing commands on the calling thread
     * Only needed when use_queue=true (CLI mode)
     * This is where query_cb and ask_cb get called
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
     * Get the SSE endpoint URL
     */
    std::string url() const;

    /**
     * Set interrupt check function (called during wait loop)
     */
    void set_interrupt_check(std::function<bool()> check);

    /**
     * Queue a command for execution on the main thread
     * Called by MCP tool handlers when use_queue=true
     */
    MCPQueueResult queue_and_wait(MCPPendingCommand::Type type, const std::string& input);

private:
    std::function<bool()> interrupt_check_;
    std::atomic<bool> running_{false};
    std::atomic<bool> use_queue_{false};
    std::string bind_addr_{"127.0.0.1"};
    int port_{0};

    // Command queue for cross-thread execution (CLI mode)
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<MCPPendingCommand*> pending_commands_;

    // Callbacks stored for execution
    QueryCallback query_cb_;
    AskCallback ask_cb_;

    // Forward declaration - impl hides fastmcpp
    class Impl;
    std::unique_ptr<Impl> impl_;

    void complete_pending_commands(const std::string& result);
};

/**
 * Format MCP server info for display
 */
std::string format_mcp_info(int port, bool has_agent);

/**
 * Format MCP server status
 */
std::string format_mcp_status(int port, bool running);

} // namespace idasql
