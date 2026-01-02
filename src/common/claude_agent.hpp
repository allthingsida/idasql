#pragma once

#ifdef IDASQL_HAS_CLAUDE_AGENT

#include <claude/claude.hpp>
#include <claude/mcp.hpp>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <variant>

namespace idasql {

// ============================================================================
// Thread-Safe Queue
// ============================================================================

template<typename T>
class ThreadSafeQueue {
public:
    void push(T item) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(std::move(item));
        }
        cv_.notify_one();
    }

    // Blocking pop - waits until item available or stopped
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !queue_.empty() || stopped_; });
        if (stopped_ && queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        return item;
    }

    // Non-blocking try_pop
    std::optional<T> try_pop() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        return item;
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopped_ = true;
        }
        cv_.notify_all();
    }

    /// Reset to initial state (clears queue, resets stopped flag)
    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::queue<T> empty;
        std::swap(queue_, empty);
        stopped_ = false;
    }

    bool is_stopped() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return stopped_;
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<T> queue_;
    bool stopped_ = false;
};

// ============================================================================
// Message Types for Main Thread Queue
// ============================================================================

/// Request to send a query to Claude
struct QueryRequest {
    std::string prompt;
    bool primed;  // True if first message (needs docs prepended)
};

/// Claude message received (assistant response, result, etc.)
struct ClaudeMessage {
    claude::Message msg;
};

/// MCP dispatch - request from reader thread, needs main thread execution
struct McpDispatch {
    claude::json request;
    std::promise<claude::json> promise;
};

/// Variant for main thread queue
using MainQueueItem = std::variant<ClaudeMessage, McpDispatch>;

// ============================================================================
// ClaudeAgent - Thread-Safe Architecture
// ============================================================================

/**
 * ClaudeAgent - Natural language interface for IDASQL
 *
 * Architecture:
 *   - Client Thread: Owns ClaudeClient, sends queries, receives messages
 *   - Reader Thread (SDK internal): Handles MCP requests, blocks on futures
 *   - Main Thread: Pumps queue, executes SQL safely, fulfills MCP promises
 *
 * This design ensures all SQL execution happens on the main thread,
 * which is required for IDA API thread safety.
 */
class ClaudeAgent {
public:
    /// Callback to execute SQL and return formatted results
    using SqlExecutor = std::function<std::string(const std::string& sql)>;

    /// Callback to display Claude messages (for streaming output)
    using MessageCallback = std::function<void(const claude::Message&)>;

    /**
     * Construct agent with SQL executor
     * @param executor Function that executes SQL and returns formatted results
     * @param verbose If true, show Claude CLI stderr output
     */
    explicit ClaudeAgent(SqlExecutor executor, bool verbose = false);

    ~ClaudeAgent();

    // Non-copyable, non-movable (owns thread)
    ClaudeAgent(const ClaudeAgent&) = delete;
    ClaudeAgent& operator=(const ClaudeAgent&) = delete;
    ClaudeAgent(ClaudeAgent&&) = delete;
    ClaudeAgent& operator=(ClaudeAgent&&) = delete;

    /**
     * Start the client thread and connect to Claude
     * Call this before send_query()
     */
    void start();

    /**
     * Stop the agent and disconnect
     * Signals shutdown and waits for client thread to finish
     */
    void stop();

    /**
     * Reset the session - clears conversation history
     * Stops the current agent and starts fresh.
     * Call this for .clear command.
     */
    void reset_session();

    /**
     * Request to quit (e.g., from Ctrl-C handler)
     * Thread-safe, can be called from signal handler
     */
    void request_quit();

    /**
     * Check if quit was requested
     */
    bool quit_requested() const { return quit_requested_.load(); }

    /**
     * Send a query to Claude (non-blocking)
     * The query will be processed by the client thread.
     * Poll main_queue() to get results.
     *
     * @param prompt User input (natural language or SQL)
     */
    void send_query(const std::string& prompt);

    /**
     * Pump the main queue once (non-blocking)
     * Processes one item from the queue:
     *   - ClaudeMessage: Returns it for display
     *   - McpDispatch: Executes SQL, fulfills promise
     *
     * @return The message if it was a ClaudeMessage, nullopt otherwise
     */
    std::optional<claude::Message> pump_once();

    /**
     * Pump the main queue until a result message or quit
     * Blocking call that processes all messages until done.
     *
     * @param on_message Callback for each assistant message
     * @return Final response text, or empty if quit
     */
    std::string pump_until_result(MessageCallback on_message = nullptr);

    /**
     * Check if input looks like SQL (for passthrough)
     * @param input User input string
     * @return true if input appears to be SQL
     */
    static bool looks_like_sql(const std::string& input);

    /**
     * Check if Claude CLI is available
     * @return true if claude CLI is found in PATH
     */
    static bool is_available();

private:
    SqlExecutor executor_;
    bool verbose_ = false;
    bool docs_primed_ = false;

    // Thread-safe queues
    ThreadSafeQueue<QueryRequest> query_queue_;
    ThreadSafeQueue<MainQueueItem> main_queue_;

    // Client thread
    std::thread client_thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> quit_requested_{false};

    /// Client thread main loop
    void client_thread_loop();

    /// Create ClaudeOptions with MCP tool that dispatches to main thread
    claude::ClaudeOptions create_options();

    /// Build primed message with documentation prepended
    std::string build_primed_message(const std::string& user_message);

    /// Process a single MCP dispatch (called on main thread)
    void handle_mcp_dispatch(McpDispatch& dispatch);

    /// Extract text from Claude messages
    std::string extract_response_text(const std::vector<claude::Message>& messages);
};

} // namespace idasql

#endif // IDASQL_HAS_CLAUDE_AGENT
