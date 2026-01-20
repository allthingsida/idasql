#pragma once

/**
 * SessionHandler - Core query processing logic for IDASQL
 *
 * This class handles:
 * - SQL query execution
 * - Meta commands (.tables, .schema, .help)
 * - Natural language queries via Claude (when enabled)
 * - Multi-turn conversation state
 *
 * NO IDA DEPENDENCIES - can be tested standalone.
 *
 * Used by:
 * - CLI main.cpp (directly)
 * - IdasqlCLI (wraps this for cli_t)
 */

#include <string>
#include <functional>
#include <memory>
#include <cctype>
#include <algorithm>

#include "idasql_commands.hpp"

#ifdef IDASQL_HAS_CLAUDE_AGENT
#include "claude_agent.hpp"
#endif

namespace idasql {

class SessionHandler
{
public:
    using SqlExecutor = std::function<std::string(const std::string&)>;

    // Simple allowlist for table identifiers (alnum + underscore)
    static bool is_safe_table_name(const std::string& name)
    {
        if (name.empty() || name.size() > 128) return false;
        return std::all_of(name.begin(), name.end(), [](unsigned char c) {
            return std::isalnum(c) || c == '_';
        });
    }

    /**
     * Create a session handler
     * @param executor Function to execute SQL and return formatted results
     * @param enable_claude Whether to enable Claude agent (if available)
     */
    explicit SessionHandler(SqlExecutor executor, bool enable_claude = false)
        : executor_(std::move(executor))
    {
        // Setup command callbacks
        callbacks_.get_tables = [this]() {
            return executor_("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
        };
        callbacks_.get_schema = [this](const std::string& table) {
            if (!is_safe_table_name(table)) {
                return std::string("Invalid table name");
            }
            std::string sql = "SELECT sql FROM sqlite_master WHERE name='" + table + "'";
            return executor_(sql);
        };
        callbacks_.get_info = [this]() {
            return executor_("PRAGMA database_list");
        };
        callbacks_.clear_session = [this]() {
            return clear_session();
        };

#ifdef IDASQL_HAS_CLAUDE_AGENT
        if (enable_claude && ClaudeAgent::is_available()) {
            agent_ = std::make_unique<ClaudeAgent>(executor_);
            agent_->start();
            claude_enabled_ = true;
        }
#else
        (void)enable_claude;  // Suppress unused warning
#endif
    }

    ~SessionHandler()
    {
        end_session();
    }

    // Non-copyable, movable
    SessionHandler(const SessionHandler&) = delete;
    SessionHandler& operator=(const SessionHandler&) = delete;
    SessionHandler(SessionHandler&&) = default;
    SessionHandler& operator=(SessionHandler&&) = default;

    /**
     * Process a line of input
     * @param line User input (SQL, meta command, or natural language)
     * @return Result string, or empty if no output
     */
    std::string process_line(const std::string& line)
    {
        if (line.empty()) {
            return "";
        }

        // Check for meta commands first
        std::string output;
        auto cmd_result = handle_command(line, callbacks_, output);

        switch (cmd_result) {
            case CommandResult::QUIT:
                quit_requested_ = true;
                return "";

            case CommandResult::HANDLED:
                return output;

            case CommandResult::NOT_HANDLED:
                // Continue to process as query
                break;
        }

#ifdef IDASQL_HAS_CLAUDE_AGENT
        // If Claude is enabled and input doesn't look like SQL, use agent
        if (claude_enabled_ && agent_ && !ClaudeAgent::looks_like_sql(line)) {
            agent_->send_query(line);
            return agent_->pump_until_result();
        }
#endif

        // Execute as raw SQL
        return executor_(line);
    }

    /**
     * One-shot query (no session, no conversation history)
     */
    std::string query(const std::string& prompt)
    {
#ifdef IDASQL_HAS_CLAUDE_AGENT
        if (claude_enabled_ && agent_) {
            agent_->send_query(prompt);
            return agent_->pump_until_result();
        }
#endif
        // Fallback: treat as SQL
        return executor_(prompt);
    }

    /**
     * End the session (cleanup agent)
     */
    void end_session()
    {
#ifdef IDASQL_HAS_CLAUDE_AGENT
        if (agent_) {
            agent_->stop();
            agent_.reset();
        }
#endif
        claude_enabled_ = false;
    }

    bool is_claude_enabled() const { return claude_enabled_; }
    bool is_quit_requested() const { return quit_requested_; }

    /**
     * Clear/reset the session
     * Resets Claude agent conversation history if enabled.
     * Override the callback to add UI-specific behavior (e.g., msg_clear).
     *
     * @return Status message
     */
    virtual std::string clear_session()
    {
#ifdef IDASQL_HAS_CLAUDE_AGENT
        if (agent_) {
            agent_->reset_session();
            return "Session cleared (conversation history reset)";
        }
#endif
        return "Session cleared";
    }

    /**
     * Get command callbacks (for overriding in derived classes)
     */
    CommandCallbacks& callbacks() { return callbacks_; }
    const CommandCallbacks& callbacks() const { return callbacks_; }

    /**
     * Check if Claude CLI is available on this system
     */
    static bool is_claude_available()
    {
#ifdef IDASQL_HAS_CLAUDE_AGENT
        return ClaudeAgent::is_available();
#else
        return false;
#endif
    }

private:
    SqlExecutor executor_;
    CommandCallbacks callbacks_;
    bool claude_enabled_ = false;
    bool quit_requested_ = false;

#ifdef IDASQL_HAS_CLAUDE_AGENT
    std::unique_ptr<ClaudeAgent> agent_;
#endif
};

} // namespace idasql
