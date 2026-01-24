#pragma once

/**
 * IdasqlCLI - IDA plugin command line interface
 *
 * Wraps SessionHandler and provides cli_t integration for IDA.
 * The actual query processing logic is in SessionHandler (testable without IDA).
 *
 * Usage:
 *   IdasqlCLI cli(executor);
 *   cli.install();  // Register with IDA
 *   // ... plugin lifetime ...
 *   cli.uninstall();  // Unregister on shutdown
 */

#include <string>
#include <functional>
#include <memory>
#include <kernwin.hpp>

#include "session_handler.hpp"

namespace idasql {

class IdasqlCLI
{
public:
    using SqlExecutor = std::function<std::string(const std::string&)>;

    explicit IdasqlCLI(SqlExecutor executor, bool enable_agent = true)
        : session_(std::move(executor), enable_agent)
    {
        // Override clear_session callback to add IDA-specific behavior
        session_.callbacks().clear_session = [this]() {
            return clear_session();
        };
    }

    ~IdasqlCLI()
    {
        uninstall();
    }

    // Non-copyable
    IdasqlCLI(const IdasqlCLI&) = delete;
    IdasqlCLI& operator=(const IdasqlCLI&) = delete;

    /**
     * Install the CLI with IDA
     */
    bool install()
    {
        if (installed_) return true;

        // Store pointer for static callback
        s_instance_ = this;

        // Setup cli_t structure
        cli_.size = sizeof(cli_t);
        cli_.flags = 0;
        cli_.sname = "idasql";
        cli_.lname = session_.is_agent_enabled()
            ? "idasql - SQL queries with AI agent support"
            : "idasql - SQL interface to IDA database";
        cli_.hint = "Enter SQL query, .command, or natural language";
        cli_.execute_line = &IdasqlCLI::execute_line_cb;
        cli_.keydown = nullptr;
        cli_.find_completions = nullptr;

        install_command_interpreter(&cli_);
        installed_ = true;
        msg("IDASQL CLI: Installed (AI agent: %s)\n",
            session_.is_agent_enabled() ? "enabled" : "disabled");
        return true;
    }

    /**
     * Uninstall the CLI from IDA
     */
    void uninstall()
    {
        if (!installed_) return;

        session_.end_session();
        remove_command_interpreter(&cli_);
        installed_ = false;
        s_instance_ = nullptr;

        msg("IDASQL CLI: Uninstalled\n");
    }

    bool is_installed() const { return installed_; }
    bool is_agent_enabled() const { return session_.is_agent_enabled(); }

    /**
     * Clear session - clears IDA message window and resets AI agent
     */
    std::string clear_session()
    {
        // Clear IDA's message window
        msg_clear();

        // Clear the AI agent session
        std::string result = session_.clear_session();

        // Print status to fresh message window
        msg("IDASQL: %s\n", result.c_str());

        return result;
    }

    /**
     * Process a line of input (delegates to SessionHandler)
     */
    std::string process_line(const std::string& line)
    {
        return session_.process_line(line);
    }

    /**
     * Get the underlying session handler (for testing)
     */
    SessionHandler& session() { return session_; }
    const SessionHandler& session() const { return session_; }

private:
    SessionHandler session_;
    cli_t cli_{};
    bool installed_ = false;

    // Static instance for callback
    static IdasqlCLI* s_instance_;

    // Static callback for cli_t
    static bool idaapi execute_line_cb(const char* line)
    {
        if (!s_instance_ || !line) return true;

        std::string result = s_instance_->process_line(line);
        if (!result.empty()) {
            msg("%s\n", result.c_str());
        }

        return true;  // Line was executed
    }
};

// Static member definition
inline IdasqlCLI* IdasqlCLI::s_instance_ = nullptr;

} // namespace idasql
