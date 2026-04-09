// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * idasql_plugin - IDA plugin providing SQL interface to IDA databases
 *
 * The plugin auto-installs a CLI (command line interface) on load.
 * Use dot commands: .http, .mcp, .help
 *
 * The plugin is hidden from the Edit > Plugins menu (PLUGIN_HIDE).
 * See plugin_control.hpp for run() arg codes.
 */

// =============================================================================
// CRITICAL: Include order matters on Windows!
// 1. nlohmann/json before IDA headers (IDA macros can interfere)
// 2. Standard library headers
// 3. IDA headers
//
// Note: USE_DANGEROUS_FUNCTIONS and USE_STANDARD_FILE_FUNCTIONS are defined
// via CMakeLists.txt to disable IDA's safe function macros that conflict
// with MSVC standard library (__msvc_filebuf.hpp uses fgetc/fputc).
// =============================================================================

#include <idasql/platform.hpp>

// Standard library includes
#include <memory>
#include <string>
#include <functional>
#include <chrono>
#include <mutex>

// Platform-specific include order:
// - Windows: json before IDA (IDA poisons stdlib functions)
// - macOS/Linux: IDA before json
#include <idasql/platform_undef.hpp>

#ifdef _WIN32
#include <xsql/json.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <idasql/database.hpp>
#include <idasql/idapython.hpp>
#include <idasql/ui_context_provider.hpp>
#else
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <idasql/database.hpp>
#include <idasql/idapython.hpp>
#include <idasql/ui_context_provider.hpp>
#include <xsql/json.hpp>
#endif

// IDASQL CLI (command line interface)
#include "../common/idasql_cli.hpp"

// Plugin control codes
#include "../common/plugin_control.hpp"
#include "ui_context_function.hpp"

// Version info
#include "../common/idasql_version.hpp"

// MCP server (optional)
#ifdef IDASQL_HAS_MCP
#include "../common/mcp_server.hpp"
#endif

// HTTP server for .http REPL command
#include "../common/http_server.hpp"
#include "../common/json_utils.hpp"

//=============================================================================
// IDA execute_sync wrapper
//=============================================================================

namespace {

// RAII guard: enables IDA batch mode, restores previous state on scope exit.
// Suppresses dialogs/message boxes during HTTP query execution so external
// clients (curl, scripts) don't hang waiting for user interaction.
struct batch_guard_t {
    bool prev;
    batch_guard_t() : prev(batch) { batch = true; }
    ~batch_guard_t() { batch = prev; }
};

struct query_request_t : public exec_request_t
{
    idasql::QueryEngine* engine;
    std::string sql;
    idasql::QueryResult result;

    query_request_t(idasql::QueryEngine* e, const std::string& s)
        : engine(e), sql(s) {}

    virtual ssize_t idaapi execute() override
    {
        batch_guard_t bg;
        result = engine->query(sql);
        return result.success ? 0 : -1;
    }
};

} // anonymous namespace

//=============================================================================
// IDA Plugin
//=============================================================================

struct idasql_plugmod_t : public plugmod_t
{
    std::unique_ptr<idasql::QueryEngine> engine_;
    std::unique_ptr<idasql::IdasqlCLI> cli_;
    std::mutex query_exec_mutex_;
    std::mutex query_meta_mutex_;
    std::string active_query_;
    std::chrono::steady_clock::time_point active_query_started_{};
    bool idapython_runtime_acquired_ = false;

#ifdef IDASQL_HAS_MCP
    idasql::IDAMCPServer mcp_server_;
#endif

    idasql::IDAHTTPServer http_server_;

    idasql::QueryResult run_query_sync(const std::string& sql)
    {
        std::lock_guard<std::mutex> exec_lock(query_exec_mutex_);

        {
            std::lock_guard<std::mutex> lock(query_meta_mutex_);
            active_query_ = sql;
            active_query_started_ = std::chrono::steady_clock::now();
        }

        query_request_t req(engine_.get(), sql);
        execute_sync(req, MFF_WRITE);

        {
            std::lock_guard<std::mutex> lock(query_meta_mutex_);
            active_query_.clear();
            active_query_started_ = std::chrono::steady_clock::time_point{};
        }

        return req.result;
    }

    idasql_plugmod_t()
    {
        engine_ = std::make_unique<idasql::QueryEngine>();
        if (engine_->is_valid()) {
            if (!idasql::plugin_functions::register_ui_context_sql_functions(engine_->database())) {
                msg("IDASQL: Failed to register get_ui_context_json()\n");
            }
            msg("IDASQL v" IDASQL_VERSION_STRING ": Query engine initialized\n");

            std::string py_capture_error;
            idapython_runtime_acquired_ = idasql::idapython::runtime_acquire(&py_capture_error);
            if (!idapython_runtime_acquired_) {
                msg("IDASQL: IDAPython capture runtime init failed: %s\n", py_capture_error.c_str());
            }

            std::string ui_context_capture_error;
            if (!idasql::ui_context::initialize_capture_helper(&ui_context_capture_error)) {
                msg("IDASQL: UI context capture helper init failed: %s\n", ui_context_capture_error.c_str());
            }

            // SQL executor that uses execute_sync for thread safety
            auto sql_executor = [this](const std::string& sql) -> std::string {
                idasql::QueryResult result = run_query_sync(sql);
                if (result.success) {
                    return result.to_string();
                } else {
                    return "Error: " + result.error;
                }
            };

            // Create CLI with execute_sync wrapper for thread safety
            cli_ = std::make_unique<idasql::IdasqlCLI>(sql_executor);

#ifdef IDASQL_HAS_MCP
            // Setup MCP callbacks
            cli_->session().callbacks().mcp_status = [this]() -> std::string {
                if (mcp_server_.is_running()) {
                    return idasql::format_mcp_status(mcp_server_.port(), true, mcp_server_.bind_addr());
                } else {
                    // Auto-start if not running
                    return start_mcp_server();
                }
            };

            cli_->session().callbacks().mcp_start = [this](int port, const std::string& bind_addr) -> std::string {
                return start_mcp_server(port, bind_addr);
            };

            cli_->session().callbacks().mcp_stop = [this]() -> std::string {
                if (mcp_server_.is_running()) {
                    mcp_server_.stop();
                    return "MCP server stopped";
                } else {
                    return "MCP server not running";
                }
            };
#endif

            // Setup HTTP server callbacks
            cli_->session().callbacks().http_status = [this]() -> std::string {
                if (http_server_.is_running()) {
                    return idasql::format_http_status(http_server_.port(), true, http_server_.bind_addr());
                } else {
                    return "HTTP server not running\nUse '.http start' to start\n";
                }
            };

            cli_->session().callbacks().http_start = [this](int port, const std::string& bind_addr) -> std::string {
                return start_http_server(port, bind_addr);
            };

            cli_->session().callbacks().http_stop = [this]() -> std::string {
                if (http_server_.is_running()) {
                    http_server_.stop();
                    return "HTTP server stopped";
                } else {
                    return "HTTP server not running";
                }
            };

            // Auto-install CLI so it's available immediately
            // User can still toggle it off with run(23) if desired
            cli_->install();
        } else {
            msg("IDASQL: Failed to init engine: %s\n", engine_->error().c_str());
        }
    }

#ifdef IDASQL_HAS_MCP
    std::string start_mcp_server(int req_port = 0, const std::string& bind_addr = "127.0.0.1")
    {
        if (mcp_server_.is_running()) {
            return idasql::format_mcp_status(mcp_server_.port(), true, mcp_server_.bind_addr());
        }

        // SQL executor that uses execute_sync for thread safety
        auto sql_executor = [this](const std::string& sql) -> std::string {
            idasql::QueryResult result = run_query_sync(sql);
            if (result.success) {
                return result.to_string();
            } else {
                return "Error: " + result.error;
            }
        };

        // Start MCP server
        int port = mcp_server_.start(req_port, sql_executor, bind_addr);
        if (port <= 0) {
            return "Error: Failed to start MCP server";
        }

        return idasql::format_mcp_info(port, mcp_server_.bind_addr());
    }
#endif

    std::string start_http_server(int req_port = 0, const std::string& bind_addr = "127.0.0.1")
    {
        if (http_server_.is_running()) {
            return idasql::format_http_status(http_server_.port(), true, http_server_.bind_addr());
        }

        // SQL executor that uses execute_sync for thread safety and returns JSON
        idasql::HTTPQueryCallback sql_cb = [this](const std::string& sql) -> std::string {
            idasql::QueryResult result = run_query_sync(sql);
            return idasql::query_result_to_json_safe(result);
        };

        // Start HTTP server, no queue (plugin mode)
        int port = http_server_.start(req_port, sql_cb, bind_addr);
        if (port <= 0) {
            return "Error: Failed to start HTTP server";
        }

        return idasql::format_http_info(
            port, http_server_.bind_addr(), "Type '.http stop' to stop the server.");
    }

    ~idasql_plugmod_t()
    {
#ifdef IDASQL_HAS_MCP
        // Stop MCP server before destroying engine
        if (mcp_server_.is_running()) {
            mcp_server_.stop();
        }
#endif
        // Stop HTTP server before destroying engine
        if (http_server_.is_running()) {
            http_server_.stop();
        }
        if (cli_) cli_->uninstall();
        idasql::ui_context::shutdown_capture_helper();
        if (idapython_runtime_acquired_) {
            idasql::idapython::runtime_release();
            idapython_runtime_acquired_ = false;
        }
        engine_.reset();
        msg("IDASQL: Plugin terminated\n");
    }

    virtual bool idaapi run(size_t arg) override
    {
        using namespace idasql;

        switch (arg) {
            case 0:
                msg("IDASQL v" IDASQL_VERSION_STRING " - SQL interface for IDA database\n");
                msg("Use dot commands: .http");
#ifdef IDASQL_HAS_MCP
                msg(", .mcp");
#endif
                msg(", .help\n");
                return true;

            case PLUGIN_ARG_TOGGLE_CLI:
                if (cli_) {
                    if (cli_->is_installed()) {
                        cli_->uninstall();
                    } else {
                        cli_->install();
                    }
                }
                return true;

            default:
                return false;
        }
    }
};

//=============================================================================
// Plugin Entry Points
//=============================================================================

static plugmod_t* idaapi init()
{
    // Skip loading when running under idalib (e.g., idasql CLI)
    if (is_ida_library()) {
        msg("IDASQL: Running under idalib, plugin skipped\n");
        return nullptr;
    }

    return new idasql_plugmod_t();
}

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI | PLUGIN_HIDE,
    init,
    nullptr,
    nullptr,
    "IDASQL - SQL interface for IDA database",
    "IDASQL Plugin\n"
    "\n"
    "Auto-installs CLI on load. Use dot commands:\n"
    "  .http start/stop  - HTTP REST server\n"
#ifdef IDASQL_HAS_MCP
    "  .mcp start/stop   - MCP server\n"
#endif
    "  .help             - Show all commands\n"
    "\n"
    "run(23): Toggle CLI (command line interface)",
    "IDASQL",
    ""
};
