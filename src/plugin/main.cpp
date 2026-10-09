// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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
#include <atomic>
#include <memory>
#include <string>
#include <functional>
#include <mutex>

// Pinning the module on an abandoned teardown (GetModuleHandleExW / dlopen).
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

// Platform-specific include order:
// - Windows: json before IDA (IDA poisons stdlib functions)
// - macOS/Linux: IDA before json
#include <idasql/platform_undef.hpp>

// clang-format off
#ifdef _WIN32
#include <xsql/json.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <auto.hpp>
#include <idasql/database.hpp>
#include <idasql/idapython.hpp>
#include <idasql/ui_context_provider.hpp>
#else
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <auto.hpp>
#include <idasql/database.hpp>
#include <idasql/idapython.hpp>
#include <idasql/ui_context_provider.hpp>
#include <xsql/json.hpp>
#endif
// clang-format on

// IDASQL CLI (command line interface)
#include "../common/idasql_cli.hpp"

// Autostart pins (.pin command + auto-launch on database open)
#include "../common/pin_commands.hpp"
#include <idasql/autostart_pin.hpp>

// Plugin control codes
#include "../common/plugin_control.hpp"

// Cross-SDK shims (idasql_is_ida_library). Lib-internal header; included here
// after the IDA SDK headers above so its inline wrappers resolve.
#include "../lib/src/ida_compat.hpp"

// Version info
#include "../common/idasql_version.hpp"

// MCP server (optional)
#ifdef IDASQL_HAS_MCP
#include "../common/mcp_server.hpp"
#endif

// HTTP server for .http REPL command
#include "../common/binary_query.hpp"
#include "../common/http_server.hpp"
#include "../common/json_utils.hpp"
#include "../common/sql_script.hpp"
#include <xsql/query_script.hpp>

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

// What a request needs from the plugin once it has been handed to the main
// thread. Each request holds its own reference, so this outlives the plugin when
// term has to abandon a server with a request still in flight (see the dtor).
struct request_gate_t
{
    // Serializes engine access. Acquired INSIDE execute() (which always runs on
    // the main thread via execute_sync), never around the execute_sync round-trip.
    // Holding it across execute_sync would deadlock: an HTTP worker would keep the
    // lock while blocked waiting for the main thread, and if the main thread (CLI
    // Enter -> process_line) then tries the same path it blocks on the lock and
    // never pumps the worker's queued request -> permanent IDA freeze. Taking it
    // there keeps the HTTP/MCP workers serialized (all funnel through the main
    // thread) without ever holding it off the main thread.
    std::mutex exec_mutex;
    idasql::QueryEngine* engine = nullptr;
    std::atomic<int> in_flight{0};
    std::atomic<bool> closing{false};
};

xsql::ScriptResult closing_result()
{
    xsql::ScriptStatementResult stmt;
    stmt.error = "IDA is closing";
    xsql::ScriptResult result;
    result.statement_count = 1;
    result.first_error_index = 0;
    result.results.push_back(std::move(stmt));
    return result;
}

struct query_script_request_t : public exec_request_t
{
    std::shared_ptr<request_gate_t> gate;
    std::string sql;
    xsql::ScriptOptions options;
    // HTTP only: its server's /cancel counter. The request is armed against it
    // when it starts, not when it was queued behind the main thread.
    idasql::CancelCounter cancel_counter;
    xsql::ScriptResult result;

    query_script_request_t(std::shared_ptr<request_gate_t> g, const std::string& s,
                           const xsql::ScriptOptions& opts, idasql::CancelCounter counter)
        : gate(std::move(g)), sql(s), options(opts), cancel_counter(std::move(counter)) {}

    virtual ssize_t idaapi execute() override
    {
        // The plugin may have gone while this waited in IDA's queue.
        if (gate->closing.load()) {
            result = closing_result();
            return -1;
        }
        std::lock_guard<std::mutex> exec_lock(gate->exec_mutex);
        idasql::arm_cancel_at_start(options, cancel_counter);
        batch_guard_t bg;
        result = idasql::run_sql_script(
            sql,
            [this](const std::string& stmt, const xsql::QueryOptions& query_options) {
                return gate->engine->query(stmt, query_options);
            },
            options);
        return result.success ? 0 : -1;
    }
};

// Runs a script on the main thread. Server callbacks capture the shared gate, never
// the plugin: a server abandoned at teardown can still call this after the plugin
// is gone, and then the gate's `closing` answers "IDA is closing".
xsql::ScriptResult run_query_script_sync(const std::shared_ptr<request_gate_t>& gate,
                                         const std::string& sql,
                                         const xsql::ScriptOptions& options,
                                         idasql::CancelCounter cancel_counter = {})
{
    // Count first, then check: the dtor sets `closing` and then reads the
    // count, so either it sees this request or this request sees `closing`.
    gate->in_flight.fetch_add(1);
    if (gate->closing.load()) {
        gate->in_flight.fetch_sub(1);
        return closing_result();
    }
    query_script_request_t req(gate, sql, options, std::move(cancel_counter));
    execute_sync(req, MFF_WRITE);
    gate->in_flight.fetch_sub(1);
    return req.result;
}

xsql::ScriptResult run_query_script_sync(const std::shared_ptr<request_gate_t>& gate,
                                         const std::string& sql)
{
    return run_query_script_sync(gate, sql, idasql::with_default_timeout({}));
}

// Keep this module loaded for good. Abandoned server threads outlive the plugin
// and may still run its code after IDA would otherwise unload it.
void pin_this_module()
{
#ifdef _WIN32
    HMODULE self = nullptr;
    (void)GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(&pin_this_module), &self);
#else
    Dl_info info{};
    if (dladdr(reinterpret_cast<void*>(&pin_this_module), &info) && info.dli_fname)
        (void)dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE);
#endif
}

} // anonymous namespace

//=============================================================================
// IDA Plugin
//=============================================================================

struct idasql_plugmod_t : public plugmod_t
{
    std::unique_ptr<idasql::QueryEngine> engine_;
    std::unique_ptr<idasql::IdasqlCLI> cli_;
    std::shared_ptr<request_gate_t> gate_ = std::make_shared<request_gate_t>();
    bool idapython_runtime_acquired_ = false;

#ifdef IDASQL_HAS_MCP
    // Held by pointer so an abandoned server can be released along with its
    // threads instead of being destroyed with the plugin (see the dtor).
    std::unique_ptr<idasql::IDAMCPServer> mcp_server_ = std::make_unique<idasql::IDAMCPServer>();
#endif

    idasql::IDAHTTPServer http_server_;

    idasql_plugmod_t()
    {
        engine_ = std::make_unique<idasql::QueryEngine>();
        gate_->engine = engine_.get();
        if (engine_->is_valid()) {
            // get_ui_context_json() is now registered by QueryEngine::init()
            // for every runtime (real here in the plugin, a stub under CLI).
            msg("IDASQL v" IDASQL_VERSION_STRING ": Query engine initialized\n");

            // Here ida_open_link() navigates this IDA directly, so the gate
            // defaults ON (it stays OFF under idalib). No-op before IDA 9.4.
            idasql::deep_links::enable_navigation_default_for_gui();

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
            auto sql_executor = [gate = gate_](const std::string& sql) -> std::string {
                xsql::ScriptResult result = run_query_script_sync(gate, sql);
                return xsql::script_result_to_text(result);
            };

            // Create CLI with execute_sync wrapper for thread safety
            cli_ = std::make_unique<idasql::IdasqlCLI>(sql_executor);

#ifdef IDASQL_HAS_MCP
            // Setup MCP callbacks
            cli_->session().callbacks().mcp_status = [this]() -> std::string {
                if (mcp_server_->is_running()) {
                    return idasql::format_mcp_status(mcp_server_->port(), true, mcp_server_->bind_addr());
                } else {
                    // Auto-start if not running
                    return start_mcp_server();
                }
            };

            cli_->session().callbacks().mcp_start = [this](int port, const std::string& bind_addr) -> std::string {
                return start_mcp_server(port, bind_addr);
            };

            cli_->session().callbacks().mcp_stop = [this]() -> std::string {
                if (mcp_server_->is_running()) {
                    mcp_server_->stop();
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

            cli_->session().callbacks().http_start = [this](int port, const std::string& bind_addr,
                                                            const std::string& token) -> std::string {
                return start_http_server(port, bind_addr, token);
            };

            cli_->session().callbacks().http_stop = [this]() -> std::string {
                if (http_server_.is_running()) {
                    http_server_.stop();
                    return "HTTP server stopped";
                } else {
                    return "HTTP server not running";
                }
            };

            // Wire the .pin command (read/write autostart pins in the IDB).
            idasql::wire_pin_callbacks(cli_->session().callbacks());

            // Auto-install CLI so it's available immediately
            // User can still toggle it off with run(23) if desired
            cli_->install();

            // Honor pinned autostart preferences for this IDB. This is the
            // plugin-only half of the .pin feature: the CLI never auto-launches
            // on open. start_*_server() is non-blocking here and no-ops if a
            // server is already running.
            idasql::autostart::PinConfig pin = idasql::autostart::load();
            if (pin.http.enabled) {
                // port may be 0 -> start_http_server allocates a fresh random
                // port through the normal start path.
                msg("IDASQL: autostart -> %s\n",
                    start_http_server(pin.http.port, pin.http.host, pin.http.token).c_str());
            }
#ifdef IDASQL_HAS_MCP
            if (pin.mcp.enabled) {
                msg("IDASQL: autostart -> %s\n",
                    start_mcp_server(pin.mcp.port, pin.mcp.host).c_str());
            }
#endif
        } else {
            msg("IDASQL: Failed to init engine: %s\n", engine_->error().c_str());
        }
    }

#ifdef IDASQL_HAS_MCP
    std::string start_mcp_server(int req_port = 0, const std::string& bind_addr = "127.0.0.1")
    {
        if (mcp_server_->is_running()) {
            return idasql::format_mcp_status(mcp_server_->port(), true, mcp_server_->bind_addr());
        }

        // With no explicit port, fall back to the pinned host/port (shared
        // rule; see autostart::apply_pin_fallback).
        std::string addr = bind_addr;
        idasql::autostart::apply_pin_fallback(
            idasql::autostart::load().mcp, req_port, addr);

        // SQL executor that uses execute_sync for thread safety
        auto sql_executor = [gate = gate_](const std::string& sql) -> std::string {
            xsql::ScriptResult result = run_query_script_sync(gate, sql);
            return xsql::script_result_to_text(result);
        };

        // Start MCP server
        mcp_server_->set_deep_links_available(IDASQL_HAS_DEEP_LINKS != 0);
        int port = mcp_server_->start(req_port, sql_executor, addr);
        if (port <= 0) {
            return "Error: Failed to start MCP server on " + addr + ":"
                   + std::to_string(req_port)
                   + " (port may be in use; try a different port or interface).";
        }

        // Copy the paste-ready MCP client config to the clipboard on a fresh start.
        (void)xsql::thinclient::try_copy_text_to_clipboard_windows(
            xsql::thinclient::build_mcp_clipboard_payload(
                "idasql", mcp_server_->bind_addr(), port));

        return idasql::format_mcp_info(port, mcp_server_->bind_addr());
    }
#endif

    std::string start_http_server(int req_port = 0, const std::string& bind_addr = "127.0.0.1",
                                  const std::string& token = "")
    {
        if (http_server_.is_running()) {
            return idasql::format_http_status(http_server_.port(), true, http_server_.bind_addr());
        }

        // With no explicit port, fall back to the pinned host/port/token (shared
        // rule; see autostart::apply_pin_fallback).
        std::string addr = bind_addr;
        std::string auth_token = token;
        idasql::autostart::apply_pin_fallback(
            idasql::autostart::load().http, req_port, addr, &auth_token);

        // SQL executor that uses execute_sync for thread safety. The request's
        // own X-XSQL-Timeout wins over query_timeout_ms, and its cancellation is
        // armed when it starts on the main thread.
        idasql::HTTPQueryCallback sql_cb =
            [gate = gate_, counter = http_server_.cancel_counter()](
                const std::string& sql, const xsql::ScriptOptions& options) {
                return run_query_script_sync(
                    gate, sql, idasql::with_default_timeout(options), counter);
            };

        // Start HTTP server, no queue (plugin mode)
        int port = http_server_.start(req_port, sql_cb, addr, /*use_queue=*/false, auth_token);
        if (port <= 0) {
            return "Error: Failed to start HTTP server on " + addr + ":"
                   + std::to_string(req_port)
                   + " (port may be in use; try a different port or interface).";
        }

        // Copy the paste-ready agent instructions to the clipboard on a fresh
        // start, with the effective token (explicit or pinned) so the curl works.
        (void)xsql::thinclient::try_copy_text_to_clipboard_windows(
            xsql::thinclient::build_http_clipboard_payload(
                "idasql", http_server_.bind_addr(), port,
                idasql::default_binary_query(), auth_token));

        return idasql::format_http_info(
            port, http_server_.bind_addr(), "Type '.http stop' to stop the server.");
    }

    ~idasql_plugmod_t()
    {
        // Refuse new requests, then see whether one is still in flight. If one is,
        // it is waiting on this (the main) thread: it is either the request that
        // called qexit() or one queued behind it, and neither can finish now.
        // Stopping a server joins its workers, so it would wait for that request
        // forever (measured: qexit from an HTTP idapython_snippet hung IDA).
        // Such a server is abandoned to process exit instead.
        gate_->closing.store(true);
        const bool abandon = gate_->in_flight.load() > 0;
        if (abandon) pin_this_module();
#ifdef IDASQL_HAS_MCP
        // Stop MCP server before destroying engine. An abandoned one is released
        // with its threads: its tool callback still points into it.
        if (mcp_server_->is_running()) {
            if (abandon) {
                mcp_server_->abandon();
                (void)mcp_server_.release();
            } else {
                mcp_server_->stop();
            }
        }
#endif
        // Stop HTTP server before destroying engine
        if (http_server_.is_running()) {
            if (abandon) http_server_.abandon(); else http_server_.stop();
        }
        if (cli_) cli_->uninstall();
        idasql::ui_context::shutdown_capture_helper();
        if (idapython_runtime_acquired_) {
            idasql::idapython::runtime_release();
            idapython_runtime_acquired_ = false;
        }
        // A request in flight may be the statement that called qexit(), still on
        // this stack; qexit never returns to it, so leave its engine to exit too.
        if (abandon) (void)engine_.release(); else engine_.reset();
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
    // Skip loading when running under idalib (e.g., idasql CLI). The SDK
    // version guard lives in idasql_is_ida_library() (ida_compat.hpp).
    if (idasql_is_ida_library()) {
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
