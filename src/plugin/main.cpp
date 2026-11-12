// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include <idasql/platform.hpp>

#include <atomic>
#include <memory>
#include <string>
#include <functional>
#include <mutex>

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

#include "../common/idasql_cli.hpp"

#include "../common/pin_commands.hpp"
#include "../common/remote_commands.hpp"
#include "../lib/src/rescue_guard.hpp"
#include "../lib/src/instances.hpp"
#include <idasql/autostart_pin.hpp>
#include <idasql/remote_setting.hpp>

#include "../common/plugin_control.hpp"

#include "../lib/src/ida_compat.hpp"

#include "../common/idasql_version.hpp"

#ifdef IDASQL_HAS_MCP
#include "../common/mcp_server.hpp"
#endif

#include "../common/binary_query.hpp"
#include "../common/http_server.hpp"
#include "../common/json_utils.hpp"
#include "../common/sql_script.hpp"
#include <xsql/query_script.hpp>

namespace {

struct batch_guard_t {
    bool prev;
    batch_guard_t() : prev(batch) { batch = true; }
    ~batch_guard_t() { batch = prev; }
};

struct request_gate_t
{
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
    idasql::CancelCounter cancel_counter;
    xsql::ScriptResult result;

    query_script_request_t(std::shared_ptr<request_gate_t> g, const std::string& s,
                           const xsql::ScriptOptions& opts, idasql::CancelCounter counter)
        : gate(std::move(g)), sql(s), options(opts), cancel_counter(std::move(counter)) {}

    virtual ssize_t idaapi execute() override
    {
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

xsql::ScriptResult run_query_script_sync(const std::shared_ptr<request_gate_t>& gate,
                                         const std::string& sql,
                                         const xsql::ScriptOptions& options,
                                         idasql::CancelCounter cancel_counter = {})
{
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

struct main_thread_call_t : public exec_request_t
{
    std::function<void()> fn;
    explicit main_thread_call_t(std::function<void()> f) : fn(std::move(f)) {}
    ssize_t idaapi execute() override
    {
        fn();
        return 0;
    }
};

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

}

struct idasql_plugmod_t : public plugmod_t
{
    std::unique_ptr<idasql::QueryEngine> engine_;
    std::unique_ptr<idasql::IdasqlCLI> cli_;
    std::shared_ptr<request_gate_t> gate_ = std::make_shared<request_gate_t>();
    bool idapython_runtime_acquired_ = false;

#ifdef IDASQL_HAS_MCP
    std::unique_ptr<idasql::IDAMCPServer> mcp_server_ = std::make_unique<idasql::IDAMCPServer>();
#endif

    idasql::IDAHTTPServer http_server_;
    idasql::rescue::Guard rescue_guard_;
    std::shared_ptr<std::atomic<bool>> alive_ = std::make_shared<std::atomic<bool>>(true);

    idasql_plugmod_t()
    {
        {
            const std::string idb = get_path(PATH_TYPE_IDB);
            std::string rescue_error;
            const bool armed = rescue_guard_.arm(idb, &rescue_error);
            if (armed)
                msg("idasql: rescue armed; if IDA hangs run: idasql rescue \"%s\"\n", idb.c_str());
            else
                msg("idasql: rescue not armed: %s\n", rescue_error.c_str());
            idasql::instances::Record rec;
            rec.host = "gui";
            char kernel[32] = {0};
            get_kernel_version(kernel, sizeof(kernel));
            rec.ida_version = kernel;
            rec.idasql_version = IDASQL_VERSION_STRING;
            rec.idb_path = idb;
            rec.rescue = armed;
            rec.remote = idasql::remote::enabled();
            (void)idasql::instances::self().start(rec);
        }
        engine_ = std::make_unique<idasql::QueryEngine>();
        gate_->engine = engine_.get();
        if (engine_->is_valid()) {
            msg("IDASQL v" IDASQL_VERSION_STRING ": Query engine initialized\n");

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

            auto sql_executor = [gate = gate_](const std::string& sql) -> std::string {
                xsql::ScriptResult result = run_query_script_sync(gate, sql);
                return xsql::script_result_to_text(result);
            };

            cli_ = std::make_unique<idasql::IdasqlCLI>(sql_executor);

#ifdef IDASQL_HAS_MCP
            cli_->session().callbacks().mcp_status = [this]() -> std::string {
                if (mcp_server_->is_running()) {
                    return idasql::format_mcp_status(mcp_server_->port(), true, mcp_server_->bind_addr());
                } else {
                    return start_mcp_server();
                }
            };

            cli_->session().callbacks().mcp_start = [this](int port, const std::string& bind_addr) -> std::string {
                return start_mcp_server(port, bind_addr);
            };

            cli_->session().callbacks().mcp_stop = [this]() -> std::string {
                return stop_mcp_server() ? "MCP server stopped" : "MCP server not running";
            };
#endif

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
                return stop_http_server() ? "HTTP server stopped" : "HTTP server not running";
            };

            idasql::wire_pin_callbacks(cli_->session().callbacks());
            idasql::wire_remote_callbacks(cli_->session().callbacks(), true);
            rescue_guard_.set_host_actions(
                [this, alive = alive_](const idasql::control::Request& req) {
                    using idasql::control::Reply;
                    if (req.action != "start" && req.action != "stop" && req.action != "remote")
                        return Reply{"unknown_action", xsql::json::object()};
                    Reply reply{"failed", xsql::json{{"message", "IDA is closing"}}};
                    main_thread_call_t call([&]() {
                        if (alive->load()) reply = remote_request_on_main_thread(req);
                    });
                    execute_sync(call, MFF_WRITE);
                    return reply;
                });

            cli_->install();

            idasql::autostart::PinConfig pin = idasql::autostart::load();
            if (pin.http.enabled) {
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
    std::string start_mcp_server(int req_port = 0, const std::string& bind_addr = "127.0.0.1",
                                 bool copy_to_clipboard = true)
    {
        if (mcp_server_->is_running()) {
            return idasql::format_mcp_status(mcp_server_->port(), true, mcp_server_->bind_addr());
        }

        std::string addr = bind_addr;
        idasql::autostart::apply_pin_fallback(
            idasql::autostart::load().mcp, req_port, addr);

        auto sql_executor = [gate = gate_](const std::string& sql) -> std::string {
            xsql::ScriptResult result = run_query_script_sync(gate, sql);
            return xsql::script_result_to_text(result);
        };

        mcp_server_->set_deep_links_available(IDASQL_HAS_DEEP_LINKS != 0);
        int port = mcp_server_->start(req_port, sql_executor, addr);
        if (port <= 0) {
            return "Error: Failed to start MCP server on " + addr + ":"
                   + std::to_string(req_port)
                   + " (port may be in use; try a different port or interface).";
        }

        idasql::instances::self().set_mcp(idasql::instances::mcp_url(mcp_server_->bind_addr(), port), false);

        if (copy_to_clipboard)
            (void)xsql::thinclient::try_copy_text_to_clipboard_windows(
                xsql::thinclient::build_mcp_clipboard_payload(
                    "idasql", mcp_server_->bind_addr(), port));

        return idasql::format_mcp_info(port, mcp_server_->bind_addr());
    }

    bool stop_mcp_server()
    {
        if (!mcp_server_->is_running()) return false;
        mcp_server_->stop();
        idasql::instances::self().set_mcp("", false);
        return true;
    }
#endif

    bool stop_http_server()
    {
        if (!http_server_.is_running()) return false;
        http_server_.stop();
        idasql::instances::self().set_http("", false);
        return true;
    }

    std::string start_http_server(int req_port = 0, const std::string& bind_addr = "127.0.0.1",
                                  const std::string& token = "", bool copy_to_clipboard = true)
    {
        if (http_server_.is_running()) {
            return idasql::format_http_status(http_server_.port(), true, http_server_.bind_addr());
        }

        std::string addr = bind_addr;
        std::string auth_token = token;
        idasql::autostart::apply_pin_fallback(
            idasql::autostart::load().http, req_port, addr, &auth_token);

        idasql::HTTPQueryCallback sql_cb =
            [gate = gate_, counter = http_server_.cancel_counter()](
                const std::string& sql, const xsql::ScriptOptions& options) {
                return run_query_script_sync(
                    gate, sql, idasql::with_default_timeout(options), counter);
            };

        int port = http_server_.start(req_port, sql_cb, addr, false, auth_token);
        if (port <= 0) {
            return "Error: Failed to start HTTP server on " + addr + ":"
                   + std::to_string(req_port)
                   + " (port may be in use; try a different port or interface).";
        }

        idasql::instances::self().set_http(idasql::instances::http_url(http_server_.bind_addr(), port),
                                           !auth_token.empty());

        if (copy_to_clipboard)
            (void)xsql::thinclient::try_copy_text_to_clipboard_windows(
                xsql::thinclient::build_http_clipboard_payload(
                    "idasql", http_server_.bind_addr(), port,
                    idasql::default_binary_query(), auth_token));

        return idasql::format_http_info(
            port, http_server_.bind_addr(), "Type '.http stop' to stop the server.");
    }

    idasql::control::Reply remote_request_on_main_thread(const idasql::control::Request& req)
    {
        using idasql::control::Reply;
        using json = xsql::json;
        const json from = req.args.value("from", json::object());
        const std::string who = from.value("exe", std::string("a process")) + " (pid "
                                + std::to_string(from.value("pid", uint64_t{0})) + ")";

        if (req.action == "remote") {
            const bool on = req.args.value("on", false);
            idasql::remote::set_enabled(on);
            idasql::instances::self().set_remote(on);
            msg("IDASQL: %s turned remote control %s for this database (remote)\n", who.c_str(),
                on ? "on" : "off");
            return Reply{"ok", json{{"remote", on}}};
        }

        const std::string service = req.args.value("service", std::string("http"));
        const char* label = service == "mcp" ? "MCP" : "HTTP";
        const bool start = req.action == "start";
        if (!idasql::remote::enabled()) {
            msg("IDASQL: %s asked to %s the %s server; refused: remote control is off (.remote on allows "
                "it)\n", who.c_str(), start ? "start" : "stop", label);
            return Reply{"remote_off", json{{"message", "remote control is off for this database"}}};
        }

        if (service == "http") {
            if (!start) {
                const bool stopped = stop_http_server();
                msg("IDASQL: %s %s the HTTP server (remote)\n", who.c_str(),
                    stopped ? "stopped" : "asked to stop (not running)");
                return Reply{"ok", json{{"stopped", stopped}}};
            }
            const bool already = http_server_.is_running();
            const std::string text = start_http_server(0, "127.0.0.1", "", false);
            if (!http_server_.is_running()) {
                msg("IDASQL: %s asked to start the HTTP server; it failed: %s\n", who.c_str(), text.c_str());
                return Reply{"failed", json{{"message", text}}};
            }
            const std::string url = idasql::instances::http_url(http_server_.bind_addr(), http_server_.port());
            msg("IDASQL: %s %s HTTP on %s (remote)\n", who.c_str(),
                already ? "asked for; already serving" : "started", url.c_str());
            return Reply{"ok", json{{"url", url},
                                    {"auth", idasql::instances::self().record().http_auth},
                                    {"already", already}}};
        }
        if (service == "mcp") {
#ifdef IDASQL_HAS_MCP
            if (!start) {
                const bool stopped = stop_mcp_server();
                msg("IDASQL: %s %s the MCP server (remote)\n", who.c_str(),
                    stopped ? "stopped" : "asked to stop (not running)");
                return Reply{"ok", json{{"stopped", stopped}}};
            }
            const bool already = mcp_server_->is_running();
            const std::string text = start_mcp_server(0, "127.0.0.1", false);
            if (!mcp_server_->is_running()) {
                msg("IDASQL: %s asked to start the MCP server; it failed: %s\n", who.c_str(), text.c_str());
                return Reply{"failed", json{{"message", text}}};
            }
            const std::string url = idasql::instances::mcp_url(mcp_server_->bind_addr(), mcp_server_->port());
            msg("IDASQL: %s %s MCP on %s (remote)\n", who.c_str(),
                already ? "asked for; already serving" : "started", url.c_str());
            return Reply{"ok", json{{"url", url}, {"auth", false}, {"already", already}}};
#else
            return Reply{"refused", json{{"message", "this IDA's idasql plugin was built without MCP"}}};
#endif
        }
        return Reply{"refused", json{{"message", "unknown service '" + service + "' (http or mcp)"}}};
    }

    ~idasql_plugmod_t()
    {
        alive_->store(false);
        rescue_guard_.set_host_actions(nullptr);
        idasql::instances::self().stop();
        if (!rescue_guard_.disarm()) pin_this_module();
        gate_->closing.store(true);
        const bool abandon = gate_->in_flight.load() > 0;
        if (abandon) pin_this_module();
#ifdef IDASQL_HAS_MCP
        if (mcp_server_->is_running()) {
            if (abandon) {
                mcp_server_->abandon();
                (void)mcp_server_.release();
            } else {
                mcp_server_->stop();
            }
        }
#endif
        if (http_server_.is_running()) {
            if (abandon) http_server_.abandon(); else http_server_.stop();
        }
        if (cli_) cli_->uninstall();
        idasql::ui_context::shutdown_capture_helper();
        if (idapython_runtime_acquired_) {
            idasql::idapython::runtime_release();
            idapython_runtime_acquired_ = false;
        }
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

static plugmod_t* idaapi init()
{
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
