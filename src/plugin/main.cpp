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

// Platform-specific include order:
// - Windows: json before IDA (IDA poisons stdlib functions)
// - macOS/Linux: IDA before json
#include <idasql/platform_undef.hpp>

#ifdef _WIN32
// Include shlobj.h BEFORE IDA headers: agent_settings.hpp pulls in <shlobj.h>
// which defines CM_MASK/CM_STATE enums in shobjidl_core.h. IDA's typeinf.hpp
// also defines CM_MASK (const uchar). Including Windows headers first lets
// IDA's definition shadow the Windows enum without conflict.
#include <shlobj.h>
#include <xsql/json.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <idasql/database.hpp>
#else
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <idasql/database.hpp>
#include <xsql/json.hpp>
#endif

// IDASQL CLI (command line interface)
#include "../common/idasql_cli.hpp"

// Plugin control codes
#include "../common/plugin_control.hpp"

// Version info
#include "../common/idasql_version.hpp"

// MCP server (when AI agent is enabled)
#ifdef IDASQL_HAS_AI_AGENT
#include "../common/mcp_server.hpp"
#include "../common/ai_agent.hpp"
#endif

// HTTP server for .http REPL command
#include "../common/http_server.hpp"

//=============================================================================
// IDA execute_sync wrapper
//=============================================================================

namespace {

struct query_request_t : public exec_request_t
{
    idasql::QueryEngine* engine;
    std::string sql;
    idasql::QueryResult result;

    query_request_t(idasql::QueryEngine* e, const std::string& s)
        : engine(e), sql(s) {}

    virtual ssize_t idaapi execute() override
    {
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

#ifdef IDASQL_HAS_AI_AGENT
    idasql::IDAMCPServer mcp_server_;
    std::unique_ptr<idasql::AIAgent> mcp_agent_;  // AI agent for MCP
#endif

    idasql::IDAHTTPServer http_server_;

    idasql_plugmod_t()
    {
        engine_ = std::make_unique<idasql::QueryEngine>();
        if (engine_->is_valid()) {
            msg("IDASQL v" IDASQL_VERSION_STRING ": Query engine initialized\n");

            // SQL executor that uses execute_sync for thread safety
            auto sql_executor = [this](const std::string& sql) -> std::string {
                query_request_t req(engine_.get(), sql);
                execute_sync(req, MFF_WRITE);
                if (req.result.success) {
                    return req.result.to_string();
                } else {
                    return "Error: " + req.result.error;
                }
            };

            // Create CLI with execute_sync wrapper for thread safety
            cli_ = std::make_unique<idasql::IdasqlCLI>(sql_executor);

#ifdef IDASQL_HAS_AI_AGENT
            // Setup MCP callbacks
            cli_->session().callbacks().mcp_status = [this]() -> std::string {
                if (mcp_server_.is_running()) {
                    return idasql::format_mcp_status(mcp_server_.port(), true);
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
                    mcp_agent_.reset();
                    return "MCP server stopped";
                } else {
                    return "MCP server not running";
                }
            };
#endif

            // Setup HTTP server callbacks
            cli_->session().callbacks().http_status = [this]() -> std::string {
                if (http_server_.is_running()) {
                    return idasql::format_http_status(http_server_.port(), true);
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

#ifdef IDASQL_HAS_AI_AGENT
    std::string start_mcp_server(int req_port = 0, const std::string& bind_addr = "127.0.0.1")
    {
        if (mcp_server_.is_running()) {
            return idasql::format_mcp_status(mcp_server_.port(), true);
        }

        // SQL executor that uses execute_sync for thread safety
        auto sql_executor = [this](const std::string& sql) -> std::string {
            query_request_t req(engine_.get(), sql);
            execute_sync(req, MFF_WRITE);
            if (req.result.success) {
                return req.result.to_string();
            } else {
                return "Error: " + req.result.error;
            }
        };

        // Create AI agent for MCP (runs on MCP thread, SQL via execute_sync)
        mcp_agent_ = std::make_unique<idasql::AIAgent>(sql_executor);
        mcp_agent_->start();

        // MCP ask callback - agent runs on MCP thread
        idasql::AskCallback ask_cb = [this](const std::string& question) -> std::string {
            if (!mcp_agent_) return "Error: AI agent not available";
            return mcp_agent_->query(question);
        };

        // Start MCP server
        int port = mcp_server_.start(req_port, sql_executor, ask_cb, bind_addr);
        if (port <= 0) {
            mcp_agent_.reset();
            return "Error: Failed to start MCP server";
        }

        return idasql::format_mcp_info(port, true);
    }
#endif

    std::string start_http_server(int req_port = 0, const std::string& bind_addr = "127.0.0.1")
    {
        if (http_server_.is_running()) {
            return idasql::format_http_status(http_server_.port(), true);
        }

        // SQL executor that uses execute_sync for thread safety and returns JSON
        idasql::HTTPQueryCallback sql_cb = [this](const std::string& sql) -> std::string {
            query_request_t req(engine_.get(), sql);
            execute_sync(req, MFF_WRITE);

            xsql::json j = {{"success", req.result.success}};
            if (req.result.success) {
                j["columns"] = req.result.columns;
                xsql::json rows = xsql::json::array();
                for (const auto& row : req.result.rows) {
                    rows.push_back(row.values);
                }
                j["rows"] = rows;
                j["row_count"] = req.result.rows.size();
            } else {
                j["error"] = req.result.error;
            }
            return j.dump();
        };

        // Start HTTP server, no queue (plugin mode)
        int port = http_server_.start(req_port, sql_cb, bind_addr);
        if (port <= 0) {
            return "Error: Failed to start HTTP server";
        }

        return idasql::format_http_info(port, "Type '.http stop' to stop the server.");
    }

    ~idasql_plugmod_t()
    {
#ifdef IDASQL_HAS_AI_AGENT
        // Stop MCP server before destroying engine
        if (mcp_server_.is_running()) {
            mcp_server_.stop();
        }
        mcp_agent_.reset();
#endif
        // Stop HTTP server before destroying engine
        if (http_server_.is_running()) {
            http_server_.stop();
        }
        if (cli_) cli_->uninstall();
        engine_.reset();
        msg("IDASQL: Plugin terminated\n");
    }

    virtual bool idaapi run(size_t arg) override
    {
        using namespace idasql;

        switch (arg) {
            case 0:
                msg("IDASQL v" IDASQL_VERSION_STRING " - SQL interface for IDA database\n");
                msg("Use dot commands: .http, .mcp, .help\n");
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
    "  .mcp start/stop   - MCP server\n"
    "  .help             - Show all commands\n"
    "\n"
    "run(23): Toggle CLI (command line interface)",
    "IDASQL",
    ""
};
