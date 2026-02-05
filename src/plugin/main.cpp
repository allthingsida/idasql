/**
 * idasql_plugin - IDA plugin that hosts an IDASQL server
 *
 * GUI mode:   Press Ctrl-Shift-Q to toggle server on/off (uses execute_sync)
 * idalib mode: Driver calls run() with control codes from plugin_control.hpp
 *
 * Connect with: idasql --remote localhost:13337 -q "SELECT * FROM funcs"
 *
 * See plugin_control.hpp for run() arg codes.
 */

// =============================================================================
// CRITICAL: Include order matters on Windows!
// 1. winsock2.h MUST come before any standard library headers (Windows requirement)
// 2. nlohmann/json before IDA headers (IDA macros can interfere)
// 3. Standard library headers
// 4. IDA headers
//
// Note: USE_DANGEROUS_FUNCTIONS and USE_STANDARD_FILE_FUNCTIONS are defined
// via CMakeLists.txt to disable IDA's safe function macros that conflict
// with MSVC standard library (__msvc_filebuf.hpp uses fgetc/fputc).
// =============================================================================

#include <idasql/platform.hpp>

// Platform-specific socket includes - MUST come first on Windows
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>

    // Include shobjidl_core.h BEFORE IDA headers to let Windows define CM_MASK first.
    // Later, IDA's CM_MASK (const uchar) will shadow Windows' CM_MASK (enum).
    // This allows both to coexist since IDA code uses its own CM_MASK.
    #include <shobjidl_core.h>

    typedef SOCKET socket_t;
    #define SOCKET_INVALID INVALID_SOCKET
    #define SOCKET_ERROR_CODE WSAGetLastError()
    #define CLOSE_SOCKET closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    typedef int socket_t;
    #define SOCKET_INVALID -1
    #define SOCKET_ERROR_CODE errno
    #define CLOSE_SOCKET close
#endif

// Standard library includes
#include <memory>
#include <thread>
#include <atomic>
#include <string>
#include <sstream>
#include <cstdint>
#include <queue>
#include <mutex>
#include <functional>
#include <limits>
#include <cstdlib>
#include <random>
#include <iomanip>

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

// Plugin control codes (shared with test harness)
#include "../common/plugin_control.hpp"

// MCP server (when AI agent is enabled)
#ifdef IDASQL_HAS_AI_AGENT
#include "../common/mcp_server.hpp"
#include "../common/ai_agent.hpp"
#endif

// HTTP server for .http REPL command
#ifdef IDASQL_HAS_HTTP
#include "../common/http_server.hpp"
#endif

//=============================================================================
// JSON Protocol Helpers
//=============================================================================

namespace {

std::string result_to_json(const idasql::QueryResult& result)
{
    xsql::json j = {{"success", result.success}};

    if (result.success) {
        j["columns"] = result.columns;

        xsql::json rows = xsql::json::array();
        for (const auto& row : result.rows) {
            rows.push_back(row.values);  // Row::values is std::vector<std::string>
        }
        j["rows"] = rows;
        j["row_count"] = result.row_count();
    } else {
        j["error"] = result.error;
    }

    return j.dump();
}

std::string extract_field(const std::string& json, const char* field)
{
    if (!field || !*field) return "";

    std::string key = "\"";
    key += field;
    key += "\"";

    auto key_pos = json.find(key);
    if (key_pos == std::string::npos) return "";

    auto colon_pos = json.find(':', key_pos + key.size());
    if (colon_pos == std::string::npos) return "";

    auto pos = json.find('\"', colon_pos + 1);
    if (pos == std::string::npos) return "";
    pos++;

    std::string value;
    while (pos < json.size() && json[pos] != '\"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            pos++;
            switch (json[pos]) {
                case 'n': value += '\n'; break;
                case 'r': value += '\r'; break;
                case 't': value += '\t'; break;
                case '\"': value += '\"'; break;
                case '\\': value += '\\'; break;
                default: value += json[pos]; break;
            }
        } else {
            value += json[pos];
        }
        pos++;
    }
    return value;
}

std::string extract_sql(const std::string& json)
{
    return extract_field(json, "sql");
}

std::string extract_token(const std::string& json)
{
    return extract_field(json, "token");
}

} // anonymous namespace

//=============================================================================
// Pending query for poll mode
//=============================================================================

struct pending_query_t
{
    std::string sql;
    idasql::QueryResult result;
    std::atomic<bool> done{false};
};

//=============================================================================
// IDA execute_sync wrapper (for GUI mode)
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
// IDASQL Server
//=============================================================================

class idasql_server_t
{
public:
    using query_func_t = std::function<idasql::QueryResult(const std::string&)>;

private:
    std::thread thread_;
    std::atomic<bool> running_{false};
    socket_t listen_sock_ = SOCKET_INVALID;
    std::atomic<socket_t> active_client_{SOCKET_INVALID};
    int port_ = 0;
    query_func_t query_func_;
    std::string auth_token_;

    // Poll mode state
    bool poll_mode_ = false;
    std::queue<pending_query_t*> pending_;
    std::mutex pending_mutex_;
    idasql::QueryEngine* engine_ = nullptr;

public:
    void set_engine(idasql::QueryEngine* e) { engine_ = e; }
    void set_query_func(query_func_t func) { query_func_ = std::move(func); }   
    void set_poll_mode(bool poll) { poll_mode_ = poll; }
    void set_auth_token(std::string token) { auth_token_ = std::move(token); }

    bool start(int port)
    {
        if (running_) return false;
        port_ = port;
        if (!auth_token_.empty()) {
            msg("IDASQL: Auth token enabled (set via IDASQL_TOKEN)\n");
        }
        running_ = true;
        thread_ = std::thread(&idasql_server_t::run_server, this);
        return true;
    }

    void stop()
    {
        if (!running_) return;
        running_ = false;

        if (listen_sock_ != SOCKET_INVALID) {
            CLOSE_SOCKET(listen_sock_);
            listen_sock_ = SOCKET_INVALID;
        }

        socket_t client = active_client_.exchange(SOCKET_INVALID);
        if (client != SOCKET_INVALID) {
#ifdef _WIN32
            ::shutdown(client, SD_BOTH);
#else
            ::shutdown(client, SHUT_RDWR);
#endif
        }

        if (thread_.joinable()) {
            thread_.join();
        }

        // Clear any pending queries
        std::lock_guard<std::mutex> lock(pending_mutex_);
        while (!pending_.empty()) {
            auto* item = pending_.front();
            pending_.pop();
            item->result.error = "Server shutting down";
            item->done = true;
        }
    }

    bool is_running() const { return running_; }

    // Called by main thread (driver) via run(arg=4)
    bool poll_one()
    {
        if (!poll_mode_ || !engine_) return false;

        pending_query_t* item = nullptr;
        {
            std::lock_guard<std::mutex> lock(pending_mutex_);
            if (pending_.empty()) return false;
            item = pending_.front();
            pending_.pop();
        }

        // Execute on main thread
        item->result = engine_->query(item->sql);
        item->done = true;
        return true;
    }

private:
    bool send_message(socket_t sock, const std::string& payload)
    {
        if (payload.size() > 10 * 1024 * 1024) return false;
        if (payload.size() > static_cast<size_t>((std::numeric_limits<uint32_t>::max)())) return false;

        auto send_all = [&](const char* data, size_t len) -> bool {
            size_t total = 0;
            while (total < len) {
                int n = send(sock, data + total, static_cast<int>(len - total), 0);
                if (n <= 0) return false;
                total += static_cast<size_t>(n);
            }
            return true;
        };

        uint32_t len = static_cast<uint32_t>(payload.size());
        uint32_t len_net = htonl(len);

        if (!send_all(reinterpret_cast<const char*>(&len_net), sizeof(len_net))) return false;
        return send_all(payload.data(), payload.size());
    }

    bool recv_message(socket_t sock, std::string& payload)
    {
        auto recv_all = [&](char* data, size_t len) -> bool {
            size_t total = 0;
            while (total < len) {
                int n = recv(sock, data + total, static_cast<int>(len - total), 0);
                if (n <= 0) return false;
                total += static_cast<size_t>(n);
            }
            return true;
        };

        uint32_t len_net = 0;
        if (!recv_all(reinterpret_cast<char*>(&len_net), sizeof(len_net))) return false;

        uint32_t len = ntohl(len_net);
        if (len > 10 * 1024 * 1024) return false;

        payload.resize(len);
        return recv_all(payload.data(), payload.size());
    }

    // Execute query - either via callback (execute_sync) or poll queue
    idasql::QueryResult execute_query(const std::string& sql)
    {
        if (!poll_mode_ && query_func_) {
            // GUI mode: use execute_sync callback
            return query_func_(sql);
        } else {
            // Poll mode: queue and wait for main thread
            auto* item = new pending_query_t();
            item->sql = sql;
            {
                std::lock_guard<std::mutex> lock(pending_mutex_);
                pending_.push(item);
            }

            // Wait for main thread to process
            while (!item->done && running_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }

            auto result = std::move(item->result);
            delete item;
            return result;
        }
    }

    void handle_client(socket_t client)
    {
        active_client_.store(client);
        std::string request;
        while (running_ && recv_message(client, request)) {
            std::string sql = extract_sql(request);
            if (sql.empty()) {
                send_message(client, xsql::json{{"success", false}, {"error", "Invalid request: missing sql field"}}.dump());
                continue;
            }

            if (!auth_token_.empty()) {
                std::string token = extract_token(request);
                if (token != auth_token_) {
                    send_message(client, xsql::json{{"success", false}, {"error", "Unauthorized"}}.dump());
                    continue;
                }
            }

            auto result = execute_query(sql);
            if (!send_message(client, result_to_json(result))) break;
        }
        active_client_.compare_exchange_strong(client, SOCKET_INVALID);
        CLOSE_SOCKET(client);
    }

    void run_server()
    {
#ifdef _WIN32
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            msg("IDASQL: WSAStartup failed\n");
            running_ = false;
            return;
        }
#endif

        listen_sock_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_sock_ == SOCKET_INVALID) {
            msg("IDASQL: socket() failed\n");
            running_ = false;
            goto cleanup;
        }

        {
            int opt = 1;
            setsockopt(listen_sock_, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<char*>(&opt), sizeof(opt));
        }

        {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
                msg("IDASQL: inet_pton() failed for 127.0.0.1\n");
                CLOSE_SOCKET(listen_sock_);
                listen_sock_ = SOCKET_INVALID;
                running_ = false;
                goto cleanup;
            }
            addr.sin_port = htons(static_cast<uint16_t>(port_));

            if (bind(listen_sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
                msg("IDASQL: bind() failed: %d\n", SOCKET_ERROR_CODE);
                CLOSE_SOCKET(listen_sock_);
                listen_sock_ = SOCKET_INVALID;
                running_ = false;
                goto cleanup;
            }
        }

        if (listen(listen_sock_, 1) < 0) {
            msg("IDASQL: listen() failed\n");
            CLOSE_SOCKET(listen_sock_);
            listen_sock_ = SOCKET_INVALID;
            running_ = false;
            goto cleanup;
        }

        msg("IDASQL: Server listening on 127.0.0.1:%d (mode=%s)\n",
            port_, poll_mode_ ? "poll" : "execute_sync");

        // Set socket timeout so accept() can check running_ flag
#ifdef _WIN32
        {
            DWORD timeout = 500;
            setsockopt(listen_sock_, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<char*>(&timeout), sizeof(timeout));
        }
#else
        {
            struct timeval tv = {0, 500000};
            setsockopt(listen_sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        }
#endif

        while (running_) {
            socket_t client = accept(listen_sock_, nullptr, nullptr);
            if (client == SOCKET_INVALID) {
                continue;  // Timeout or error, check running_ and retry
            }

            msg("IDASQL: Client connected\n");
            handle_client(client);
            msg("IDASQL: Client disconnected\n");
        }

        if (listen_sock_ != SOCKET_INVALID) {
            CLOSE_SOCKET(listen_sock_);
            listen_sock_ = SOCKET_INVALID;
        }

cleanup:
#ifdef _WIN32
        WSACleanup();
#endif
        msg("IDASQL: Server thread exiting\n");
    }
};

//=============================================================================
// IDA Plugin
//=============================================================================

struct idasql_plugmod_t : public plugmod_t
{
    std::unique_ptr<idasql::QueryEngine> engine_;
    idasql_server_t server_;
    std::unique_ptr<idasql::IdasqlCLI> cli_;

#ifdef IDASQL_HAS_AI_AGENT
    idasql::IDAMCPServer mcp_server_;
    std::unique_ptr<idasql::AIAgent> mcp_agent_;  // AI agent for MCP
#endif

#ifdef IDASQL_HAS_HTTP
    idasql::IDAHTTPServer http_server_;
#endif

    idasql_plugmod_t()
    {
        engine_ = std::make_unique<idasql::QueryEngine>();
        if (engine_->is_valid()) {
            msg("IDASQL: Query engine initialized\n");
            server_.set_engine(engine_.get());

            qstring tok;
            bool allow_unauth = false;
            qstring allow_env;
            if (qgetenv("IDASQL_ALLOW_NO_AUTH", &allow_env) && !allow_env.empty()) {
                allow_unauth = true;
            }

            if (qgetenv("IDASQL_TOKEN", &tok) && !tok.empty()) {
                server_.set_auth_token(tok.c_str());
                msg("IDASQL: Auth token enabled via IDASQL_TOKEN\n");
            } else if (!allow_unauth) {
                // Generate a temporary token to avoid unauthenticated access by default
                std::random_device rd;
                std::mt19937_64 rng(rd());
                std::uniform_int_distribution<uint64_t> dist;
                uint64_t hi = dist(rng);
                uint64_t lo = dist(rng);
                std::ostringstream oss;
                oss << std::hex << std::setfill('0') << std::setw(16) << hi
                    << std::setw(16) << lo;
                auto token = oss.str();
                server_.set_auth_token(token);
                msg("IDASQL: Auth token generated (set IDASQL_TOKEN to override). Token: %s\n",
                    token.c_str());
            } else {
                msg("IDASQL: WARNING: Remote server starting without auth (IDASQL_ALLOW_NO_AUTH set)\n");
            }

            // Setup execute_sync callback for GUI mode
            server_.set_query_func([this](const std::string& sql) {
                query_request_t req(engine_.get(), sql);
                // Allow write-capable SQL helpers (set_name, set_comment, etc.)
                execute_sync(req, MFF_WRITE);
                return std::move(req.result);
            });

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

            cli_->session().callbacks().mcp_start = [this]() -> std::string {
                return start_mcp_server();
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

#ifdef IDASQL_HAS_HTTP
            // Setup HTTP server callbacks
            cli_->session().callbacks().http_status = [this]() -> std::string {
                if (http_server_.is_running()) {
                    return idasql::format_http_status(http_server_.port(), true);
                } else {
                    return "HTTP server not running\nUse '.http start' to start\n";
                }
            };

            cli_->session().callbacks().http_start = [this]() -> std::string {
                return start_http_server();
            };

            cli_->session().callbacks().http_stop = [this]() -> std::string {
                if (http_server_.is_running()) {
                    http_server_.stop();
                    return "HTTP server stopped";
                } else {
                    return "HTTP server not running";
                }
            };
#endif

            // Auto-install CLI so it's available immediately
            // User can still toggle it off with run(23) if desired
            cli_->install();
        } else {
            msg("IDASQL: Failed to init engine: %s\n", engine_->error().c_str());
        }
    }

#ifdef IDASQL_HAS_AI_AGENT
    std::string start_mcp_server()
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

        // Start MCP server with random port (port=0)
        int port = mcp_server_.start(0, sql_executor, ask_cb);
        if (port <= 0) {
            mcp_agent_.reset();
            return "Error: Failed to start MCP server";
        }

        return idasql::format_mcp_info(port, true);
    }
#endif

#ifdef IDASQL_HAS_HTTP
    std::string start_http_server()
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

        // Start HTTP server with random port (port=0), no queue (plugin mode)
        int port = http_server_.start(0, sql_cb);
        if (port <= 0) {
            return "Error: Failed to start HTTP server";
        }

        return idasql::format_http_info(port);
    }
#endif

    ~idasql_plugmod_t()
    {
#ifdef IDASQL_HAS_AI_AGENT
        // Stop MCP server before destroying engine
        if (mcp_server_.is_running()) {
            mcp_server_.stop();
        }
        mcp_agent_.reset();
#endif
#ifdef IDASQL_HAS_HTTP
        // Stop HTTP server before destroying engine
        if (http_server_.is_running()) {
            http_server_.stop();
        }
#endif
        if (cli_) cli_->uninstall();
        server_.stop();
        engine_.reset();
        msg("IDASQL: Plugin terminated\n");
    }

    virtual bool idaapi run(size_t arg) override
    {
        using namespace idasql;

        if (!engine_ || !engine_->is_valid()) {
            msg("IDASQL: Query engine not available\n");
            return false;
        }

        // Decode port from upper 16 bits (0 = use default)
        int port = static_cast<int>((arg >> PLUGIN_ARG_PORT_SHIFT) & PLUGIN_ARG_CMD_MASK);
        if (port == 0) port = PLUGIN_DEFAULT_PORT;
        size_t cmd = arg & PLUGIN_ARG_CMD_MASK;

        switch (cmd) {
            case PLUGIN_ARG_GUI_TOGGLE:  // Toggle server (GUI mode with execute_sync)
                if (server_.is_running()) {
                    server_.stop();
                    msg("IDASQL: Server stopped\n");
                } else {
                    server_.set_poll_mode(false);
                    server_.start(port);
                }
                return true;

            case PLUGIN_ARG_START_POLL_MODE:  // Start server in poll mode (idalib)
                if (!server_.is_running()) {
                    server_.set_poll_mode(true);
                    server_.start(port);
                }
                return true;

            case PLUGIN_ARG_STOP_SERVER:  // Stop server
                if (server_.is_running()) {
                    server_.stop();
                    msg("IDASQL: Server stopped\n");
                }
                return true;

            case PLUGIN_ARG_TOGGLE_CLI:  // Toggle CLI
                if (cli_) {
                    if (cli_->is_installed()) {
                        cli_->uninstall();
                    } else {
                        cli_->install();
                    }
                }
                return true;

            case PLUGIN_ARG_POLL_ONE:  // Poll: execute one pending query
                return server_.poll_one();

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
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "IDASQL - SQL interface for IDA database",
    "IDASQL Plugin\n"
    "\n"
    "run(0):  Toggle remote server on/off (GUI mode)\n"
    "run(21): Start server in poll mode (idalib)\n"
    "run(22): Stop server\n"
    "run(23): Toggle CLI (command line interface)\n"
    "run(24): Poll pending query (idalib)\n"
    "\n"
    "Port encoding: arg = (port << 16) | cmd\n"
    "\n"
    "Remote: idasql --remote localhost:13337\n"
    "CLI: Type SQL or natural language in IDA's command line",
    "IDASQL",
    "Ctrl-Shift-Q"
};
