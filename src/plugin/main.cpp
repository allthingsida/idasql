/**
 * idasql_plugin - IDA plugin that hosts an IDASQL server
 *
 * GUI mode:   Press Ctrl-Shift-Q to toggle server on/off (uses execute_sync)
 * idalib mode: Driver calls run(1) to start, run(4) to poll, run(2) to stop
 *
 * Connect with: idasql --remote localhost:13337 -q "SELECT * FROM funcs"
 *
 * run() arg codes:
 *   0 = Toggle server (GUI mode, uses execute_sync)
 *   1 = Start server in poll mode (for idalib)
 *   2 = Stop server
 *   4 = Poll: execute one pending query (for idalib pump loop)
 */

// Standard library includes BEFORE IDA headers to avoid conflicts
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

// IDA SDK headers
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

// IDASQL library
#include <idasql/database.hpp>

// Platform-specific socket includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
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

//=============================================================================
// JSON Protocol Helpers
//=============================================================================

namespace {

std::string json_escape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 10);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out += c; break;
        }
    }
    return out;
}

std::string result_to_json(const idasql::QueryResult& result)
{
    std::ostringstream json;
    json << "{";
    json << "\"success\":" << (result.success ? "true" : "false");

    if (result.success) {
        json << ",\"columns\":[";
        for (size_t i = 0; i < result.columns.size(); i++) {
            if (i > 0) json << ",";
            json << "\"" << json_escape(result.columns[i]) << "\"";
        }
        json << "]";

        json << ",\"rows\":[";
        for (size_t r = 0; r < result.rows.size(); r++) {
            if (r > 0) json << ",";
            json << "[";
            for (size_t c = 0; c < result.rows[r].size(); c++) {
                if (c > 0) json << ",";
                json << "\"" << json_escape(result.rows[r][c]) << "\"";
            }
            json << "]";
        }
        json << "]";
        json << ",\"row_count\":" << result.row_count();
    } else {
        json << ",\"error\":\"" << json_escape(result.error) << "\"";
    }

    json << "}";
    return json.str();
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
        std::string request;
        while (running_ && recv_message(client, request)) {
            std::string sql = extract_sql(request);
            if (sql.empty()) {
                send_message(client, "{\"success\":false,\"error\":\"Invalid request: missing sql field\"}");
                continue;
            }

            if (!auth_token_.empty()) {
                std::string token = extract_token(request);
                if (token != auth_token_) {
                    send_message(client, "{\"success\":false,\"error\":\"Unauthorized\"}");
                    continue;
                }
            }

            auto result = execute_query(sql);
            if (!send_message(client, result_to_json(result))) break;
        }
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
            addr.sin_addr.s_addr = inet_addr("127.0.0.1");
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

    idasql_plugmod_t()
    {
        engine_ = std::make_unique<idasql::QueryEngine>();
        if (engine_->is_valid()) {
            msg("IDASQL: Query engine initialized\n");
            server_.set_engine(engine_.get());

            if (const char* tok = std::getenv("IDASQL_TOKEN")) {
                if (*tok) {
                    server_.set_auth_token(tok);
                }
            }

            // Setup execute_sync callback for GUI mode
            server_.set_query_func([this](const std::string& sql) {
                query_request_t req(engine_.get(), sql);
                execute_sync(req, MFF_READ);
                return std::move(req.result);
            });
        } else {
            msg("IDASQL: Failed to init engine: %s\n", engine_->error().c_str());
        }
    }

    ~idasql_plugmod_t()
    {
        server_.stop();
        engine_.reset();
        msg("IDASQL: Plugin terminated\n");
    }

    virtual bool idaapi run(size_t arg) override
    {
        if (!engine_ || !engine_->is_valid()) {
            msg("IDASQL: Query engine not available\n");
            return false;
        }

        switch (arg) {
            case 0:  // Toggle (GUI mode with execute_sync)
                if (server_.is_running()) {
                    server_.stop();
                    msg("IDASQL: Server stopped\n");
                } else {
                    server_.set_poll_mode(false);
                    server_.start(13337);
                }
                return true;

            case 1:  // Start in poll mode (idalib)
                if (!server_.is_running()) {
                    server_.set_poll_mode(true);
                    server_.start(13337);
                }
                return true;

            case 2:  // Stop server
                if (server_.is_running()) {
                    server_.stop();
                    msg("IDASQL: Server stopped\n");
                }
                return true;

            case 4:  // Poll: execute one pending query
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
    return new idasql_plugmod_t();
}

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "IDASQL - SQL server for IDA database",
    "IDASQL Plugin\n"
    "GUI: Press hotkey to toggle server on/off.\n"
    "idalib: Use arg codes 1/4/2 for start/poll/stop.\n"
    "Connect with: idasql --remote localhost:13337",
    "IDASQL",
    "Ctrl-Shift-Q"
};
