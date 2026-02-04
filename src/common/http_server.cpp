#include "http_server.hpp"

#ifdef IDASQL_HAS_HTTP

// Windows SDK compatibility for cpp-httplib
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include <httplib.h>
#include <xsql/json.hpp>

#include <chrono>
#include <random>
#include <sstream>
#include <thread>

namespace idasql {

// Help text served at /help endpoint
static const char* HTTP_HELP_TEXT = R"(IDASQL HTTP REST API
====================

SQL interface for IDA Pro databases via HTTP.

Endpoints:
  GET  /         - Welcome message
  GET  /help     - This documentation
  POST /query    - Execute SQL (body = raw SQL, response = JSON)
  GET  /status   - Server health check
  GET  /health   - Alias for /status
  POST /shutdown - Stop server

Response Format:
  Success: {"success": true, "columns": [...], "rows": [[...]], "row_count": N}
  Error:   {"success": false, "error": "message"}

Example:
  curl http://localhost:<port>/help
  curl -X POST http://localhost:<port>/query -d "SELECT name FROM funcs LIMIT 5"
)";

class IDAHTTPServer::Impl {
public:
    httplib::Server svr;
    std::thread server_thread;
};

IDAHTTPServer::IDAHTTPServer() = default;

IDAHTTPServer::~IDAHTTPServer() {
    stop();
}

std::string IDAHTTPServer::queue_and_wait(const std::string& sql) {
    if (!running_.load()) {
        return xsql::json{{"success", false}, {"error", "Server not running"}}.dump();
    }

    auto cmd = std::make_shared<HTTPPendingCommand>();
    cmd->sql = sql;
    cmd->completed = false;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        pending_commands_.push(cmd);
    }
    queue_cv_.notify_one();

    // Wait for completion with timeout
    {
        std::unique_lock<std::mutex> lock(cmd->done_mutex);
        int wait_count = 0;
        while (!cmd->completed && wait_count < 600) {  // 60 seconds max
            cmd->done_cv.wait_for(lock, std::chrono::milliseconds(100));
            wait_count++;
        }
        if (!cmd->completed) {
            return xsql::json{{"success", false}, {"error", "Request timed out"}}.dump();
        }
    }

    return cmd->result;
}

int IDAHTTPServer::start(int port, HTTPQueryCallback query_cb,
                         const std::string& bind_addr, bool use_queue) {
    if (running_.load()) {
        return port_;
    }

    query_cb_ = query_cb;
    bind_addr_ = bind_addr;
    use_queue_.store(use_queue);

    // If port is 0, pick a random port in the 8100-8199 range
    if (port == 0) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(8100, 8199);
        port = dis(gen);
    }

    impl_ = std::make_unique<Impl>();

    // Set up routes
    auto& svr = impl_->svr;

    svr.Get("/", [port](const httplib::Request&, httplib::Response& res) {
        std::string welcome = "IDASQL HTTP Server (REPL)\n\nEndpoints:\n"
            "  GET  /help     - API documentation\n"
            "  POST /query    - Execute SQL query\n"
            "  GET  /status   - Health check\n"
            "  POST /shutdown - Stop server\n\n"
            "Example: curl -X POST http://localhost:" + std::to_string(port) +
            "/query -d \"SELECT name FROM funcs LIMIT 5\"\n";
        res.set_content(welcome, "text/plain");
    });

    svr.Get("/help", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(HTTP_HELP_TEXT, "text/plain");
    });

    // POST /query - Execute SQL
    svr.Post("/query", [this](const httplib::Request& req, httplib::Response& res) {
        if (req.body.empty()) {
            res.status = 400;
            res.set_content(
                xsql::json{{"success", false}, {"error", "Empty query"}}.dump(),
                "application/json");
            return;
        }

        std::string result;
        if (use_queue_.load()) {
            result = queue_and_wait(req.body);
        } else {
            if (!query_cb_) {
                res.status = 500;
                res.set_content(
                    xsql::json{{"success", false}, {"error", "Query callback not set"}}.dump(),
                    "application/json");
                return;
            }
            result = query_cb_(req.body);
        }
        res.set_content(result, "application/json");
    });

    // GET /status
    svr.Get("/status", [this](const httplib::Request&, httplib::Response& res) {
        xsql::json status = {
            {"success", true},
            {"status", "ok"},
            {"tool", "idasql"},
            {"mode", "repl"}
        };
        res.set_content(status.dump(), "application/json");
    });

    // GET /health (alias)
    svr.Get("/health", [this](const httplib::Request&, httplib::Response& res) {
        xsql::json status = {
            {"success", true},
            {"status", "ok"},
            {"tool", "idasql"},
            {"mode", "repl"}
        };
        res.set_content(status.dump(), "application/json");
    });

    // POST /shutdown
    svr.Post("/shutdown", [this](const httplib::Request&, httplib::Response& res) {
        res.set_content(
            xsql::json{{"success", true}, {"message", "Shutting down"}}.dump(),
            "application/json");
        // Schedule stop after response is sent
        std::thread([this] {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            stop();
        }).detach();
    });

    // Start server in background thread
    port_ = port;
    impl_->server_thread = std::thread([this, port]() {
        impl_->svr.listen(bind_addr_.c_str(), port);
    });

    // Wait for server to start listening
    int attempts = 0;
    while (!impl_->svr.is_running() && attempts < 50) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        attempts++;
    }

    if (!impl_->svr.is_running()) {
        impl_->server_thread.detach();
        impl_.reset();
        return -1;
    }

    running_.store(true);
    return port_;
}

void IDAHTTPServer::set_interrupt_check(std::function<bool()> check) {
    interrupt_check_ = check;
}

void IDAHTTPServer::run_until_stopped() {
    while (running_.load()) {
        if (interrupt_check_ && interrupt_check_()) {
            stop();
            break;
        }

        std::shared_ptr<HTTPPendingCommand> cmd;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (queue_cv_.wait_for(lock, std::chrono::milliseconds(100),
                                   [this]() { return !pending_commands_.empty() || !running_.load(); })) {
                if (!pending_commands_.empty()) {
                    cmd = pending_commands_.front();
                    pending_commands_.pop();
                }
            }
        }

        if (cmd) {
            try {
                if (query_cb_) {
                    cmd->result = query_cb_(cmd->sql);
                } else {
                    cmd->result = xsql::json{{"success", false}, {"error", "No query handler"}}.dump();
                }
            } catch (const std::exception& e) {
                cmd->result = xsql::json{{"success", false}, {"error", e.what()}}.dump();
            }

            {
                std::lock_guard<std::mutex> lock(cmd->done_mutex);
                cmd->completed = true;
            }
            cmd->done_cv.notify_one();
        }
    }
}

void IDAHTTPServer::stop() {
    running_.store(false);
    queue_cv_.notify_all();
    complete_pending_commands(
        xsql::json{{"success", false}, {"error", "HTTP server stopped"}}.dump());

    if (impl_) {
        if (impl_->svr.is_running()) {
            impl_->svr.stop();
        }
        if (impl_->server_thread.joinable()) {
            impl_->server_thread.join();
        }
    }

    impl_.reset();
}

void IDAHTTPServer::complete_pending_commands(const std::string& result) {
    std::queue<std::shared_ptr<HTTPPendingCommand>> pending;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        std::swap(pending, pending_commands_);
    }

    while (!pending.empty()) {
        auto cmd = pending.front();
        pending.pop();
        if (!cmd) continue;

        {
            std::lock_guard<std::mutex> lock(cmd->done_mutex);
            if (!cmd->completed) {
                cmd->result = result;
                cmd->completed = true;
            }
        }
        cmd->done_cv.notify_one();
    }
}

std::string IDAHTTPServer::url() const {
    std::ostringstream ss;
    ss << "http://" << bind_addr_ << ":" << port_;
    return ss.str();
}

std::string format_http_info(int port) {
    std::ostringstream ss;
    ss << "HTTP server started on port " << port << "\n";
    ss << "URL: http://127.0.0.1:" << port << "\n\n";
    ss << "Endpoints:\n";
    ss << "  GET  /help     - API documentation\n";
    ss << "  POST /query    - Execute SQL query\n";
    ss << "  GET  /status   - Health check\n";
    ss << "  POST /shutdown - Stop server\n\n";
    ss << "Example:\n";
    ss << "  curl -X POST http://127.0.0.1:" << port << "/query -d \"SELECT name FROM funcs LIMIT 5\"\n\n";
    ss << "Press Ctrl+C to stop and return to REPL.\n";
    return ss.str();
}

std::string format_http_status(int port, bool running) {
    std::ostringstream ss;
    if (running) {
        ss << "HTTP server running on port " << port << "\n";
        ss << "URL: http://127.0.0.1:" << port << "\n";
    } else {
        ss << "HTTP server not running\n";
        ss << "Use '.http start' to start\n";
    }
    return ss.str();
}

} // namespace idasql

#endif // IDASQL_HAS_HTTP
