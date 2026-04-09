// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "mcp_server.hpp"
#include <idasql/runtime_settings.hpp>

#include <fastmcpp/mcp/handler.hpp>
#include <fastmcpp/server/sse_server.hpp>
#include <fastmcpp/tools/manager.hpp>
#include <fastmcpp/tools/tool.hpp>
#include <nlohmann/json.hpp>
#include <xsql/thinclient/clipboard.hpp>

#include <algorithm>
#include <chrono>
#include <random>
#include <sstream>
#include <unordered_map>

namespace idasql {

using Json = nlohmann::json;

class IDAMCPServer::Impl {
public:
    fastmcpp::tools::ToolManager tool_manager;
    std::unique_ptr<fastmcpp::server::SseServerWrapper> server;
};

IDAMCPServer::IDAMCPServer() = default;

IDAMCPServer::~IDAMCPServer() {
    stop();
}

MCPQueueResult IDAMCPServer::queue_and_wait(MCPPendingCommand::Type type, const std::string& input) {
    if (!running_.load()) {
        return {false, "Error: MCP server is not running"};
    }

    auto cmd = std::make_shared<MCPPendingCommand>();
    cmd->type = type;
    cmd->input = input;
    cmd->completed = false;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        const size_t max_queue = idasql::runtime_settings().max_queue();
        if (max_queue > 0 && pending_commands_.size() >= max_queue) {
            return {false, "Error: MCP queue is full (raise PRAGMA idasql.max_queue)"};
        }
        pending_commands_.push_back(cmd);
    }
    queue_cv_.notify_one();

    {
        std::unique_lock<std::mutex> lock(cmd->done_mutex);
        const int timeout_ms = idasql::runtime_settings().queue_admission_timeout_ms();
        if (timeout_ms <= 0) {
            while (!cmd->completed && running_.load()) {
                cmd->done_cv.wait_for(lock, std::chrono::milliseconds(100));
            }
        } else {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
            while (!cmd->completed && running_.load()) {
                if (cmd->started) {
                    cmd->done_cv.wait_for(
                        lock,
                        std::chrono::milliseconds(100),
                        [&]() { return cmd->completed || !running_.load(); });
                    continue;
                }

                if (cmd->done_cv.wait_until(
                        lock,
                        deadline,
                        [&]() { return cmd->completed || cmd->started || !running_.load(); })) {
                    continue;
                }

                // Timed out before command admission: mark canceled and remove from pending queue.
                if (!cmd->completed && !cmd->started) {
                    cmd->canceled = true;
                }
                lock.unlock();
                {
                    std::lock_guard<std::mutex> qlock(queue_mutex_);
                    auto it = std::find(pending_commands_.begin(), pending_commands_.end(), cmd);
                    if (it != pending_commands_.end()) {
                        pending_commands_.erase(it);
                    }
                }
                return {false, "Error: MCP request timed out in queue (raise PRAGMA idasql.queue_admission_timeout_ms)"};
            }
        }
    }

    if (!cmd->completed) {
        if (!running_.load()) {
            return {false, "Error: MCP server stopped"};
        }
        return {false, "Error: MCP request timed out in queue (raise PRAGMA idasql.queue_admission_timeout_ms)"};
    }

    // Convention: query callbacks return "Error: ..." on failure
    bool ok = !cmd->result.starts_with("Error: ");
    return {ok, cmd->result};
}

int IDAMCPServer::start(int port, QueryCallback query_cb,
                        const std::string& bind_addr, bool use_queue) {
    if (running_.load()) {
        return port_;
    }

    query_cb_ = query_cb;
    bind_addr_ = bind_addr;
    use_queue_.store(use_queue);

    if (port == 0) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(9000, 9999);
        port = dis(gen);
    }

    impl_ = std::make_unique<Impl>();

    Json query_input_schema = {
        {"type", "object"},
        {"properties", {
            {"query", {
                {"type", "string"},
                {"description", "SQL query to execute against the IDA database"}
            }}
        }},
        {"required", Json::array({"query"})}
    };

    // No outputSchema — the tool returns text content, not structuredContent.
    // Declaring an outputSchema without returning structuredContent violates
    // the MCP spec and causes the official Python SDK to reject responses.
    fastmcpp::tools::Tool sql_query_tool{
        "idasql_query",
        query_input_schema,
        Json(),
        [this](const Json& args) -> Json {
            std::string query = args.value("query", "");
            if (query.empty()) {
                return Json{
                    {"content", Json::array({
                        Json{{"type", "text"}, {"text", "Error: missing query"}}
                    })},
                    {"isError", true}
                };
            }

            std::string result;
            bool success = true;

            if (use_queue_.load()) {
                auto qr = queue_and_wait(MCPPendingCommand::Type::Query, query);
                result = qr.payload;
                success = qr.success;
            } else {
                if (!query_cb_) {
                    return Json{
                        {"content", Json::array({
                            Json{{"type", "text"}, {"text", "Error: query callback not set"}}
                        })},
                        {"isError", true}
                    };
                }
                result = query_cb_(query);
                // Convention: query callbacks return "Error: ..." on failure
                if (result.starts_with("Error: ")) {
                    success = false;
                }
            }

            return Json{
                {"content", Json::array({
                    Json{{"type", "text"}, {"text", result}}
                })},
                {"isError", !success}
            };
        }
    };
    sql_query_tool.set_description("Execute a SQL query against the IDA database and return results");
    impl_->tool_manager.register_tool(sql_query_tool);

    std::unordered_map<std::string, std::string> descriptions = {
        {"idasql_query", "Execute a SQL query against the IDA database and return results"}
    };

    auto handler = fastmcpp::mcp::make_mcp_handler(
        "idasql",
        "1.0.0",
        impl_->tool_manager,
        descriptions
    );

    impl_->server = std::make_unique<fastmcpp::server::SseServerWrapper>(
        handler,
        bind_addr_,
        port,
        "/sse",
        "/messages"
    );

    if (!impl_->server->start()) {
        impl_.reset();
        return -1;
    }

    port_ = impl_->server->port();
    running_.store(true);
    return port_;
}

void IDAMCPServer::set_interrupt_check(std::function<bool()> check) {
    interrupt_check_ = check;
}

void IDAMCPServer::run_until_stopped() {
    while (running_.load()) {
        if (interrupt_check_ && interrupt_check_()) {
            stop();
            break;
        }

        std::shared_ptr<MCPPendingCommand> cmd;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (queue_cv_.wait_for(
                    lock,
                    std::chrono::milliseconds(100),
                    [this]() { return !pending_commands_.empty() || !running_.load(); })) {
                if (!pending_commands_.empty()) {
                    cmd = pending_commands_.front();
                    pending_commands_.pop_front();
                }
            }
        }

        if (!cmd) {
            continue;
        }

        bool should_execute = false;
        {
            std::lock_guard<std::mutex> lock(cmd->done_mutex);
            if (!cmd->completed && !cmd->canceled) {
                cmd->started = true;
                should_execute = true;
            } else if (!cmd->completed && cmd->canceled) {
                cmd->completed = true;
            }
        }

        if (!should_execute) {
            cmd->done_cv.notify_one();
            continue;
        }

        std::string result;
        try {
            if (cmd->type == MCPPendingCommand::Type::Query && query_cb_) {
                result = query_cb_(cmd->input);
            } else {
                result = "Error: No handler for command type";
            }
        } catch (const std::exception& e) {
            result = std::string("Error: ") + e.what();
        }

        {
            std::lock_guard<std::mutex> lock(cmd->done_mutex);
            if (!cmd->completed) {
                cmd->result = std::move(result);
                cmd->completed = true;
            }
        }
        cmd->done_cv.notify_one();
    }
}

void IDAMCPServer::stop() {
    running_.store(false);
    queue_cv_.notify_all();
    complete_pending_commands("Error: MCP server stopped");

    if (impl_ && impl_->server) {
        impl_->server->stop();
    }

    impl_.reset();
}

void IDAMCPServer::complete_pending_commands(const std::string& result) {
    std::deque<std::shared_ptr<MCPPendingCommand>> pending;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        std::swap(pending, pending_commands_);
    }

    while (!pending.empty()) {
        auto cmd = pending.front();
        pending.pop_front();
        if (!cmd) {
            continue;
        }

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

std::string IDAMCPServer::url() const {
    std::ostringstream ss;
    ss << "http://" << xsql::thinclient::format_url_host(bind_addr_) << ":" << port_;
    return ss.str();
}

std::string format_mcp_info(int port) {
    return format_mcp_info(port, "127.0.0.1");
}

std::string format_mcp_info(int port, const std::string& bind_addr) {
    const std::string rendered_host = xsql::thinclient::format_url_host(bind_addr);
    return "IDASQL MCP server: http://" + rendered_host + ":" + std::to_string(port) + "/sse\n";
}

std::string format_mcp_status(int port, bool running) {
    return format_mcp_status(port, running, "127.0.0.1");
}

std::string format_mcp_status(int port, bool running, const std::string& bind_addr) {
    std::ostringstream ss;
    const std::string rendered_host = xsql::thinclient::format_url_host(bind_addr);
    if (running) {
        ss << "MCP server running on port " << port << "\n";
        ss << "SSE endpoint: http://" << rendered_host << ":" << port << "/sse\n";
    } else {
        ss << "MCP server not running\n";
        ss << "Use '.mcp start' to start\n";
    }
    return ss.str();
}

} // namespace idasql
