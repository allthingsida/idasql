// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace idasql {

using QueryCallback = std::function<std::string(const std::string& sql)>;

struct MCPPendingCommand {
    enum class Type { Query };

    Type type = Type::Query;
    std::string input;
    std::string result;
    bool started = false;
    bool canceled = false;
    bool completed = false;
    std::mutex done_mutex;
    std::condition_variable done_cv;
};

struct MCPQueueResult {
    bool success;
    std::string payload;
};

class IDAMCPServer {
public:
    IDAMCPServer();
    ~IDAMCPServer();

    IDAMCPServer(const IDAMCPServer&) = delete;
    IDAMCPServer& operator=(const IDAMCPServer&) = delete;

    int start(int port, QueryCallback query_cb,
              const std::string& bind_addr = "127.0.0.1", bool use_queue = false);

    void run_until_stopped();

    void stop();

    void abandon();

    bool is_running() const { return running_.load(); }

    void set_deep_links_available(bool available) { deep_links_ = available; }

    int port() const { return port_; }

    std::string url() const;

    const std::string& bind_addr() const { return bind_addr_; }

    void set_interrupt_check(std::function<bool()> check);

    MCPQueueResult queue_and_wait(MCPPendingCommand::Type type, const std::string& input);

private:
    std::function<bool()> interrupt_check_;
    std::atomic<bool> running_{false};
    std::atomic<bool> use_queue_{false};
    bool deep_links_ = false;
    std::string bind_addr_{"127.0.0.1"};
    int port_{0};

    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::deque<std::shared_ptr<MCPPendingCommand>> pending_commands_;

    QueryCallback query_cb_;

    class Impl;
    std::unique_ptr<Impl> impl_;

    void complete_pending_commands(const std::string& result);
};

std::string format_mcp_info(int port);
std::string format_mcp_info(int port, const std::string& bind_addr);

std::string format_mcp_status(int port, bool running, const std::string& bind_addr);

std::string mcp_server_instructions(bool deep_links);
std::string mcp_query_tool_description(bool deep_links);

}
