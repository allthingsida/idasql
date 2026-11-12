// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "os.hpp"

#include <xsql/json.hpp>

#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace idasql {
namespace control {

std::string normalise_db_path(const std::string& path);

uint32_t djb2(const std::string& s);

std::string channel_id(const std::string& db_path);

std::string bell_name(const std::string& channel);
std::string reply_bell_name(const std::string& channel, const std::string& request_id);

std::filesystem::path control_dir();

struct Request {
    std::string id;
    std::string action;
    xsql::json args = xsql::json::object();
};

struct Reply {
    std::string outcome;
    xsql::json data = xsql::json::object();
    std::function<void()> after_reply;
};

using Handler = std::function<Reply(const Request&)>;

class Server {
public:
    Server() = default;
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    ~Server() { stop(); }

    bool start(const std::string& db_path, Handler handler, const std::filesystem::path& dir,
               std::string* error = nullptr);
    bool start(const std::string& db_path, Handler handler, std::string* error = nullptr) {
        return start(db_path, std::move(handler), control_dir(), error);
    }
    bool stop(int grace_ms = 2000);
    bool running() const { return waiter_.running(); }
    const std::string& channel() const;

private:
    struct State;
    std::shared_ptr<State> state_;
    os::SemaphoreWaiter waiter_;
};

enum class SendStatus {
    ok,
    no_server,
    timeout,
    error,
};

struct SendResult {
    SendStatus status = SendStatus::error;
    Reply reply;
    std::string error;
};

SendResult send(const std::string& db_path, const std::string& action, const xsql::json& args, int timeout_ms,
                const std::filesystem::path& dir);
inline SendResult send(const std::string& db_path, const std::string& action, const xsql::json& args,
                       int timeout_ms) {
    return send(db_path, action, args, timeout_ms, control_dir());
}

bool is_armed(const std::string& db_path);

bool file_exists(const std::string& utf8_path);

}
}
