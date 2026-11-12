// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "control_channel.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <random>
#include <sstream>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace idasql {
namespace control {

namespace {

using json = xsql::json;

fs::path to_path(const std::string& s) {
#ifdef _WIN32
    if (s.empty()) return fs::path();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return fs::path(w);
#else
    return fs::path(s);
#endif
}

std::string to_utf8(const fs::path& p) {
#ifdef _WIN32
    const std::wstring& w = p.native();
    if (w.empty()) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
#else
    return p.native();
#endif
}

std::string random_request_id() {
    static std::mutex m;
    static std::mt19937 rng{std::random_device{}()};
    std::lock_guard<std::mutex> lock(m);
    const uint32_t v = rng() & 0xffffffu;
    static const char* hex = "0123456789abcdef";
    std::string out(6, '0');
    for (int i = 5, x = static_cast<int>(v); i >= 0; --i, x >>= 4) out[static_cast<size_t>(i)] = hex[x & 0xf];
    return out;
}

bool valid_request_id(const std::string& id) {
    if (id.size() != 6) return false;
    return std::all_of(id.begin(), id.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

fs::path request_file(const fs::path& dir, const std::string& channel, const std::string& req) {
    return dir / (channel + "-" + req + ".request.json");
}

fs::path reply_file(const fs::path& dir, const std::string& channel, const std::string& req) {
    return dir / (channel + "-" + req + ".reply.json");
}

bool write_atomic(const fs::path& file, const std::string& text) {
    fs::path tmp = file;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out << text;
        if (!out) return false;
    }
    std::error_code ec;
    fs::rename(tmp, file, ec);
    if (ec) {
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

bool read_file(const fs::path& file, std::string& out) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

std::vector<fs::path> channel_files(const fs::path& dir, const std::string& channel, const std::string& kind) {
    std::vector<fs::path> out;
    std::error_code ec;
    const std::string prefix = channel + "-";
    const std::string suffix = "." + kind + ".json";
    for (const auto& e : fs::directory_iterator(dir, ec)) {
        const std::string name = to_utf8(e.path().filename());
        if (name.size() == prefix.size() + 6 + suffix.size() && name.compare(0, prefix.size(), prefix) == 0 &&
            name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0)
            out.push_back(e.path());
    }
    std::sort(out.begin(), out.end());
    return out;
}

}

std::string normalise_db_path(const std::string& path) {
    if (path.empty()) return std::string();
    std::error_code ec;
    fs::path p = fs::absolute(to_path(path), ec);
    if (ec) p = to_path(path);
    const fs::path canonical = fs::weakly_canonical(p, ec);
    if (!ec) p = canonical;
    p = p.lexically_normal();
#ifdef _WIN32
    std::wstring w = p.native();
    std::replace(w.begin(), w.end(), L'/', L'\\');
    if (!w.empty()) {
        std::wstring lower(w.size(), L'\0');
        const int n = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, w.data(), static_cast<int>(w.size()),
                                    lower.data(), static_cast<int>(lower.size()), nullptr, nullptr, 0);
        if (n > 0) {
            lower.resize(static_cast<size_t>(n));
            w = lower;
        }
    }
    return to_utf8(fs::path(w));
#else
    return to_utf8(p);
#endif
}

uint32_t djb2(const std::string& s) {
    uint32_t h = 5381;
    for (unsigned char c : s) h = ((h << 5) + h) + c;
    return h;
}

std::string channel_id(const std::string& db_path) {
    static const char* hex = "0123456789abcdef";
    const uint32_t h = djb2(normalise_db_path(db_path));
    std::string out(8, '0');
    for (int i = 7, shift = 0; i >= 0; --i, shift += 4) out[static_cast<size_t>(i)] = hex[(h >> shift) & 0xf];
    return out;
}

std::string bell_name(const std::string& channel) { return "idasql_ctl_" + channel; }

std::string reply_bell_name(const std::string& channel, const std::string& request_id) {
    return "idasql_ctl_" + channel + "_" + request_id;
}

fs::path control_dir() { return os::config_dir() / "ctl"; }

struct Server::State {
    Handler handler;
    fs::path dir;
    std::string channel;
    std::mutex m;
    std::condition_variable cv;
    int active = 0;
};

const std::string& Server::channel() const {
    static const std::string none;
    return state_ ? state_->channel : none;
}

bool Server::start(const std::string& db_path, Handler handler, const fs::path& dir, std::string* error) {
    stop();
    auto st = std::make_shared<State>();
    st->handler = std::move(handler);
    st->dir = dir;
    st->channel = channel_id(db_path);
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        if (error) *error = "cannot create " + to_utf8(dir) + ": " + ec.message();
        return false;
    }
    for (const auto& f : channel_files(dir, st->channel, "request")) fs::remove(f, ec);
    for (const auto& f : channel_files(dir, st->channel, "reply")) fs::remove(f, ec);

    std::weak_ptr<State> weak = st;
    const bool ok = waiter_.start(bell_name(st->channel), [weak] {
        const std::shared_ptr<State> s = weak.lock();
        if (!s) return;
        for (const auto& file : channel_files(s->dir, s->channel, "request")) {
            std::string text;
            const bool read = read_file(file, text);
            std::error_code rm;
            fs::remove(file, rm);
            if (!read) continue;
            const json j = json::parse(text, nullptr, false);
            if (!j.is_object() || !j.contains("id") || !j["id"].is_string() || !j.contains("action") ||
                !j["action"].is_string())
                continue;
            Request req;
            req.id = j["id"].get<std::string>();
            if (!valid_request_id(req.id)) continue;
            req.action = j["action"].get<std::string>();
            if (j.contains("args") && j["args"].is_object()) req.args = j["args"];
            {
                std::lock_guard<std::mutex> lock(s->m);
                ++s->active;
            }
            std::thread([s, req] {
                Reply reply;
                try {
                    reply = s->handler ? s->handler(req) : Reply{"unknown_action", json::object()};
                } catch (const std::exception& e) {
                    reply = Reply{"error", json{{"message", e.what()}}};
                } catch (...) {
                    reply = Reply{"error", json{{"message", "unknown exception"}}};
                }
                const json out = {{"id", req.id}, {"outcome", reply.outcome}, {"data", reply.data}};
                const fs::path file = reply_file(s->dir, s->channel, req.id);
                if (write_atomic(file, out.dump())) {
                    os::NamedSemaphore bell;
                    if (bell.open(reply_bell_name(s->channel, req.id))) {
                        bell.post();
                    } else {
                        std::error_code gone;
                        fs::remove(file, gone);
                    }
                }
                {
                    std::lock_guard<std::mutex> lock(s->m);
                    --s->active;
                }
                s->cv.notify_all();
                if (reply.after_reply) reply.after_reply();
            }).detach();
        }
    });
    if (!ok) {
        if (error) *error = "cannot create the semaphore " + bell_name(st->channel);
        return false;
    }
    state_ = st;
    return true;
}

bool Server::stop(int grace_ms) {
    waiter_.stop();
    if (!state_) return true;
    bool finished = false;
    {
        std::unique_lock<std::mutex> lock(state_->m);
        finished = state_->cv.wait_for(lock, std::chrono::milliseconds(grace_ms < 0 ? 0 : grace_ms),
                                       [this] { return state_->active == 0; });
    }
    state_.reset();
    return finished;
}

SendResult send(const std::string& db_path, const std::string& action, const json& args, int timeout_ms,
                const fs::path& dir) {
    SendResult r;
    const std::string channel = channel_id(db_path);
    os::NamedSemaphore bell;
    if (!bell.open(bell_name(channel))) {
        r.status = SendStatus::no_server;
        return r;
    }
    const std::string req = random_request_id();
    os::NamedSemaphore reply_bell;
    if (!reply_bell.create(reply_bell_name(channel, req))) {
        r.error = "cannot create the reply semaphore";
        return r;
    }
    const json body = {{"id", req}, {"action", action}, {"args", args.is_object() ? args : json::object()}};
    const fs::path req_file = request_file(dir, channel, req);
    if (!write_atomic(req_file, body.dump())) {
        r.error = "cannot write " + to_utf8(req_file);
        return r;
    }
    bell.post();
    const os::WaitResult w = reply_bell.wait(timeout_ms);
    const fs::path rep_file = reply_file(dir, channel, req);
    std::error_code ec;
    if (w != os::WaitResult::signaled) {
        fs::remove(req_file, ec);
        r.status = w == os::WaitResult::timeout ? SendStatus::timeout : SendStatus::error;
        if (r.status == SendStatus::error) r.error = "waiting for the reply failed";
        return r;
    }
    std::string text;
    const bool read = read_file(rep_file, text);
    fs::remove(rep_file, ec);
    const json j = read ? json::parse(text, nullptr, false) : json();
    if (!j.is_object() || j.value("id", std::string()) != req) {
        r.error = "malformed reply";
        return r;
    }
    r.status = SendStatus::ok;
    r.reply.outcome = j.value("outcome", std::string());
    if (j.contains("data")) r.reply.data = j["data"];
    return r;
}

bool file_exists(const std::string& utf8_path) {
    std::error_code ec;
    return fs::exists(to_path(utf8_path), ec);
}

bool is_armed(const std::string& db_path) {
    os::NamedSemaphore bell;
    return bell.open(bell_name(channel_id(db_path)));
}

}
}
