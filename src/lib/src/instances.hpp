// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace idasql {
namespace instances {

struct Record {
    uint64_t pid = 0;
    std::string host;
    std::string ida_version;
    std::string idasql_version;
    std::string idb_path;
    std::string http;
    bool http_auth = false;
    std::string mcp;
    bool mcp_auth = false;
    bool rescue = false;
    bool remote = false;
    std::string started;
};

struct Entry {
    Record record;
    bool idasql = false;
    bool ipc = false;
    bool responsive = true;
    bool self = false;
};

std::filesystem::path registry_dir();

void set_registry_dir_override(std::optional<std::filesystem::path> dir);

std::string to_json(const Record& r);
std::optional<Record> from_json(const std::string& text);

std::vector<Record> read_registry(const std::filesystem::path& dir);

struct ListOptions {
    std::filesystem::path dir;
    bool use_ipc = true;
    int ipc_io_timeout_ms = 10000;
    uint64_t skip_ipc_pid = 0;
    std::vector<uint64_t> only_pids;
};

std::vector<Entry> list(const ListOptions& options = {});

class Registration {
public:
    Registration() = default;
    Registration(const Registration&) = delete;
    Registration& operator=(const Registration&) = delete;
    ~Registration() { stop(); }

    bool start(const Record& base, const std::filesystem::path& dir = {});
    void set_idb(const std::string& idb_path);
    void set_http(const std::string& url, bool auth);
    void set_mcp(const std::string& url, bool auth);
    void set_rescue(bool armed);
    void set_remote(bool on);
    void stop();
    bool active() const;
    Record record() const;

private:
    void write_locked();

    mutable std::mutex m_;
    Record rec_;
    std::filesystem::path file_;
    bool active_ = false;
};

Registration& self();

std::string http_url(const std::string& bind_addr, int port);
std::string mcp_url(const std::string& bind_addr, int port);

int run_cli(const std::vector<std::string>& args);

}
}
