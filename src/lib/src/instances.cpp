// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "instances.hpp"

#include "deep_link.hpp"
#include "os.hpp"
#include "../../common/cli_args.hpp"

#include <xsql/json.hpp>
#include <xsql/thinclient/clipboard.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>

namespace fs = std::filesystem;

namespace idasql {
namespace instances {

namespace {

using json = xsql::json;

std::mutex g_dir_override_m;
std::optional<fs::path> g_dir_override;

std::string utc_now() {
    const std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm u{};
#ifdef _WIN32
    gmtime_s(&u, &t);
#else
    gmtime_r(&t, &u);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &u);
    return buf;
}

std::string idb_name(const std::string& path) {
    if (path.empty()) return {};
    const size_t slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

json entry_json(const Entry& e, const deep_link::IpcOptions& ipc) {
    const Record& r = e.record;
    json j = {{"pid", r.pid},
              {"host", r.host},
              {"ida_version", r.ida_version},
              {"idasql_version", r.idasql_version.empty() ? json(nullptr) : json(r.idasql_version)},
              {"idb_path", r.idb_path},
              {"idb_name", idb_name(r.idb_path)},
              {"http", r.http.empty() ? json(nullptr) : json(r.http)},
              {"http_auth", r.http_auth},
              {"mcp", r.mcp.empty() ? json(nullptr) : json(r.mcp)},
              {"mcp_auth", r.mcp_auth},
              {"rescue", r.rescue},
              {"remote", r.remote},
              {"started", r.started.empty() ? json(nullptr) : json(r.started)},
              {"idasql", e.idasql},
              {"ipc", e.ipc},
              {"responsive", e.responsive}};
    j["analysis_complete"] = nullptr;
    if (e.ipc && e.responsive && !r.idb_path.empty()) {
        std::string err;
        const auto done =
            deep_link::analysis_complete({r.pid, deep_link::endpoint_path(r.pid, ipc)}, err, ipc);
        if (done) j["analysis_complete"] = *done;
    }
    return j;
}

std::string sql_column(const Entry& e) {
    const Record& r = e.record;
    if (!r.http.empty()) return r.http + (r.http_auth ? "*" : "");
    if (!r.mcp.empty()) return "mcp " + r.mcp + (r.mcp_auth ? "*" : "");
    return "-";
}

std::string remote_column(const Entry& e) {
    if (!e.idasql || e.record.host != "gui") return "-";
    return e.record.remote ? "on" : "off";
}

std::string state_column(const Entry& e) {
    if (!e.responsive) return "NOT ANSWERING (hung or busy; to save its work: idasql rescue <db>)";
    return "ok";
}

}

fs::path registry_dir() {
    {
        std::lock_guard<std::mutex> lock(g_dir_override_m);
        if (g_dir_override) return *g_dir_override;
    }
    return os::config_dir() / "instances";
}

void set_registry_dir_override(std::optional<fs::path> dir) {
    std::lock_guard<std::mutex> lock(g_dir_override_m);
    g_dir_override = std::move(dir);
}

std::string to_json(const Record& r) {
    json j = {{"pid", r.pid},           {"host", r.host},         {"ida_version", r.ida_version},
              {"idasql_version", r.idasql_version},               {"idb_path", r.idb_path},
              {"http", r.http},         {"http_auth", r.http_auth}, {"mcp", r.mcp},
              {"mcp_auth", r.mcp_auth}, {"rescue", r.rescue},       {"remote", r.remote},
              {"started", r.started}};
    return j.dump(2);
}

std::optional<Record> from_json(const std::string& text) {
    const json j = json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;
    Record r;
    try {
        r.pid = j.value("pid", uint64_t{0});
        r.host = j.value("host", std::string());
        r.ida_version = j.value("ida_version", std::string());
        r.idasql_version = j.value("idasql_version", std::string());
        r.idb_path = j.value("idb_path", std::string());
        r.http = j.value("http", std::string());
        r.http_auth = j.value("http_auth", false);
        r.mcp = j.value("mcp", std::string());
        r.mcp_auth = j.value("mcp_auth", false);
        r.rescue = j.value("rescue", false);
        r.remote = j.value("remote", false);
        r.started = j.value("started", std::string());
    } catch (...) {
        return std::nullopt;
    }
    if (r.pid == 0) return std::nullopt;
    return r;
}

std::vector<Record> read_registry(const fs::path& dir) {
    std::vector<Record> out;
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) return out;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        const fs::path p = it->path();
        if (p.extension() != ".json") continue;
        std::ifstream in(p, std::ios::binary);
        std::stringstream ss;
        ss << in.rdbuf();
        in.close();
        const auto rec = from_json(ss.str());
        if (!rec || p.stem().string() != std::to_string(rec->pid)) continue;
        if (!os::pid_alive(rec->pid)) {
            std::error_code rm;
            fs::remove(p, rm);
            continue;
        }
        out.push_back(*rec);
    }
    return out;
}

std::vector<Entry> list(const ListOptions& options) {
    std::map<uint64_t, Entry> by_pid;
    const uint64_t me = os::current_pid();
    const auto wanted = [&](uint64_t pid) {
        return options.only_pids.empty() ||
               std::find(options.only_pids.begin(), options.only_pids.end(), pid) != options.only_pids.end();
    };
    for (const Record& r : read_registry(options.dir.empty() ? registry_dir() : options.dir)) {
        if (!wanted(r.pid)) continue;
        Entry& e = by_pid[r.pid];
        e.record = r;
        e.idasql = true;
    }
    if (options.use_ipc) {
        deep_link::IpcOptions ipc = deep_link::effective_ipc_options();
        ipc.io_timeout_ms = std::min(ipc.io_timeout_ms, options.ipc_io_timeout_ms);
        if (options.skip_ipc_pid != 0 || !options.only_pids.empty()) {
            std::vector<uint64_t> pids;
            for (const auto& ep : deep_link::discover(ipc))
                if (ep.pid != options.skip_ipc_pid && wanted(ep.pid)) pids.push_back(ep.pid);
            if (pids.empty()) pids.push_back(0);
            ipc.only_pids = pids;
        }
        for (const auto& inst : deep_link::list_instances(ipc)) {
            if (inst.pid == 0) continue;
            Entry& e = by_pid[inst.pid];
            e.ipc = true;
            e.responsive = inst.responsive;
            e.record.pid = inst.pid;
            if (!e.idasql) e.record.host = "gui";
            if (e.record.ida_version.empty()) e.record.ida_version = inst.version;
            if (inst.responsive && !inst.idb_path.empty()) e.record.idb_path = inst.idb_path;
        }
        if (options.skip_ipc_pid != 0) {
            auto it = by_pid.find(options.skip_ipc_pid);
            if (it != by_pid.end() && it->second.idasql) it->second.ipc = false;
        }
    }
    std::vector<Entry> out;
    for (auto& [pid, e] : by_pid) {
        e.self = pid == me;
        out.push_back(e);
    }
    return out;
}

bool Registration::start(const Record& base, const fs::path& dir) {
    std::lock_guard<std::mutex> lock(m_);
    rec_ = base;
    rec_.pid = os::current_pid();
    rec_.started = utc_now();
    const fs::path d = dir.empty() ? registry_dir() : dir;
    std::error_code ec;
    fs::create_directories(d, ec);
#ifndef _WIN32
    fs::permissions(d, fs::perms::owner_all, fs::perm_options::replace, ec);
#endif
    file_ = d / (std::to_string(rec_.pid) + ".json");
    active_ = true;
    write_locked();
    return fs::exists(file_, ec);
}

void Registration::set_idb(const std::string& idb_path) {
    std::lock_guard<std::mutex> lock(m_);
    rec_.idb_path = idb_path;
    write_locked();
}

void Registration::set_http(const std::string& url, bool auth) {
    std::lock_guard<std::mutex> lock(m_);
    rec_.http = url;
    rec_.http_auth = !url.empty() && auth;
    write_locked();
}

void Registration::set_mcp(const std::string& url, bool auth) {
    std::lock_guard<std::mutex> lock(m_);
    rec_.mcp = url;
    rec_.mcp_auth = !url.empty() && auth;
    write_locked();
}

void Registration::set_rescue(bool armed) {
    std::lock_guard<std::mutex> lock(m_);
    rec_.rescue = armed;
    write_locked();
}

void Registration::set_remote(bool on) {
    std::lock_guard<std::mutex> lock(m_);
    rec_.remote = on;
    write_locked();
}

void Registration::stop() {
    std::lock_guard<std::mutex> lock(m_);
    if (!active_) return;
    active_ = false;
    std::error_code ec;
    fs::remove(file_, ec);
}

bool Registration::active() const {
    std::lock_guard<std::mutex> lock(m_);
    return active_;
}

Record Registration::record() const {
    std::lock_guard<std::mutex> lock(m_);
    return rec_;
}

void Registration::write_locked() {
    if (!active_) return;
    const fs::path tmp = file_.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return;
        out << to_json(rec_);
    }
    std::error_code ec;
    fs::rename(tmp, file_, ec);
    if (ec) fs::remove(tmp, ec);
}

Registration& self() {
    static Registration r;
    return r;
}

std::string http_url(const std::string& bind_addr, int port) {
    return "http://" + xsql::thinclient::format_connect_url_host(bind_addr) + ":" + std::to_string(port);
}

std::string mcp_url(const std::string& bind_addr, int port) { return http_url(bind_addr, port) + "/sse"; }

int run_cli(const std::vector<std::string>& a) {
    const cli::Args args = cli::parse_args(a, {{"--json"}, {"--pid"}});
    std::string error = args.ok() ? std::string() : args.error;
    if (error.empty() && !args.positionals.empty()) error = "unexpected argument " + args.positionals[0];
    ListOptions options;
    if (error.empty() && !args.value("--pid").empty()) {
        std::stringstream pids(args.value("--pid"));
        std::string one;
        while (std::getline(pids, one, ',')) {
            char* end = nullptr;
            const unsigned long long pid = std::strtoull(one.c_str(), &end, 10);
            if (one.empty() || *end != '\0' || pid == 0) {
                error = "--pid takes process ids: --pid 1234 or --pid 1234,5678";
                break;
            }
            options.only_pids.push_back(pid);
        }
    }
    if (!error.empty()) {
        std::cerr << "error: " << error << "\nusage: idasql instances [--json] [--pid N[,N...]]\n";
        return cli::kUsage;
    }
    try {
        const deep_link::IpcOptions ipc = deep_link::effective_ipc_options();
        const auto entries = list(options);
        if (args.has("--json")) {
            json arr = json::array();
            for (const auto& e : entries) arr.push_back(entry_json(e, ipc));
            std::cout << arr.dump(2) << "\n";
            return cli::kOk;
        }
        if (entries.empty()) {
            std::cout << "No running IDA instances.\n";
            return cli::kOk;
        }
        struct Line {
            std::string pid, host, ida, sql, remote, state, db;
        };
        std::vector<Line> lines;
        Line head{"PID", "HOST", "IDA", "SQL", "REMOTE", "STATE", "DATABASE"};
        bool needs_token = false;
        for (const auto& e : entries) {
            const Record& r = e.record;
            needs_token = needs_token || r.http_auth || r.mcp_auth;
            lines.push_back({std::to_string(r.pid), r.host.empty() ? "?" : r.host,
                             r.ida_version.empty() ? "?" : r.ida_version, sql_column(e), remote_column(e),
                             e.responsive ? "ok" : "-",
                             r.idb_path.empty() ? "(no database open)" : r.idb_path});
        }
        size_t w[6] = {head.pid.size(), head.host.size(), head.ida.size(),
                       head.sql.size(), head.remote.size(), head.state.size()};
        for (const auto& l : lines) {
            w[0] = std::max(w[0], l.pid.size());
            w[1] = std::max(w[1], l.host.size());
            w[2] = std::max(w[2], l.ida.size());
            w[3] = std::max(w[3], l.sql.size());
            w[4] = std::max(w[4], l.remote.size());
            w[5] = std::max(w[5], l.state.size());
        }
        const auto print = [&w](const Line& l) {
            std::cout << std::left << std::setw(static_cast<int>(w[0] + 2)) << l.pid
                      << std::setw(static_cast<int>(w[1] + 2)) << l.host << std::setw(static_cast<int>(w[2] + 2))
                      << l.ida << std::setw(static_cast<int>(w[3] + 2)) << l.sql
                      << std::setw(static_cast<int>(w[4] + 2)) << l.remote << std::setw(static_cast<int>(w[5] + 2))
                      << l.state << l.db << "\n";
        };
        print(head);
        for (size_t i = 0; i < lines.size(); ++i) {
            print(lines[i]);
            if (!entries[i].responsive) std::cout << "  " << state_column(entries[i]) << "\n";
        }
        if (needs_token) std::cout << "* needs a token (shown by `.http start` in that IDA)\n";
        return cli::kOk;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
    } catch (...) {
        std::cerr << "error: internal error\n";
    }
    return cli::kFailed;
}

}
}
