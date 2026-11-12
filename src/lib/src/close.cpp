// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "close.hpp"

#include "control_channel.hpp"
#include "os.hpp"
#include "../../common/cli_args.hpp"

#include <xsql/json.hpp>
#ifdef XSQL_HAS_THINCLIENT
#include <xsql/thinclient/client.hpp>
#endif

#include <chrono>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace idasql {
namespace close_cmd {

const char* const kUsage =
    "usage: idasql close <database> --save|--discard [--timeout <seconds>]\n"
    "       idasql close <url> --save|--discard [--token <token>] [--timeout <seconds>]\n"
    "\n"
    "  Ends an IDA cleanly: --save saves the database first, --discard leaves it exactly\n"
    "  as it was on disk (unsaved changes are lost). Exactly one of the two.\n"
    "\n"
    "  <database>  an IDA on this machine that has it open (the GUI with the idasql plugin,\n"
    "              or an `idasql -s` server session); no server is needed.\n"
    "  <url>       an IDA serving SQL (http://host:port, as `.http start` or\n"
    "              `idasql instances` shows it); --token when that server has one.\n"
    "\n"
    "  --timeout   seconds to wait for that IDA to end (default 60).\n"
    "\n"
    "  Exit codes: 0 closed, 1 nothing to close / refused / failed, 2 usage,\n"
    "  3 timed out (a frozen IDA cannot run the close: `idasql rescue <db> --kill`).\n";

namespace {

using json = xsql::json;

bool wait_until(const std::function<bool()>& done, int timeout_s) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
    while (std::chrono::steady_clock::now() < deadline) {
        if (done()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return done();
}

int close_local(const std::string& db, bool save, int timeout_s) {
    const std::string shown = control::normalise_db_path(db);
    if (!control::is_armed(db)) {
        std::cerr << "no idasql-armed IDA on this machine has " << shown
                  << " open; for a remote IDA use its URL\n";
        return cli::kFailed;
    }
    const auto r = control::send(db, "close", json{{"save", save}}, 10000);
    switch (r.status) {
        case control::SendStatus::no_server:
            std::cerr << "no idasql-armed IDA on this machine has " << shown << " open\n";
            return cli::kFailed;
        case control::SendStatus::error:
            std::cerr << "error: " << r.error << "\n";
            return cli::kFailed;
        case control::SendStatus::timeout:
            std::cerr << "the IDA holding " << shown << " did not answer (it may be frozen): "
                      << "idasql rescue \"" << shown << "\" --kill\n";
            return cli::kTimeout;
        case control::SendStatus::ok:
            break;
    }
    if (r.reply.outcome != "closing") {
        std::cerr << "refused: " << r.reply.data.value("message", r.reply.outcome) << "\n";
        return cli::kFailed;
    }
    const uint64_t pid = r.reply.data.value("pid", uint64_t{0});
    std::cout << "closing the IDA holding " << shown << " (pid " << pid << ", "
              << (save ? "saving" : "discarding changes") << ") ...\n"
              << std::flush;
    if (!wait_until([pid] { return !os::pid_alive(pid); }, timeout_s)) {
        std::cerr << "timed out after " << timeout_s << " s: that IDA is still running (busy, a dialog, or "
                  << "frozen); to end it anyway: idasql rescue \"" << shown << "\" --kill\n";
        return cli::kTimeout;
    }
    std::cout << "closed\n";
    return cli::kOk;
}

#ifdef XSQL_HAS_THINCLIENT
bool parse_url(const std::string& url, std::string& host, int& port) {
    std::string rest = url.substr(url.find("://") + 3);
    const size_t slash = rest.find('/');
    if (slash != std::string::npos) rest = rest.substr(0, slash);
    size_t colon = rest.rfind(':');
    if (!rest.empty() && rest[0] == '[') {
        const size_t close = rest.find(']');
        if (close == std::string::npos) return false;
        host = rest.substr(1, close - 1);
        colon = rest.find(':', close);
    } else {
        host = rest.substr(0, colon);
    }
    if (colon == std::string::npos || host.empty()) return false;
    try {
        size_t used = 0;
        const std::string p = rest.substr(colon + 1);
        port = std::stoi(p, &used);
        return used == p.size() && port > 0 && port < 65536;
    } catch (...) {
        return false;
    }
}
#endif

int close_remote(const std::string& url, bool save, const std::string& token, int timeout_s) {
#ifdef XSQL_HAS_THINCLIENT
    if (url.rfind("http://", 0) != 0) {
        std::cerr << "error: only http:// URLs are served by idasql\n";
        return cli::kUsage;
    }
    xsql::thinclient::client_config cfg;
    if (!parse_url(url, cfg.host, cfg.port)) {
        std::cerr << "error: not a server URL: " << url << " (http://host:port)\n";
        return cli::kUsage;
    }
    cfg.auth_token = token;
    cfg.timeout_sec = 10;
    xsql::thinclient::client c(cfg);
    try {
        (void)c.query("SELECT 1");
    } catch (const std::exception& e) {
        const std::string what = e.what();
        if (what.find("Connection failed") != std::string::npos) {
            std::cerr << "nothing answers at " << url << "\n";
        } else {
            std::cerr << "refused: " << what << (token.empty() ? " (does that server need --token?)" : "") << "\n";
        }
        return cli::kFailed;
    }
    try {
        const std::string body = c.query(std::string("UPDATE ui_actions SET args = '{\"save\": ") +
                                         (save ? "true" : "false") + "}', run = 1 WHERE name = 'quit'");
        const json env = json::parse(body, nullptr, false);
        if (env.is_object() && !env.value("success", true)) {
            std::string why = env.value("error", std::string());
            for (const auto& r : env.value("results", json::array()))
                if (r.is_object() && !r.value("success", true)) why = r.value("error", why);
            std::cerr << "refused: " << (why.empty() ? body : why) << "\n";
            return cli::kFailed;
        }
    } catch (const std::exception& e) {
        const std::string what = e.what();
        if (what.find("Could not connect") == std::string::npos && what.find("connection") == std::string::npos &&
            what.find("Connection") == std::string::npos) {
            std::cerr << "refused: " << what << "\n";
            return cli::kFailed;
        }
    }
    std::cout << "closing the IDA at " << url << " (" << (save ? "saving" : "discarding changes") << ") ...\n"
              << std::flush;
    if (!wait_until([&c] { return !c.ping(); }, timeout_s)) {
        std::cerr << "timed out after " << timeout_s << " s: the server at " << url << " still answers\n";
        return cli::kTimeout;
    }
    std::cout << "closed\n";
    return cli::kOk;
#else
    (void)url;
    (void)save;
    (void)token;
    (void)timeout_s;
    std::cerr << "error: this build has no HTTP client; close a remote IDA from a full idasql build\n";
    return cli::kFailed;
#endif
}

}

bool is_url(const std::string& target) { return target.find("://") != std::string::npos; }

int run_cli(const std::vector<std::string>& in) {
    const cli::Args args = cli::parse_args(in, {{"--save", "--discard"}, {"--timeout", "--token"}});
    std::string error;
    if (!args.ok()) error = args.error;
    else if (args.positionals.size() != 1)
        error = args.positionals.empty() ? "a database path or a server URL is needed" : "one target at a time";
    else if (args.has("--save") == args.has("--discard"))
        error = "exactly one of --save or --discard";
    int timeout_s = kDefaultTimeoutS;
    if (error.empty() && !args.value("--timeout").empty()) {
        try {
            size_t used = 0;
            timeout_s = std::stoi(args.value("--timeout"), &used);
            if (used != args.value("--timeout").size()) timeout_s = -1;
        } catch (...) {
            timeout_s = -1;
        }
        if (timeout_s < 1 || timeout_s > 3600) error = "--timeout must be 1..3600 seconds";
    }
    if (error.empty() && !args.value("--token").empty() && !is_url(args.positionals[0]))
        error = "--token is for a URL target";
    if (!error.empty()) {
        std::cerr << "error: " << error << "\n" << kUsage;
        return cli::kUsage;
    }
    const std::string target = args.positionals[0];
    const bool save = args.has("--save");
    try {
        return is_url(target) ? close_remote(target, save, args.value("--token"), timeout_s)
                              : close_local(target, save, timeout_s);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
    }
    return cli::kFailed;
}

}
}
