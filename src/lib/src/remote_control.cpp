// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "remote_control.hpp"

#include "control_channel.hpp"
#include "os.hpp"
#include "../../common/cli_args.hpp"

#include <xsql/json.hpp>

#include <iostream>

namespace idasql {
namespace remote {

const char* const kHttpUsage =
    "usage: idasql http start|stop <database|pid> [--timeout <seconds>] [--json]\n"
    "\n"
    "  Starts or stops the HTTP server of another IDA on this machine, as `.http start`\n"
    "  and `.http stop` do in that IDA. The target is the database it has open or its\n"
    "  process id (`idasql instances` lists both). That database must have remote\n"
    "  control on (`idasql remote on <database|pid>`, or `.remote on` in that IDA).\n"
    "\n"
    "  start prints the server URL (bound to 127.0.0.1, or the database's own pin).\n"
    "  A server that is already running is left as it is and its URL printed. A token\n"
    "  is never handed out: a server pinned with one says so.\n"
    "\n"
    "  An `idasql -s --http` session already serves: start prints its URL. Other\n"
    "  `idasql -s` sessions cannot start a server on request.\n"
    "\n"
    "  --timeout   seconds to wait for that IDA's answer (default 10).\n"
    "  --json      print the result as JSON.\n"
    "\n"
    "  Exit codes: 0 done, 1 not found / refused / failed, 2 usage, 3 timed out (IDA\n"
    "  busy or frozen), 4 remote control is off there.\n";

const char* const kMcpUsage =
    "usage: idasql mcp start|stop <database|pid> [--timeout <seconds>] [--json]\n"
    "\n"
    "  The same as `idasql http start|stop`, for the MCP server (`.mcp start|stop` in\n"
    "  that IDA). start prints the MCP URL (.../sse). Needs remote control on there,\n"
    "  and an IDA plugin built with MCP.\n"
    "\n"
    "  Exit codes: 0 done, 1 not found / refused / failed, 2 usage, 3 timed out (IDA\n"
    "  busy or frozen), 4 remote control is off there.\n";

const char* const kRemoteUsage =
    "usage: idasql remote on|off <database|pid> [--timeout <seconds>] [--json]\n"
    "\n"
    "  Switches the remote control of another IDA's database, as `.remote on|off`\n"
    "  does in that IDA. On: other processes of yours on this machine may start and\n"
    "  stop its servers (`idasql http start`, `UPDATE ida_instances SET start = ...`).\n"
    "  Off is the default. The switch is stored in the database (saved with it), and\n"
    "  that IDA prints every request it gets in its Output window.\n"
    "\n"
    "  Exit codes: 0 done, 1 not found / refused / failed, 2 usage, 3 timed out (IDA\n"
    "  busy or frozen).\n";

namespace {

using json = xsql::json;

bool all_digits(const std::string& s) {
    return !s.empty() && s.find_first_not_of("0123456789") == std::string::npos;
}

std::string name_of(const std::string& path) {
    const size_t slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string who(const instances::Record& t) {
    return name_of(t.idb_path) + " (pid " + std::to_string(t.pid) + ")";
}

std::string upper(const std::string& service) { return service == "mcp" ? "MCP" : "HTTP"; }

json from_field() { return json{{"pid", os::current_pid()}, {"exe", os::current_exe_name()}}; }

Result base(const instances::Record& t) {
    Result r;
    r.pid = t.pid;
    r.idb_path = t.idb_path;
    return r;
}

Result fail(Result r, int exit, std::string message) {
    r.exit = exit;
    r.message = std::move(message);
    return r;
}

bool exchange(const instances::Record& t, const std::string& action, const json& args, int timeout_s,
              Result& r, control::Reply& reply) {
    if (!t.rescue) {
        r = fail(r, cli::kFailed, who(t) + " has no control channel (its idasql could not arm one)");
        return false;
    }
    const auto sent = control::send(t.idb_path, action, args, timeout_s * 1000);
    switch (sent.status) {
        case control::SendStatus::no_server:
            r = fail(r, cli::kFailed, who(t) + " no longer has that database open");
            return false;
        case control::SendStatus::error:
            r = fail(r, cli::kFailed, "error: " + sent.error);
            return false;
        case control::SendStatus::timeout:
            r = fail(r, cli::kTimeout,
                     "no answer from pid " + std::to_string(t.pid) + " in " + std::to_string(timeout_s) +
                         " s (IDA busy or frozen; to save its work: idasql rescue \"" + t.idb_path + "\")");
            return false;
        case control::SendStatus::ok:
            break;
    }
    reply = sent.reply;
    const std::string& o = reply.outcome;
    if (o == "ok") return true;
    if (o == "remote_off") {
        r = fail(r, kRemoteOff,
                 "remote control is off for " + who(t) + "\nturn it on with: idasql remote on " +
                     std::to_string(t.pid) + "   (or .remote on in that IDA)");
    } else if (o == "unknown_action") {
        r = fail(r, cli::kFailed,
                 who(t) + " runs an idasql that takes no remote requests (idasql " +
                     (t.idasql_version.empty() ? std::string("?") : t.idasql_version) + "); update it");
    } else {
        r = fail(r, cli::kFailed, "refused: " + reply.data.value("message", o));
    }
    return false;
}

json to_json(const Result& r) {
    json j = {{"ok", r.ok()}, {"exit", r.exit}, {"pid", r.pid}, {"idb_path", r.idb_path}, {"message", r.message}};
    if (!r.url.empty()) {
        j["url"] = r.url;
        j["already"] = r.already;
        j["auth"] = r.auth;
    }
    return j;
}

int print(const Result& r, bool as_json) {
    if (as_json) {
        std::cout << to_json(r).dump(2) << "\n";
    } else {
        (r.ok() ? std::cout : std::cerr) << r.message << "\n";
    }
    return r.exit;
}

struct Parsed {
    std::string verb, target, error;
    int timeout_s = kDefaultTimeoutS;
    bool json = false;
};

Parsed parse(const std::vector<std::string>& in, const std::vector<std::string>& verbs) {
    Parsed p;
    const cli::Args a = cli::parse_args(in, {{"--json"}, {"--timeout"}});
    if (!a.ok()) {
        p.error = a.error;
        return p;
    }
    p.json = a.has("--json");
    if (a.positionals.empty()) {
        p.error = "a verb is needed";
        return p;
    }
    p.verb = a.positionals[0];
    bool known = false;
    for (const auto& v : verbs) known = known || v == p.verb;
    if (!known) {
        p.error = "unknown verb '" + p.verb + "'";
        return p;
    }
    if (a.positionals.size() != 2) {
        p.error = a.positionals.size() < 2 ? "a database path or a process id is needed" : "one target at a time";
        return p;
    }
    p.target = a.positionals[1];
    const std::string t = a.value("--timeout");
    if (!t.empty()) {
        p.timeout_s = all_digits(t) && t.size() <= 4 ? std::stoi(t) : -1;
        if (p.timeout_s < 1 || p.timeout_s > 3600) p.error = "--timeout must be 1..3600 seconds";
    }
    return p;
}

}

bool find_target(const std::string& target, instances::Record& out, std::string& error) {
    const auto records = instances::read_registry(instances::registry_dir());
    if (all_digits(target)) {
        const uint64_t pid = target.size() <= 19 ? std::stoull(target) : 0;
        for (const auto& r : records) {
            if (r.pid == pid) {
                out = r;
                return true;
            }
        }
        error = "no idasql session on this machine has pid " + target + " (`idasql instances` lists them)";
        return false;
    }
    const std::string want = control::normalise_db_path(target);
    for (const auto& r : records) {
        if (!r.idb_path.empty() && control::normalise_db_path(r.idb_path) == want) {
            out = r;
            return true;
        }
    }
    error = "no idasql session on this machine has " + want + " open (`idasql instances` lists them)";
    return false;
}

Result server(const instances::Record& t, const std::string& service, bool start, int timeout_s) {
    Result r = base(t);
    if (service != "http" && service != "mcp") return fail(r, cli::kUsage, "unknown service '" + service + "'");
    if (t.host == "idalib") {
        const std::string& url = service == "http" ? t.http : t.mcp;
        if (start && !url.empty()) {
            r.exit = cli::kOk;
            r.url = url;
            r.already = true;
            r.auth = service == "http" ? t.http_auth : t.mcp_auth;
            r.message = url + " (already running)";
            return r;
        }
        return fail(r, cli::kFailed,
                    "pid " + std::to_string(t.pid) + " is an idasql -s session; " +
                        (start ? "it serves only when started with --http or --mcp"
                               : "stop its server where it runs (Ctrl+C)"));
    }
    control::Reply reply;
    if (!exchange(t, start ? "start" : "stop", json{{"service", service}, {"from", from_field()}}, timeout_s, r,
                  reply))
        return r;
    r.exit = cli::kOk;
    if (start) {
        r.url = reply.data.value("url", std::string());
        r.already = reply.data.value("already", false);
        r.auth = reply.data.value("auth", false);
        r.message = r.url + (r.already ? " (already running)" : "") +
                    (r.auth ? "  (needs a token: ask whoever set it)" : "");
    } else {
        r.message = upper(service) + (reply.data.value("stopped", false) ? " server stopped" : " server was not running");
    }
    return r;
}

Result set_remote(const instances::Record& t, bool on, int timeout_s) {
    Result r = base(t);
    if (t.host == "idalib")
        return fail(r, cli::kFailed,
                    "pid " + std::to_string(t.pid) +
                        " is an idasql -s session; remote control applies to an IDA window (set it with .remote "
                        "there, or open the database in IDA)");
    control::Reply reply;
    if (!exchange(t, "remote", json{{"on", on}, {"from", from_field()}}, timeout_s, r, reply)) return r;
    r.exit = cli::kOk;
    r.message = std::string("remote control ") + (reply.data.value("remote", on) ? "on" : "off") + " for " + who(t);
    return r;
}

int run_server_cli(const std::string& service, const std::vector<std::string>& args) {
    const char* usage = service == "mcp" ? kMcpUsage : kHttpUsage;
    const Parsed p = parse(args, {"start", "stop"});
    if (!p.error.empty()) {
        std::cerr << "error: " << p.error << "\n" << usage;
        return cli::kUsage;
    }
    try {
        instances::Record t;
        std::string error;
        if (!find_target(p.target, t, error)) {
            Result r;
            return print(fail(r, cli::kFailed, error), p.json);
        }
        return print(server(t, service, p.verb == "start", p.timeout_s), p.json);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
    }
    return cli::kFailed;
}

int run_remote_cli(const std::vector<std::string>& args) {
    const Parsed p = parse(args, {"on", "off"});
    if (!p.error.empty()) {
        std::cerr << "error: " << p.error << "\n" << kRemoteUsage;
        return cli::kUsage;
    }
    try {
        instances::Record t;
        std::string error;
        if (!find_target(p.target, t, error)) {
            Result r;
            return print(fail(r, cli::kFailed, error), p.json);
        }
        return print(set_remote(t, p.verb == "on", p.timeout_s), p.json);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
    }
    return cli::kFailed;
}

}
}
