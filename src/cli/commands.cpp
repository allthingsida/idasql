// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "commands.hpp"

#include "../common/cli_args.hpp"
#include "../lib/src/deep_link.hpp"
#include "../lib/src/close.hpp"
#include "../lib/src/rescue.hpp"
#include "../lib/src/instances.hpp"
#include "../lib/src/remote_control.hpp"

#include <iomanip>
#include <sstream>

namespace idasql {
namespace cli {

namespace {

std::string ida_label(int sdk_version) {
    std::ostringstream s;
    s << "IDA " << sdk_version / 100 << "." << (sdk_version / 10) % 10;
    return s.str();
}

}

std::vector<Command> build_command_table(const BuildInfo& build) {
    const std::string needs_94 =
        build.deep_links ? std::string()
                         : "needs a build for IDA 9.4 or later (this one is for " + ida_label(build.ida_sdk_version) + ")";
    std::vector<Command> t;
    t.push_back({
        "link",
        "link <verb>",
        "ida:// deep links: open | status | register | unregister | source | config",
        "",
        [](const std::vector<std::string>& a) { return deep_link::run_cli(a); },
        needs_94,
    });
    t.push_back({
        "instances",
        "instances [--json]",
        "running IDA instances and the databases they have open",
        "usage: idasql instances [--json] [--pid N[,N...]]\n"
        "\n"
        "  Lists the running IDA instances without opening any database: process id,\n"
        "  host (gui or idalib), IDA version, the database each has open, the SQL\n"
        "  server URL when one runs (* = needs a token; the token is never listed),\n"
        "  whether other processes may start its servers (REMOTE; `idasql remote on`),\n"
        "  and whether it answers. Found through idasql's instance registry (every\n"
        "  idasql session, every IDA version) and the IPC endpoints of IDA 9.4+ (every\n"
        "  IDA 9.4+ GUI, idasql loaded or not). --json prints one object per instance;\n"
        "  --pid lists (and asks) only those processes.\n"
        "\n"
        "  Exit codes: 0 listed (an empty list included), 1 failed, 2 usage.\n",
        [](const std::vector<std::string>& a) { return instances::run_cli(a); },
        "",
    });
    t.push_back({
        "rescue",
        "rescue <db> [--kill]",
        "save a copy of the database a stuck IDA has open",
        rescue::kUsage,
        [](const std::vector<std::string>& a) { return rescue::run_cli(a); },
        "",
    });
    t.push_back({
        "close",
        "close <db|url>",
        "end an IDA cleanly: --save or --discard",
        close_cmd::kUsage,
        [](const std::vector<std::string>& a) { return close_cmd::run_cli(a); },
        "",
    });
    t.push_back({
        "http",
        "http start|stop <db|pid>",
        "start or stop another IDA's HTTP server (needs remote on there)",
        remote::kHttpUsage,
        [](const std::vector<std::string>& a) { return remote::run_server_cli("http", a); },
        "",
    });
    t.push_back({
        "mcp",
        "mcp start|stop <db|pid>",
        "the same for its MCP server",
        remote::kMcpUsage,
        [](const std::vector<std::string>& a) { return remote::run_server_cli("mcp", a); },
        "",
    });
    t.push_back({
        "remote",
        "remote on|off <db|pid>",
        "let other processes start/stop that IDA's servers",
        remote::kRemoteUsage,
        [](const std::vector<std::string>& a) { return remote::run_remote_cli(a); },
        "",
    });
    return t;
}

bool dispatch(const std::vector<Command>& table, const std::vector<std::string>& args, int& rc,
              std::ostream& out, std::ostream& err) {
    if (args.empty()) return false;
    const Command* cmd = nullptr;
    for (const auto& c : table) {
        if (c.name == args[0]) {
            cmd = &c;
            break;
        }
    }
    if (cmd == nullptr) return false;
    const std::vector<std::string> rest(args.begin() + 1, args.end());
    if (!cmd->unavailable.empty()) {
        err << "idasql " << cmd->name << ": " << cmd->unavailable << "\n";
        rc = kFailed;
        return true;
    }
    if (!cmd->usage.empty() && wants_help(rest)) {
        out << cmd->usage;
        rc = kOk;
        return true;
    }
    rc = cmd->run(rest);
    return true;
}

void print_command_list(const std::vector<Command>& table, std::ostream& out) {
    out << "Commands (no database is opened; `idasql <command> --help` for details):\n";
    for (const auto& c : table) {
        constexpr size_t kWidth = 26;
        out << "  " << std::left << std::setw(static_cast<int>(kWidth)) << c.synopsis
            << (c.synopsis.size() >= kWidth ? " " : "") << c.summary;
        if (!c.unavailable.empty()) out << " [" << c.unavailable << "]";
        out << "\n";
    }
}

}
}
