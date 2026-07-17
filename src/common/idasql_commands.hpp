// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * idasql_commands.hpp - Dot-command parser for interactive sessions
 *
 * Shared command handling for CLI and plugin session frontends.
 */

#pragma once

#include <functional>
#include <string>

#include <xsql/thinclient/clipboard.hpp>
#include "binary_query.hpp"

namespace idasql {

// Checked port parse: digits-only, in [0, 65535]. Returns true and sets `out` on
// success; false (leaving `out` untouched) on empty/non-numeric/out-of-range
// input. Used everywhere user input becomes a port so a bad ".http start
// 99999999999999" / "--http abc" is a clean error instead of an std::stoi throw
// unwinding through IDA's C execute_line (crash/UB) or aborting the CLI.
inline bool parse_port(const std::string& s, int& out) {
    if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos) {
        return false;
    }
    // Bound the length before conversion so a very long all-digit string can't
    // overflow; 5 digits covers the full 0..65535 range.
    if (s.size() > 5) {
        return false;
    }
    const int value = std::stoi(s);  // safe: <= 99999, digits-only
    if (value < 0 || value > 65535) {
        return false;
    }
    out = value;
    return true;
}

enum class CommandResult {
    NOT_HANDLED,  // Not a command, process as query
    HANDLED,      // Command executed successfully
    QUIT          // User requested quit
};

struct CommandCallbacks {
    std::function<std::string()> get_tables;
    std::function<std::string(const std::string&)> get_schema;
    std::function<std::string()> get_info;

    // MCP server callbacks (optional)
    std::function<std::string()> mcp_status;
    std::function<std::string(int, const std::string&)> mcp_start;
    std::function<std::string()> mcp_stop;

    // HTTP server callbacks (optional). http_start receives (port, bind, token);
    // an empty token means no authentication.
    std::function<std::string()> http_status;
    std::function<std::string(int, const std::string&, const std::string&)> http_start;
    std::function<std::string()> http_stop;

    // Autostart pin callbacks (optional). Wired by both the CLI and the plugin
    // (see common/pin_commands.hpp); the netnode work lives behind them so this
    // header has no IDA dependency. service is "http" | "mcp"; for pin_clear it
    // may also be "all".
    std::function<std::string()> pin_list;
    std::function<std::string(const std::string& service,
                              const std::string& bind, int port,
                              const std::string& token)> pin_set;
    std::function<std::string(const std::string& service, bool enable)> pin_enable;
    std::function<std::string(const std::string& service)> pin_clear;
};

// Parse "[bindinterface] [port]" into bind_addr/port. Returns false (leaving
// outputs at their defaults) when a token that must be a port fails the checked
// parse (non-numeric or out of range) — callers turn that into a usage error
// instead of throwing out of std::stoi on bad user input.
inline bool parse_bind_and_port(const std::string& raw, std::string& bind_addr, int& port) {
    bind_addr = "127.0.0.1";
    port = 0;

    std::string rest = raw;
    size_t rs = rest.find_first_not_of(" \t");
    if (rs == std::string::npos) {
        return true;
    }
    rest = rest.substr(rs);

    std::string tok1;
    std::string tok2;
    size_t sp = rest.find_first_of(" \t");
    if (sp != std::string::npos) {
        tok1 = rest.substr(0, sp);
        size_t t2s = rest.find_first_not_of(" \t", sp);
        if (t2s != std::string::npos) {
            tok2 = rest.substr(t2s);
        }
    } else {
        tok1 = rest;
    }

    const bool tok1_numeric = !tok1.empty() && tok1.find_first_not_of("0123456789") == std::string::npos;
    if (tok1_numeric) {
        return parse_port(tok1, port);
    } else {
        bind_addr = tok1;
        if (!tok2.empty()) {
            return parse_port(tok2, port);
        }
    }
    return true;
}

// Parse "[bindinterface] [port] [--token SECRET]". Extracts and removes a
// `--token <value>` pair (if present) into `token`, then parses the remaining
// "[bind] [port]" via parse_bind_and_port. `--token` with no following value is a
// usage error (returns false). Same numeric-port validation semantics as above.
inline bool parse_bind_port_token(const std::string& raw, std::string& bind_addr,
                                  int& port, std::string& token) {
    token.clear();
    std::string cleaned;
    cleaned.reserve(raw.size());

    // Tokenize on whitespace, pulling out `--token <value>`; keep the rest verbatim.
    size_t i = 0;
    bool expect_token_value = false;
    while (i < raw.size()) {
        size_t start = raw.find_first_not_of(" \t", i);
        if (start == std::string::npos) break;
        size_t end = raw.find_first_of(" \t", start);
        if (end == std::string::npos) end = raw.size();
        std::string word = raw.substr(start, end - start);
        i = end;

        if (expect_token_value) {
            token = word;
            expect_token_value = false;
        } else if (word == "--token") {
            expect_token_value = true;
        } else {
            if (!cleaned.empty()) cleaned.push_back(' ');
            cleaned += word;
        }
    }
    if (expect_token_value) {
        return false; // "--token" with no value
    }
    return parse_bind_and_port(cleaned, bind_addr, port);
}

inline CommandResult handle_command(
    const std::string& input,
    const CommandCallbacks& callbacks,
    std::string& output) {
    if (input.empty() || input[0] != '.') {
        return CommandResult::NOT_HANDLED;
    }

    if (input == ".quit" || input == ".exit") {
        return CommandResult::QUIT;
    }

    if (input == ".tables") {
        if (callbacks.get_tables) {
            output = callbacks.get_tables();
        }
        return CommandResult::HANDLED;
    }

    if (input == ".info") {
        if (callbacks.get_info) {
            output = callbacks.get_info();
        }
        return CommandResult::HANDLED;
    }

    if (input == ".help") {
        output = "IDASQL Commands:\n"
                 "  .tables         List all tables\n"
                 "  .schema <table> Show table schema\n"
                 "  .info           Show database info\n"
                 "  .quit / .exit   Exit\n"
                 "  .help           Show this help\n"
#ifdef IDASQL_HAS_MCP
                 "\n"
                 "MCP Server:\n"
                 "  .mcp                              Show status or start if not running\n"
                 "  .mcp start [bindinterface] [port] Start MCP server\n"
                 "  .mcp stop                         Stop MCP server\n"
                 "  .mcp help                         Show MCP help\n"
#endif
                 "\n"
                 "HTTP Server:\n"
                 "  .http                              Show status or start if not running\n"
                 "  .http start [bindinterface] [port] Start HTTP server\n"
                 "  .http stop                         Stop HTTP server\n"
                 "  .http help                         Show HTTP help\n"
                 "\n"
                 "Autostart Pins:\n"
                 "  .pin                              Show pinned autostart config\n"
                 "  .pin http|mcp [bindinterface] [port]  Pin a server; omit port for a random port each launch\n"
                 "  .pin on|off http|mcp              Enable/disable autostart-on-load\n"
                 "  .pin clear [http|mcp|all]         Remove pinned config\n"
                 "  .pin help                         Show pin help\n"
                 "\n"
                 "SQL:\n"
                 "  SELECT * FROM funcs LIMIT 10;\n"
                 "  SELECT name, size FROM funcs ORDER BY size DESC;\n";
        return CommandResult::HANDLED;
    }

    if (input.rfind(".mcp", 0) == 0) {
#ifdef IDASQL_HAS_MCP
        std::string subargs = input.length() > 4 ? input.substr(4) : "";
        size_t start = subargs.find_first_not_of(" \t");
        if (start != std::string::npos) {
            subargs = subargs.substr(start);
        }

        if (subargs.empty()) {
            if (callbacks.mcp_status) {
                output = callbacks.mcp_status();
            } else {
                output = "MCP server not available";
            }
        } else if (subargs.rfind("start", 0) == 0) {
            int port = 0;
            std::string bind_addr = "127.0.0.1";
            std::string rest = subargs.length() > 5 ? subargs.substr(5) : "";
            if (!parse_bind_and_port(rest, bind_addr, port)) {
                output = "Error: invalid port (must be a number 0-65535).\n"
                         "Usage: .mcp start [bindinterface] [port]";
                return CommandResult::HANDLED;
            }

            if (callbacks.mcp_start) {
                // The clipboard config is copied by the start callback itself at
                // bind time (it knows the real host/port and, in the CLI, the call
                // blocks until Ctrl+C so nothing could be copied here after it
                // returns). See start_mcp_server / the CLI mcp_start callback.
                output = callbacks.mcp_start(port, bind_addr);
            } else {
                output = "MCP server not available";
            }
        } else if (subargs == "stop") {
            if (callbacks.mcp_stop) {
                output = callbacks.mcp_stop();
            } else {
                output = "MCP server not available";
            }
        } else if (subargs == "help") {
            output = "MCP Server Commands:\n"
                     "  .mcp                              Show status, start if not running\n"
                     "  .mcp start [bindinterface] [port] Start MCP server (default: 127.0.0.1, random port)\n"
                     "  .mcp stop                         Stop MCP server\n"
                     "  .mcp help                         Show this help\n"
                     "\n"
                     "The MCP server exposes one tool:\n"
                     "  idasql_query  - Execute SQL query directly\n"
                     "\n"
                     "Connect with Claude Desktop by adding to config:\n"
                     "  {\"mcpServers\": {\"idasql\": {\"url\": \"http://127.0.0.1:<port>/sse\"}}}\n";
        } else {
            output = "Unknown MCP command: " + subargs + "\nUse '.mcp help' for available commands.";
        }
#else
        output = "MCP server support not compiled in. Rebuild with -DIDASQL_WITH_MCP=ON";
#endif
        return CommandResult::HANDLED;
    }

    if (input.rfind(".http", 0) == 0) {
        std::string subargs = input.length() > 5 ? input.substr(5) : "";
        size_t start = subargs.find_first_not_of(" \t");
        if (start != std::string::npos) {
            subargs = subargs.substr(start);
        }

        if (subargs.empty()) {
            if (callbacks.http_status) {
                output = callbacks.http_status();
            } else {
                output = "HTTP server not available";
            }
        } else if (subargs.rfind("start", 0) == 0) {
            int port = 0;
            std::string bind_addr = "127.0.0.1";
            std::string token;
            std::string rest = subargs.length() > 5 ? subargs.substr(5) : "";
            if (!parse_bind_port_token(rest, bind_addr, port, token)) {
                output = "Error: invalid port (must be a number 0-65535) or missing --token value.\n"
                         "Usage: .http start [bindinterface] [port] [--token SECRET]";
                return CommandResult::HANDLED;
            }

            if (callbacks.http_start) {
                // The clipboard payload is copied by the start callback at bind time
                // (see the CLI http_start / start_http_server) -- in the CLI the call
                // blocks until Ctrl+C, so the returned string is the post-stop message
                // and copying it here would copy the wrong text.
                output = callbacks.http_start(port, bind_addr, token);
            } else {
                output = "HTTP server not available";
            }
        } else if (subargs == "stop") {
            if (callbacks.http_stop) {
                output = callbacks.http_stop();
            } else {
                output = "HTTP server not available";
            }
        } else if (subargs == "help") {
            const std::string example = idasql::format_query_curl_example("http://127.0.0.1:<port>");
            output = "HTTP Server Commands:\n"
                     "  .http                              Show status, start if not running\n"
                     "  .http start [bindinterface] [port] [--token SECRET]  Start HTTP server\n"
                     "                                     (default: 127.0.0.1, random port, no auth;\n"
                     "                                      --token requires Authorization: Bearer SECRET)\n"
                     "  .http stop                         Stop HTTP server\n"
                     "  .http help                         Show this help\n"
                     "\n"
                     "Endpoints:\n"
                     "  GET  /help       API documentation\n"
                     "  POST /query      Execute SQL (body = raw SQL)\n"
                     "  GET  /status     Health check\n"
                     "  POST /shutdown   Stop server\n"
                     "\n"
                     "Schema discovery:\n"
                     "  SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY type, name;\n"
                     "  PRAGMA table_info(funcs);\n"
                     "\n"
                     "Example:\n"
                     "  " + example + "\n";
        } else {
            output = "Unknown HTTP command: " + subargs + "\nUse '.http help' for available commands.";
        }
        return CommandResult::HANDLED;
    }

    if (input.rfind(".pin", 0) == 0) {
        static const char* kPinUnavailable =
            "Autostart pinning is not available in this session.";

        std::string subargs = input.length() > 4 ? input.substr(4) : "";
        size_t s = subargs.find_first_not_of(" \t");
        subargs = (s == std::string::npos) ? "" : subargs.substr(s);

        // Pop the next whitespace-delimited token off the front of rest.
        auto next_token = [](std::string& rest) -> std::string {
            size_t b = rest.find_first_not_of(" \t");
            if (b == std::string::npos) { rest.clear(); return ""; }
            rest = rest.substr(b);
            size_t e = rest.find_first_of(" \t");
            std::string tok = (e == std::string::npos) ? rest : rest.substr(0, e);
            rest = (e == std::string::npos) ? "" : rest.substr(e);
            return tok;
        };

        if (subargs.empty() || subargs == "list" || subargs == "status") {
            output = callbacks.pin_list ? callbacks.pin_list() : kPinUnavailable;
        } else if (subargs == "help") {
            output =
                "Autostart pin commands:\n"
                "  .pin                      Show pinned config (alias of .pin list)\n"
                "  .pin list | .pin status   Show pinned config\n"
#ifdef IDASQL_HAS_MCP
                "  .pin http [bindinterface] [port]  Pin HTTP; enables autostart\n"
                "  .pin mcp  [bindinterface] [port]  Pin MCP; enables autostart\n"
                "  .pin set http|mcp [bindinterface] [port]  Same, explicit form\n"
                "  .pin on  http|mcp         Enable autostart-on-load for a service\n"
                "  .pin off http|mcp         Disable autostart (keeps host/port)\n"
                "  .pin clear [http|mcp|all] Remove pinned config (default: all)\n"
#else
                "  .pin http [bindinterface] [port]  Pin HTTP; enables autostart\n"
                "  .pin set http [bindinterface] [port]  Same, explicit form\n"
                "  .pin on  http             Enable autostart-on-load for HTTP\n"
                "  .pin off http             Disable autostart (keeps host/port)\n"
                "  .pin clear [http|all]     Remove pinned config (default: all)\n"
#endif
                "  .pin help                 Show this help\n"
                "\n"
#ifdef IDASQL_HAS_MCP
                "Pins are stored in the IDB. The plugin auto-starts enabled\n"
                "services when the database is opened; '.http start' / '.mcp start'\n"
                "with no explicit port reuse the pinned host/port. Omit the port\n"
                "to autostart on a fresh random port each launch; bindinterface\n"
                "defaults to 127.0.0.1.\n";
#else
                "Pins are stored in the IDB. The plugin auto-starts the enabled\n"
                "service when the database is opened; '.http start' with no\n"
                "explicit port reuses the pinned host/port. Omit the port to\n"
                "autostart on a fresh random port each launch; bindinterface\n"
                "defaults to 127.0.0.1.\n";
#endif
        } else {
            std::string verb = next_token(subargs);
            // Shared "pin a service" handler. The port is optional: when omitted
            // (or 0) the pin is stored with port 0 = "autostart with a fresh
            // random port each launch". bind defaults to 127.0.0.1.
            auto do_pin_set = [&](const std::string& service) {
                if (service != "http" && service != "mcp") {
                    output = "Usage: .pin set http|mcp [bindinterface] [port] [--token SECRET]";
                    return;
                }
                std::string bind_addr;
                int port = 0;
                std::string token;
                if (!parse_bind_port_token(subargs, bind_addr, port, token)) {
                    output = "Error: invalid port (must be a number 0-65535; "
                             "0 = random port each launch) or missing --token value.";
                } else if (service == "mcp" && !token.empty()) {
                    output = "Error: --token is only supported for the HTTP server "
                             "(MCP has no auth).";
                } else if (callbacks.pin_set) {
                    output = callbacks.pin_set(service, bind_addr, port, token);
                } else {
                    output = kPinUnavailable;
                }
            };
            if (verb == "set") {
                do_pin_set(next_token(subargs));
            } else if (verb == "http" || verb == "mcp") {
                // Shorthand: ".pin http [bindinterface] [port]".
                do_pin_set(verb);
            } else if (verb == "on" || verb == "off") {
                std::string service = next_token(subargs);
                if (service != "http" && service != "mcp") {
                    output = "Usage: .pin " + verb + " http|mcp";
                } else if (callbacks.pin_enable) {
                    output = callbacks.pin_enable(service, verb == "on");
                } else {
                    output = kPinUnavailable;
                }
            } else if (verb == "clear") {
                std::string service = next_token(subargs);
                if (service.empty()) service = "all";
                if (service != "http" && service != "mcp" && service != "all") {
                    output = "Usage: .pin clear [http|mcp|all]";
                } else if (callbacks.pin_clear) {
                    output = callbacks.pin_clear(service);
                } else {
                    output = kPinUnavailable;
                }
            } else {
                output = "Unknown pin command: " + verb
                         + "\nUse '.pin help' for available commands.";
            }
        }
        return CommandResult::HANDLED;
    }

    if (input.rfind(".schema", 0) == 0) {
        std::string table = input.length() > 8 ? input.substr(8) : "";
        size_t start = table.find_first_not_of(" \t");
        if (start != std::string::npos) {
            table = table.substr(start);
            size_t end = table.find_last_not_of(" \t");
            if (end != std::string::npos) {
                table = table.substr(0, end + 1);
            }
        } else {
            table.clear();
        }

        if (table.empty()) {
            output = "Usage: .schema <table_name>";
        } else if (callbacks.get_schema) {
            output = callbacks.get_schema(table);
        }
        return CommandResult::HANDLED;
    }

    output = "Unknown command: " + input;
    return CommandResult::HANDLED;
}

} // namespace idasql
