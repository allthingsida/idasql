// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * idasql_commands.hpp - Dot-command parser for interactive sessions
 *
 * Shared command handling for CLI and plugin session frontends.
 */

#pragma once

#include <functional>
#include <string>

#include <xsql/thinclient/clipboard.hpp>
#include "welcome_query.hpp"

namespace idasql {

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

    // HTTP server callbacks (optional)
    std::function<std::string()> http_status;
    std::function<std::string(int, const std::string&)> http_start;
    std::function<std::string()> http_stop;
};

inline void parse_bind_and_port(const std::string& raw, std::string& bind_addr, int& port) {
    bind_addr = "127.0.0.1";
    port = 0;

    std::string rest = raw;
    size_t rs = rest.find_first_not_of(" \t");
    if (rs == std::string::npos) {
        return;
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
        port = std::stoi(tok1);
    } else {
        bind_addr = tok1;
        if (!tok2.empty()) {
            port = std::stoi(tok2);
        }
    }
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
                 "  .mcp                     Show status or start if not running\n"
                 "  .mcp start [bind] [port] Start MCP server\n"
                 "  .mcp stop                Stop MCP server\n"
                 "  .mcp help                Show MCP help\n"
#endif
                 "\n"
                 "HTTP Server:\n"
                 "  .http                    Show status or start if not running\n"
                 "  .http start [bind] [port] Start HTTP server\n"
                 "  .http stop               Stop HTTP server\n"
                 "  .http help               Show HTTP help\n"
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
            parse_bind_and_port(rest, bind_addr, port);

            if (callbacks.mcp_start) {
                output = callbacks.mcp_start(port, bind_addr);
                // Only copy to clipboard on fresh start (multi-line output with URL)
                auto nl = output.find('\n');
                if (nl != std::string::npos) {
                    const std::string clipboard_text = output.substr(0, nl);
                    (void)xsql::thinclient::try_copy_text_to_clipboard_windows(clipboard_text);
                }
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
                     "  .mcp                     Show status, start if not running\n"
                     "  .mcp start [bind] [port] Start MCP server (default: 127.0.0.1, random port)\n"
                     "  .mcp stop                Stop MCP server\n"
                     "  .mcp help                Show this help\n"
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
            std::string rest = subargs.length() > 5 ? subargs.substr(5) : "";
            parse_bind_and_port(rest, bind_addr, port);

            if (callbacks.http_start) {
                output = callbacks.http_start(port, bind_addr);
                // Only copy to clipboard on fresh start (multi-line output with URL)
                auto nl = output.find('\n');
                if (nl != std::string::npos) {
                    const std::string clipboard_text = output.substr(0, nl);
                    (void)xsql::thinclient::try_copy_text_to_clipboard_windows(clipboard_text);
                }
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
                     "  .http                     Show status, start if not running\n"
                     "  .http start [bind] [port] Start HTTP server (default: 127.0.0.1, random port)\n"
                     "  .http stop                Stop HTTP server\n"
                     "  .http help                Show this help\n"
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
