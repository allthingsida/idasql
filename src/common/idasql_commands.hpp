#pragma once

#include <functional>
#include <string>
#include <sstream>

#ifdef IDASQL_HAS_AI_AGENT
#include "agent_settings.hpp"
#endif

namespace idasql {

/**
 * Command handler result
 */
enum class CommandResult {
    NOT_HANDLED,  // Not a command, process as query
    HANDLED,      // Command executed successfully
    QUIT          // User requested quit
};

/**
 * Command handler callbacks
 *
 * These callbacks allow different environments (CLI, plugin) to extend
 * command behavior. For example, .clear might:
 *   - Core: Reset the AI agent session
 *   - Plugin: Also call msg_clear() to clear IDA's message window
 */
struct CommandCallbacks {
    std::function<std::string()> get_tables;      // Return table list
    std::function<std::string(const std::string&)> get_schema;  // Return schema for table
    std::function<std::string()> get_info;        // Return database info
    std::function<std::string()> clear_session;   // Clear/reset session (agent, UI, etc.)

    // MCP server callbacks (optional - plugin only)
    std::function<std::string()> mcp_status;      // Get MCP status
    std::function<std::string(int, const std::string&)> mcp_start;  // Start MCP server (port, bind_addr)
    std::function<std::string()> mcp_stop;        // Stop MCP server

    // HTTP server callbacks (optional)
    std::function<std::string()> http_status;     // Get HTTP server status
    std::function<std::string(int, const std::string&)> http_start;  // Start HTTP server (port, bind_addr)
    std::function<std::string()> http_stop;       // Stop HTTP server
};

/**
 * Handle dot commands (.tables, .schema, .help, .quit, etc.)
 *
 * @param input User input line
 * @param callbacks Callbacks to execute commands
 * @param output Output string (filled if command produces output)
 * @return CommandResult indicating how to proceed
 */
inline CommandResult handle_command(
    const std::string& input,
    const CommandCallbacks& callbacks,
    std::string& output)
{
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

    if (input == ".clear") {
        if (callbacks.clear_session) {
            output = callbacks.clear_session();
        } else {
            output = "Session cleared";
        }
        return CommandResult::HANDLED;
    }

    if (input == ".help") {
        output = "IDASQL Commands:\n"
                 "  .tables         List all tables\n"
                 "  .schema <table> Show table schema\n"
                 "  .info           Show database info\n"
                 "  .clear          Clear/reset session\n"
                 "  .quit / .exit   Exit\n"
                 "  .help           Show this help\n"
#ifdef IDASQL_HAS_AI_AGENT
                 "\n"
                 "MCP Server:\n"
                 "  .mcp                    Show status or start if not running\n"
                 "  .mcp start [bind] [port] Start MCP server\n"
                 "  .mcp stop               Stop MCP server\n"
                 "  .mcp help               Show MCP help\n"
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
                 "  SELECT name, size FROM funcs ORDER BY size DESC;\n"
#ifdef IDASQL_HAS_AI_AGENT
                 "\n"
                 "AI Agent:\n"
                 "  .agent help       Show agent commands\n"
                 "  .agent provider   Show/set AI provider\n"
                 "  .agent clear      Clear conversation\n"
                 "\n"
                 "Natural Language:\n"
                 "  Find the largest functions\n"
                 "  Show functions that call malloc\n"
                 "  What imports does this binary use?\n"
#endif
                 ;
        return CommandResult::HANDLED;
    }

    // .mcp commands (MCP server control - plugin only)
    if (input.rfind(".mcp", 0) == 0) {
#ifdef IDASQL_HAS_AI_AGENT
        std::string subargs = input.length() > 4 ? input.substr(4) : "";
        // Trim leading whitespace
        size_t start = subargs.find_first_not_of(" \t");
        if (start != std::string::npos)
            subargs = subargs.substr(start);

        if (subargs.empty()) {
            // .mcp - show status, start if not running
            if (callbacks.mcp_status) {
                output = callbacks.mcp_status();
            } else {
                output = "MCP server not available (plugin mode only)";
            }
        }
        else if (subargs.rfind("start", 0) == 0) {
            int port = 0;
            std::string bind_addr = "127.0.0.1";
            // Parse optional: "start [bind] [port]"
            std::string rest = subargs.length() > 5 ? subargs.substr(5) : "";
            size_t rs = rest.find_first_not_of(" \t");
            if (rs != std::string::npos) {
                rest = rest.substr(rs);
                // Split into tokens
                std::string tok1, tok2;
                size_t sp = rest.find_first_of(" \t");
                if (sp != std::string::npos) {
                    tok1 = rest.substr(0, sp);
                    size_t t2s = rest.find_first_not_of(" \t", sp);
                    if (t2s != std::string::npos) tok2 = rest.substr(t2s);
                } else {
                    tok1 = rest;
                }
                // Heuristic: if tok1 is all digits, treat as port; otherwise bind_addr
                bool tok1_numeric = !tok1.empty() && tok1.find_first_not_of("0123456789") == std::string::npos;
                if (tok1_numeric) {
                    port = std::stoi(tok1);
                } else {
                    bind_addr = tok1;
                    if (!tok2.empty()) port = std::stoi(tok2);
                }
            }
            if (callbacks.mcp_start) {
                output = callbacks.mcp_start(port, bind_addr);
            } else {
                output = "MCP server not available (plugin mode only)";
            }
        }
        else if (subargs == "stop") {
            if (callbacks.mcp_stop) {
                output = callbacks.mcp_stop();
            } else {
                output = "MCP server not available (plugin mode only)";
            }
        }
        else if (subargs == "help") {
            output = "MCP Server Commands:\n"
                     "  .mcp                     Show status, start if not running\n"
                     "  .mcp start [bind] [port]  Start MCP server (default: 127.0.0.1, random port)\n"
                     "  .mcp stop                Stop MCP server\n"
                     "  .mcp help                Show this help\n"
                     "\n"
                     "The MCP server exposes two tools:\n"
                     "  idasql_query  - Execute SQL query directly\n"
                     "  idasql_agent  - Ask natural language question (AI-powered)\n"
                     "\n"
                     "Connect with Claude Desktop by adding to config:\n"
                     "  {\"mcpServers\": {\"idasql\": {\"url\": \"http://127.0.0.1:<port>/sse\"}}}\n";
        }
        else {
            output = "Unknown MCP command: " + subargs + "\nUse '.mcp help' for available commands.";
        }
#else
        output = "MCP server requires AI agent support. Rebuild with -DIDASQL_WITH_AI_AGENT=ON";
#endif
        return CommandResult::HANDLED;
    }

    // .http commands (HTTP server control)
    if (input.rfind(".http", 0) == 0) {
        std::string subargs = input.length() > 5 ? input.substr(5) : "";
        // Trim leading whitespace
        size_t start = subargs.find_first_not_of(" \t");
        if (start != std::string::npos)
            subargs = subargs.substr(start);

        if (subargs.empty()) {
            // .http - show status, start if not running
            if (callbacks.http_status) {
                output = callbacks.http_status();
            } else {
                output = "HTTP server not available";
            }
        }
        else if (subargs.rfind("start", 0) == 0) {
            int port = 0;
            std::string bind_addr = "127.0.0.1";
            // Parse optional: "start [bind] [port]"
            std::string rest = subargs.length() > 5 ? subargs.substr(5) : "";
            size_t rs = rest.find_first_not_of(" \t");
            if (rs != std::string::npos) {
                rest = rest.substr(rs);
                // Split into tokens
                std::string tok1, tok2;
                size_t sp = rest.find_first_of(" \t");
                if (sp != std::string::npos) {
                    tok1 = rest.substr(0, sp);
                    size_t t2s = rest.find_first_not_of(" \t", sp);
                    if (t2s != std::string::npos) tok2 = rest.substr(t2s);
                } else {
                    tok1 = rest;
                }
                // Heuristic: if tok1 is all digits, treat as port; otherwise bind_addr
                bool tok1_numeric = !tok1.empty() && tok1.find_first_not_of("0123456789") == std::string::npos;
                if (tok1_numeric) {
                    port = std::stoi(tok1);
                } else {
                    bind_addr = tok1;
                    if (!tok2.empty()) port = std::stoi(tok2);
                }
            }
            if (callbacks.http_start) {
                output = callbacks.http_start(port, bind_addr);
            } else {
                output = "HTTP server not available";
            }
        }
        else if (subargs == "stop") {
            if (callbacks.http_stop) {
                output = callbacks.http_stop();
            } else {
                output = "HTTP server not available";
            }
        }
        else if (subargs == "help") {
            output = "HTTP Server Commands:\n"
                     "  .http                     Show status, start if not running\n"
                     "  .http start [bind] [port]  Start HTTP server (default: 127.0.0.1, random port)\n"
                     "  .http stop                Stop HTTP server\n"
                     "  .http help                Show this help\n"
                     "\n"
                     "Endpoints:\n"
                     "  GET  /help       API documentation\n"
                     "  POST /query      Execute SQL (body = raw SQL)\n"
                     "  GET  /status     Health check\n"
                     "  POST /shutdown   Stop server\n"
                     "\n"
                     "Example:\n"
                     "  curl -X POST http://127.0.0.1:<port>/query -d \"SELECT name FROM funcs LIMIT 5\"\n";
        }
        else {
            output = "Unknown HTTP command: " + subargs + "\nUse '.http help' for available commands.";
        }
        return CommandResult::HANDLED;
    }

    // .agent commands
    if (input.rfind(".agent", 0) == 0) {
#ifdef IDASQL_HAS_AI_AGENT
        std::string subargs = input.length() > 6 ? input.substr(6) : "";
        // Trim leading whitespace
        size_t start = subargs.find_first_not_of(" \t");
        if (start != std::string::npos)
            subargs = subargs.substr(start);

        // Parse subcmd and value
        std::string subcmd, value;
        size_t space = subargs.find(' ');
        if (space != std::string::npos) {
            subcmd = subargs.substr(0, space);
            value = subargs.substr(space + 1);
            size_t val_start = value.find_first_not_of(" \t");
            if (val_start != std::string::npos)
                value = value.substr(val_start);
        } else {
            subcmd = subargs;
        }

        auto settings = LoadAgentSettings();
        std::string provider_name = libagents::provider_type_name(settings.default_provider);

        if (subcmd.empty() || subcmd == "help") {
            output = "Agent Commands:\n"
                     "  .agent help               Show this help\n"
                     "  .agent provider           Show current provider\n"
                     "  .agent provider NAME      Switch provider (claude, copilot)\n"
                     "  .agent clear              Clear conversation\n"
                     "  .agent timeout            Show response timeout\n"
                     "  .agent timeout MS         Set response timeout in milliseconds\n"
                     "  .agent byok               Show BYOK status\n"
                     "  .agent byok enable        Enable BYOK\n"
                     "  .agent byok disable       Disable BYOK\n"
                     "  .agent byok key VALUE     Set API key\n"
                     "  .agent byok endpoint URL  Set API endpoint\n"
                     "  .agent byok model NAME    Set model name\n"
                     "  .agent byok type TYPE     Set provider type (openai, anthropic, azure)\n"
                     "\nCurrent provider: " + provider_name + "\n";
        }
        else if (subcmd == "provider") {
            if (value.empty()) {
                output = "Current provider: " + provider_name + "\n"
                         "\nAvailable providers:\n"
                         "  claude   - Claude Code (Anthropic)\n"
                         "  copilot  - GitHub Copilot\n";
            } else {
                try {
                    auto type = ParseProviderType(value);
                    settings.default_provider = type;
                    SaveAgentSettings(settings);
                    output = "Provider set to: " + std::string(libagents::provider_type_name(type)) +
                             " (saved to settings)\n"
                             "Note: Restart agent session for changes to take effect.\n";
                } catch (const std::exception& e) {
                    output = std::string("Error: ") + e.what() + "\n"
                             "Available providers: claude, copilot\n";
                }
            }
        }
        else if (subcmd == "clear") {
            if (callbacks.clear_session) {
                output = callbacks.clear_session();
            } else {
                output = "Session cleared";
            }
        }
        else if (subcmd == "timeout") {
            if (value.empty()) {
                output = "Response timeout: " + std::to_string(settings.response_timeout_ms) + " ms (" +
                         std::to_string(settings.response_timeout_ms / 1000) + " seconds)\n";
            } else {
                try {
                    int ms = std::stoi(value);
                    if (ms < 1000) {
                        output = "Error: Timeout must be at least 1000 ms (1 second).\n";
                    } else {
                        settings.response_timeout_ms = ms;
                        SaveAgentSettings(settings);
                        output = "Timeout set to " + std::to_string(ms) + " ms (" +
                                 std::to_string(ms / 1000) + " seconds).\n";
                    }
                } catch (...) {
                    output = "Error: Invalid timeout value. Use milliseconds.\n";
                }
            }
        }
        else if (subcmd == "byok") {
            // Parse BYOK subcommand
            std::string byok_subcmd, byok_value;
            size_t byok_space = value.find(' ');
            if (byok_space != std::string::npos) {
                byok_subcmd = value.substr(0, byok_space);
                byok_value = value.substr(byok_space + 1);
                size_t bv_start = byok_value.find_first_not_of(" \t");
                if (bv_start != std::string::npos)
                    byok_value = byok_value.substr(bv_start);
            } else {
                byok_subcmd = value;
            }

            const BYOKSettings* byok = settings.get_byok();

            if (byok_subcmd.empty()) {
                std::stringstream ss;
                ss << "BYOK status for provider '" << provider_name << "':\n";
                if (byok) {
                    ss << "  Enabled:  " << (byok->enabled ? "yes" : "no") << "\n"
                       << "  API Key:  " << (byok->api_key.empty() ? "(not set)" : "********") << "\n"
                       << "  Endpoint: " << (byok->base_url.empty() ? "(default)" : byok->base_url) << "\n"
                       << "  Model:    " << (byok->model.empty() ? "(default)" : byok->model) << "\n"
                       << "  Type:     " << (byok->provider_type.empty() ? "(default)" : byok->provider_type) << "\n"
                       << "  Usable:   " << (byok->is_usable() ? "yes" : "no") << "\n";
                } else {
                    ss << "  (not configured)\n";
                }
                output = ss.str();
            }
            else if (byok_subcmd == "enable") {
                auto& b = settings.get_or_create_byok();
                b.enabled = true;
                SaveAgentSettings(settings);
                output = "BYOK enabled for provider '" + provider_name + "'.\n";
                if (b.api_key.empty()) {
                    output += "Warning: API key not set. Use '.agent byok key <value>' to set it.\n";
                }
            }
            else if (byok_subcmd == "disable") {
                auto& b = settings.get_or_create_byok();
                b.enabled = false;
                SaveAgentSettings(settings);
                output = "BYOK disabled for provider '" + provider_name + "'.\n";
            }
            else if (byok_subcmd == "key") {
                if (byok_value.empty()) {
                    output = "Error: API key value required.\n"
                             "Usage: .agent byok key <value>\n";
                } else {
                    auto& b = settings.get_or_create_byok();
                    b.api_key = byok_value;
                    SaveAgentSettings(settings);
                    output = "BYOK API key set for provider '" + provider_name + "'.\n";
                }
            }
            else if (byok_subcmd == "endpoint") {
                auto& b = settings.get_or_create_byok();
                b.base_url = byok_value;
                SaveAgentSettings(settings);
                output = byok_value.empty() ?
                    "BYOK endpoint cleared (using default).\n" :
                    "BYOK endpoint set to: " + byok_value + "\n";
            }
            else if (byok_subcmd == "model") {
                auto& b = settings.get_or_create_byok();
                b.model = byok_value;
                SaveAgentSettings(settings);
                output = byok_value.empty() ?
                    "BYOK model cleared (using default).\n" :
                    "BYOK model set to: " + byok_value + "\n";
            }
            else if (byok_subcmd == "type") {
                auto& b = settings.get_or_create_byok();
                b.provider_type = byok_value;
                SaveAgentSettings(settings);
                output = byok_value.empty() ?
                    "BYOK type cleared (using default).\n" :
                    "BYOK type set to: " + byok_value + "\n";
            }
            else {
                output = "Unknown byok subcommand: " + byok_subcmd + "\n"
                         "Use '.agent byok' to see available commands.\n";
            }
        }
        else {
            output = "Unknown agent subcommand: " + subcmd + "\n"
                     "Use '.agent help' for available commands.\n";
        }
#else
        output = "AI agent support not compiled in. Rebuild with -DIDASQL_WITH_AI_AGENT=ON\n";
#endif
        return CommandResult::HANDLED;
    }

    if (input.rfind(".schema", 0) == 0) {
        std::string table = input.length() > 8 ? input.substr(8) : "";
        // Trim leading whitespace
        size_t start = table.find_first_not_of(" \t");
        if (start != std::string::npos) {
            table = table.substr(start);
            // Trim trailing whitespace
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

/**
 * Handle --config CLI commands
 *
 * @param path Config path like "agent.provider" or "agent.byok.key"
 * @param value Value to set (empty = get current value)
 * @return tuple<success, output, exit_code>
 */
inline std::tuple<bool, std::string, int> handle_config_command(
    const std::string& path,
    const std::string& value)
{
#ifdef IDASQL_HAS_AI_AGENT
    auto settings = LoadAgentSettings();
    std::string provider_name = libagents::provider_type_name(settings.default_provider);
    std::stringstream ss;

    // Show all config
    if (path.empty()) {
        ss << "Settings: " << GetSettingsPath() << "\n\n";
        ss << "agent.provider:  " << provider_name << "\n";
        ss << "agent.timeout:   " << settings.response_timeout_ms << " ms\n";
        ss << "agent.prompt:    " << (settings.custom_prompt.empty() ? "(not set)" : "\"" + settings.custom_prompt + "\"") << "\n";
        ss << "\n";

        const BYOKSettings* byok = settings.get_byok();
        ss << "agent.byok (" << provider_name << "):\n";
        if (byok) {
            ss << "  enabled:   " << (byok->enabled ? "true" : "false") << "\n";
            ss << "  key:       " << (byok->api_key.empty() ? "(not set)" : "********") << "\n";
            ss << "  endpoint:  " << (byok->base_url.empty() ? "(default)" : byok->base_url) << "\n";
            ss << "  model:     " << (byok->model.empty() ? "(default)" : byok->model) << "\n";
            ss << "  type:      " << (byok->provider_type.empty() ? "(default)" : byok->provider_type) << "\n";
        } else {
            ss << "  (not configured)\n";
        }
        return {true, ss.str(), 0};
    }

    // Parse path
    std::vector<std::string> parts;
    std::string part;
    std::istringstream iss(path);
    while (std::getline(iss, part, '.')) {
        if (!part.empty()) parts.push_back(part);
    }

    if (parts.empty() || parts[0] != "agent") {
        return {false, "Error: Unknown config path: " + path + "\nUse --config to see available options.\n", 1};
    }

    // agent.*
    if (parts.size() == 1) {
        // Just "agent" - show agent settings
        ss << "agent.provider:  " << provider_name << "\n";
        ss << "agent.timeout:   " << settings.response_timeout_ms << " ms\n";
        ss << "agent.prompt:    " << (settings.custom_prompt.empty() ? "(not set)" : "\"" + settings.custom_prompt + "\"") << "\n";
        return {true, ss.str(), 0};
    }

    std::string key = parts[1];

    // agent.provider
    if (key == "provider") {
        if (value.empty()) {
            ss << "agent.provider = " << provider_name << "\n";
        } else {
            try {
                auto type = ParseProviderType(value);
                settings.default_provider = type;
                SaveAgentSettings(settings);
                ss << "agent.provider = " << libagents::provider_type_name(type) << " (saved)\n";
            } catch (const std::exception& e) {
                return {false, std::string("Error: ") + e.what() + "\n", 1};
            }
        }
        return {true, ss.str(), 0};
    }

    // agent.timeout
    if (key == "timeout") {
        if (value.empty()) {
            ss << "agent.timeout = " << settings.response_timeout_ms << " ms\n";
        } else {
            try {
                int ms = std::stoi(value);
                if (ms < 1000) {
                    return {false, "Error: Timeout must be at least 1000 ms.\n", 1};
                }
                settings.response_timeout_ms = ms;
                SaveAgentSettings(settings);
                ss << "agent.timeout = " << ms << " ms (saved)\n";
            } catch (...) {
                return {false, "Error: Invalid timeout value.\n", 1};
            }
        }
        return {true, ss.str(), 0};
    }

    // agent.prompt
    if (key == "prompt") {
        if (value.empty()) {
            ss << "agent.prompt = " << (settings.custom_prompt.empty() ? "(not set)" : "\"" + settings.custom_prompt + "\"") << "\n";
        } else {
            settings.custom_prompt = value;
            SaveAgentSettings(settings);
            ss << "agent.prompt = \"" << value << "\" (saved)\n";
        }
        return {true, ss.str(), 0};
    }

    // agent.byok.*
    if (key == "byok") {
        // Helper lambda to show BYOK status for a provider
        auto show_byok = [&ss](const std::string& pname, const BYOKSettings* byok) {
            ss << "agent.byok." << pname << ":\n";
            if (byok) {
                ss << "  enabled:   " << (byok->enabled ? "true" : "false") << "\n";
                ss << "  key:       " << (byok->api_key.empty() ? "(not set)" : "********") << "\n";
                ss << "  endpoint:  " << (byok->base_url.empty() ? "(default)" : byok->base_url) << "\n";
                ss << "  model:     " << (byok->model.empty() ? "(default)" : byok->model) << "\n";
                ss << "  type:      " << (byok->provider_type.empty() ? "(default)" : byok->provider_type) << "\n";
            } else {
                ss << "  (not configured)\n";
            }
        };

        // Helper lambda to get/set a BYOK field
        auto handle_byok_field = [&](BYOKSettings& byok, const std::string& field,
                                      const std::string& prefix) -> std::tuple<bool, std::string, int> {
            std::stringstream out;
            if (field == "enabled") {
                if (value.empty()) {
                    out << prefix << ".enabled = " << (byok.enabled ? "true" : "false") << "\n";
                } else {
                    byok.enabled = (value == "true" || value == "1" || value == "yes");
                    SaveAgentSettings(settings);
                    out << prefix << ".enabled = " << (byok.enabled ? "true" : "false") << " (saved)\n";
                }
                return {true, out.str(), 0};
            }
            if (field == "key") {
                if (value.empty()) {
                    out << prefix << ".key = " << (byok.api_key.empty() ? "(not set)" : "********") << "\n";
                } else {
                    byok.api_key = value;
                    SaveAgentSettings(settings);
                    out << prefix << ".key = ******** (saved)\n";
                }
                return {true, out.str(), 0};
            }
            if (field == "endpoint") {
                if (value.empty()) {
                    out << prefix << ".endpoint = " << (byok.base_url.empty() ? "(default)" : byok.base_url) << "\n";
                } else {
                    byok.base_url = value;
                    SaveAgentSettings(settings);
                    out << prefix << ".endpoint = " << value << " (saved)\n";
                }
                return {true, out.str(), 0};
            }
            if (field == "model") {
                if (value.empty()) {
                    out << prefix << ".model = " << (byok.model.empty() ? "(default)" : byok.model) << "\n";
                } else {
                    byok.model = value;
                    SaveAgentSettings(settings);
                    out << prefix << ".model = " << value << " (saved)\n";
                }
                return {true, out.str(), 0};
            }
            if (field == "type") {
                if (value.empty()) {
                    out << prefix << ".type = " << (byok.provider_type.empty() ? "(default)" : byok.provider_type) << "\n";
                } else {
                    byok.provider_type = value;
                    SaveAgentSettings(settings);
                    out << prefix << ".type = " << value << " (saved)\n";
                }
                return {true, out.str(), 0};
            }
            return {false, "Error: Unknown BYOK field: " + field + "\n", 1};
        };

        if (parts.size() == 2) {
            // "agent.byok" - show all providers' BYOK status
            auto it_claude = settings.byok.find("claude");
            auto it_copilot = settings.byok.find("copilot");
            show_byok("claude", it_claude != settings.byok.end() ? &it_claude->second : nullptr);
            ss << "\n";
            show_byok("copilot", it_copilot != settings.byok.end() ? &it_copilot->second : nullptr);
            return {true, ss.str(), 0};
        }

        std::string part2 = parts[2];

        // Check if part2 is a provider name (claude/copilot) or a field name
        if (part2 == "claude" || part2 == "copilot") {
            // agent.byok.<provider> or agent.byok.<provider>.<field>
            std::string target_provider = part2;

            if (parts.size() == 3) {
                // "agent.byok.copilot" - show this provider's BYOK
                auto it = settings.byok.find(target_provider);
                show_byok(target_provider, it != settings.byok.end() ? &it->second : nullptr);
                return {true, ss.str(), 0};
            }

            if (parts.size() == 4) {
                // "agent.byok.copilot.<field>" - get/set field
                std::string field = parts[3];
                auto& byok = settings.byok[target_provider];
                return handle_byok_field(byok, field, "agent.byok." + target_provider);
            }
        } else {
            // agent.byok.<field> - uses current provider
            auto& byok = settings.get_or_create_byok();
            return handle_byok_field(byok, part2, "agent.byok");
        }

        return {false, "Error: Unknown config path: " + path + "\n", 1};
    }

    return {false, "Error: Unknown config path: " + path + "\nUse --config to see available options.\n", 1};

#else
    return {false, "Error: AI agent not compiled in. Rebuild with -DIDASQL_WITH_AI_AGENT=ON\n", 1};
#endif
}

} // namespace idasql
