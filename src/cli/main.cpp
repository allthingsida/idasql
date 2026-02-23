#include <idasql/platform.hpp>

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <cstring>
#include <cctype>
#include <vector>
#include <algorithm>
#include <csignal>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <thread>
#include <chrono>
#include <memory>

// Windows UTF-8 console support
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <xsql/thinclient/server.hpp>
#include "../common/http_server.hpp"

#include "../common/idasql_version.hpp"

// AI Agent integration (optional, enabled via IDASQL_WITH_AI_AGENT)
#ifdef IDASQL_HAS_AI_AGENT
#include "../common/ai_agent.hpp"
#include "../common/idasql_commands.hpp"
#include "../common/mcp_server.hpp"

// Global signal handler state
namespace {
    std::atomic<bool> g_quit_requested{false};
    idasql::AIAgent* g_agent = nullptr;
    std::unique_ptr<idasql::IDAMCPServer> g_mcp_server;
    std::unique_ptr<idasql::AIAgent> g_mcp_agent;
    std::unique_ptr<idasql::IDAHTTPServer> g_repl_http_server;
}

extern "C" void signal_handler(int sig) {
    (void)sig;
    g_quit_requested.store(true);
    if (g_agent) {
        g_agent->request_quit();
    }
}
#endif

// ============================================================================
// Table Printing (shared between remote and local modes)
// ============================================================================

// Table-style output
struct TablePrinter {
    std::vector<std::string> columns;
    std::vector<std::vector<std::string>> rows;
    std::vector<size_t> widths;
    bool first_row = true;

    void add_row(const std::vector<std::string>& cols,
                 const std::vector<std::string>& values) {
        if (first_row) {
            columns = cols;
            widths.assign(columns.size(), 0);
            for (size_t i = 0; i < columns.size(); i++) {
                widths[i] = (std::max)(widths[i], columns[i].length());
            }
            first_row = false;
        }

        std::vector<std::string> row = values;
        if (row.size() < columns.size()) {
            row.resize(columns.size());
        }
        for (size_t i = 0; i < row.size(); i++) {
            widths[i] = (std::max)(widths[i], row[i].length());
        }
        rows.push_back(std::move(row));
    }

    void print() {
        if (columns.empty()) return;

        // Header separator
        std::string sep = "+";
        for (size_t w : widths) {
            sep += std::string(w + 2, '-') + "+";
        }

        // Header
        std::cout << sep << "\n| ";
        for (size_t i = 0; i < columns.size(); i++) {
            std::cout << std::left;
            std::cout.width(widths[i]);
            std::cout << columns[i] << " | ";
        }
        std::cout << "\n" << sep << "\n";

        // Rows
        for (const auto& row : rows) {
            std::cout << "| ";
            for (size_t i = 0; i < row.size(); i++) {
                std::cout << std::left;
                std::cout.width(widths[i]);
                std::cout << row[i] << " | ";
            }
            std::cout << "\n";
        }
        std::cout << sep << "\n";
        std::cout << rows.size() << " row(s)\n";
    }
};

// ============================================================================ 
// Validation Helpers
// ============================================================================ 

static bool is_safe_table_name(const std::string& name) {
    if (name.empty() || name.size() > 128) return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '_';
    });
}

// ============================================================================
// Local Mode - Uses IDA SDK (delay-loaded on Windows)
// ============================================================================
// From here on, code may call IDA functions. On Windows with /DELAYLOAD,
// ida.dll and idalib.dll are loaded on first use.
//
// Platform-specific include order:
// - Windows: json before IDA (IDA poisons stdlib functions)
// - macOS/Linux: IDA before json
#include <idasql/platform_undef.hpp>

#ifdef _WIN32
#include <xsql/json.hpp>
#include <idasql/database.hpp>
#else
#include <idasql/database.hpp>
#include <xsql/json.hpp>
#endif

static void add_query_result_rows(TablePrinter& printer, const idasql::QueryResult& result) {
    for (const auto& row : result.rows) {
        printer.add_row(result.columns, row.values);
    }
}

static void print_query_warnings(std::ostream& os, const idasql::QueryResult& result) {
    for (const auto& warning : result.warnings) {
        os << "Warning: " << warning << "\n";
    }
    if (result.timed_out) {
        os << "Warning: query timed out";
        if (result.elapsed_ms > 0) {
            os << " after " << result.elapsed_ms << " ms";
        }
        if (result.partial) {
            os << " (partial rows returned)";
        }
        os << "\n";
    }
}

// ============================================================================
// REPL - Interactive Mode (Local)
// ============================================================================

static void show_help() {
    std::cout << R"(
Commands:
  .tables             List all tables
  .schema [table]     Show table schema
  .info               Show database info
  .clear              Clear session (reset conversation)
  .quit / .exit       Exit interactive mode
  .help               Show this help

SQL queries end with semicolon (;)
Multi-line queries are supported.
)" << std::endl;
}

static void show_tables(idasql::Database& db) {
    auto result = db.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;");
    if (!result.success) {
        std::cerr << "Error: " << db.error() << "\n";
        return;
    }

    std::cout << "Tables:\n";
    for (const auto& row : result.rows) {
        std::cout << "  " << (row.size() > 0 ? row[0] : "") << "\n";
    }
}

static void show_schema(idasql::Database& db, const std::string& table) {
    if (!is_safe_table_name(table)) {
        std::cerr << "Invalid table name\n";
        return;
    }

    std::string sql = "SELECT sql FROM sqlite_master WHERE type='table' AND name='" + table + "';";
    auto result = db.query(sql);
    if (!result.success) {
        std::cerr << "Error: " << db.error() << "\n";
        return;
    }
    if (!result.rows.empty() && result.rows[0].size() > 0) {
        std::cout << result.rows[0][0] << "\n";
    } else {
        std::cout << "Not found\n";
    }
}

// Helper to execute SQL and format results as string (for AI agent)
static std::string execute_sql_to_string(idasql::Database& db, const std::string& sql) {
    auto result = db.query(sql);
    if (!result.success) {
        return "Error: " + std::string(db.error());
    }

    std::stringstream ss;
    TablePrinter printer;
    add_query_result_rows(printer, result);

    // Capture to string instead of stdout
    std::streambuf* old_cout = std::cout.rdbuf(ss.rdbuf());
    printer.print();
    print_query_warnings(std::cout, result);
    std::cout.rdbuf(old_cout);
    return ss.str();
}

// Forward declaration (defined in HTTP section below)
static std::string query_result_to_json(idasql::Database& db, const std::string& sql);

#ifdef IDASQL_HAS_AI_AGENT
static void run_repl(idasql::Database& db, bool agent_mode, bool verbose,
                     const std::string& provider_override = "") {
#else
static void run_repl(idasql::Database& db) {
    [[maybe_unused]] bool agent_mode = false;
#endif
    std::string line;
    std::string query;

#ifdef IDASQL_HAS_AI_AGENT
    std::unique_ptr<idasql::AIAgent> agent;
    if (agent_mode) {
        auto executor = [&db](const std::string& sql) -> std::string {
            return execute_sql_to_string(db, sql);
        };

        // Load settings (includes BYOK, provider, timeout)
        idasql::AgentSettings settings = idasql::LoadAgentSettings();

        // Apply provider override from CLI if specified
        if (!provider_override.empty()) {
            try {
                settings.default_provider = idasql::ParseProviderType(provider_override);
            } catch (...) {
                // Already validated in argument parsing
            }
        }

        agent = std::make_unique<idasql::AIAgent>(executor, settings, verbose);

        // Register signal handler for clean Ctrl-C handling
        g_agent = agent.get();
        std::signal(SIGINT, signal_handler);
#ifdef _WIN32
        // Windows also needs SIGBREAK for Ctrl-Break
        std::signal(SIGBREAK, signal_handler);
#endif

        agent->start();  // Initialize agent

        std::cout << "IDASQL AI Agent Mode\n"
                  << "Ask questions in natural language or use SQL directly.\n"
                  << "Type .help for commands, .clear to reset, .quit to exit\n\n";
    } else {
#endif
        std::cout << "IDASQL Interactive Mode\n"
                  << "Type .help for commands, .clear to reset, .quit to exit\n\n";
#ifdef IDASQL_HAS_AI_AGENT
    }
#endif

    while (true) {
#ifdef IDASQL_HAS_AI_AGENT
        // Check for quit request from signal handler
        if (g_quit_requested.load()) {
            std::cout << "\nInterrupted.\n";
            break;
        }
#endif

        // Prompt
        std::cout << (query.empty() ? "idasql> " : "   ...> ");
        std::cout.flush();

        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        // Handle dot commands
        if (query.empty() && !line.empty() && line[0] == '.') {
#ifdef IDASQL_HAS_AI_AGENT
            // Use unified command handler for agent mode
            idasql::CommandCallbacks callbacks;
            callbacks.get_tables = [&db]() -> std::string {
                std::stringstream ss;
                auto result = db.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
                for (const auto& row : result.rows) {
                    if (row.size() > 0) ss << row[0] << "\n";
                }
                return ss.str();
            };
            callbacks.get_schema = [&db](const std::string& table) -> std::string {
                auto result = db.query("SELECT sql FROM sqlite_master WHERE name='" + table + "'");
                if (!result.empty() && result.rows[0].size() > 0) {
                    return std::string(result.rows[0][0]);
                }
                return "Table not found: " + table;
            };
            callbacks.get_info = [&db]() -> std::string {
                return db.info();
            };
            callbacks.clear_session = [&agent]() -> std::string {
                if (agent) {
                    agent->reset_session();
                    return "Session cleared (conversation history reset)";
                }
                return "Session cleared";
            };

            // MCP server callbacks
            callbacks.mcp_status = []() -> std::string {
                if (g_mcp_server && g_mcp_server->is_running()) {
                    return idasql::format_mcp_status(g_mcp_server->port(), true);
                } else {
                    return "MCP server not running\nUse '.mcp start' to start\n";
                }
            };

            callbacks.mcp_start = [&db, &agent](int req_port, const std::string& bind_addr) -> std::string {
                if (g_mcp_server && g_mcp_server->is_running()) {
                    return idasql::format_mcp_status(g_mcp_server->port(), true);
                }

                // Create MCP server if needed
                if (!g_mcp_server) {
                    g_mcp_server = std::make_unique<idasql::IDAMCPServer>();
                }

                // SQL executor - will be called on main thread via wait()
                idasql::QueryCallback sql_cb = [&db](const std::string& sql) -> std::string {
                    auto result = db.query(sql);
                    if (result.success) {
                        return result.to_string();
                    }
                    return "Error: " + result.error;
                };

                // Create MCP agent for natural language queries
                g_mcp_agent = std::make_unique<idasql::AIAgent>(sql_cb);
                g_mcp_agent->start();

                idasql::AskCallback ask_cb = [](const std::string& question) -> std::string {
                    if (!g_mcp_agent) return "Error: AI agent not available";
                    return g_mcp_agent->query(question);
                };

                // Start with use_queue=true for CLI mode (main thread execution)
                int port = g_mcp_server->start(req_port, sql_cb, ask_cb, bind_addr, true);
                if (port <= 0) {
                    g_mcp_agent.reset();
                    return "Error: Failed to start MCP server\n";
                }

                // Print info
                std::cout << idasql::format_mcp_info(port, true);
                std::cout << "Press Ctrl+C to stop MCP server and return to REPL...\n\n";
                std::cout.flush();

                // Install signal handler so Ctrl+C sets g_quit_requested
                g_quit_requested.store(false);
                auto old_handler = std::signal(SIGINT, signal_handler);
#ifdef _WIN32
                auto old_break_handler = std::signal(SIGBREAK, signal_handler);
#endif

                // Set interrupt check to stop on Ctrl+C
                g_mcp_server->set_interrupt_check([]() {
                    return g_quit_requested.load();
                });

                // Enter wait loop - processes MCP commands on main thread
                // This blocks until Ctrl+C or .mcp stop via another client
                g_mcp_server->run_until_stopped();

                // Restore previous signal handler
                std::signal(SIGINT, old_handler);
#ifdef _WIN32
                std::signal(SIGBREAK, old_break_handler);
#endif
                g_mcp_agent.reset();
                g_quit_requested.store(false);  // Reset for continued REPL use

                return "MCP server stopped. Returning to REPL.\n";
            };

            callbacks.mcp_stop = []() -> std::string {
                if (g_mcp_server && g_mcp_server->is_running()) {
                    g_mcp_server->stop();
                    g_mcp_agent.reset();
                    return "MCP server stopped\n";
                }
                return "MCP server not running\n";
            };

            // HTTP server callbacks
            callbacks.http_status = []() -> std::string {
                if (g_repl_http_server && g_repl_http_server->is_running()) {
                    return idasql::format_http_status(g_repl_http_server->port(), true);
                }
                return "HTTP server not running\nUse '.http start' to start\n";
            };

            callbacks.http_start = [&db](int req_port, const std::string& bind_addr) -> std::string {
                if (g_repl_http_server && g_repl_http_server->is_running()) {
                    return idasql::format_http_status(g_repl_http_server->port(), true);
                }

                // Create HTTP server if needed
                if (!g_repl_http_server) {
                    g_repl_http_server = std::make_unique<idasql::IDAHTTPServer>();
                }

                // SQL executor - called on main thread via run_until_stopped()
                idasql::HTTPQueryCallback sql_cb = [&db](const std::string& sql) -> std::string {
                    return query_result_to_json(db, sql);
                };

                // Start with use_queue=true (CLI mode)
                int port = g_repl_http_server->start(req_port, sql_cb, bind_addr, true);
                if (port <= 0) {
                    return "Error: Failed to start HTTP server\n";
                }

                // Print info
                std::cout << idasql::format_http_info(port);
                std::cout.flush();

                // Install signal handler so Ctrl+C sets g_quit_requested
                g_quit_requested.store(false);
                auto old_handler = std::signal(SIGINT, signal_handler);
#ifdef _WIN32
                auto old_break_handler = std::signal(SIGBREAK, signal_handler);
#endif

                // Set interrupt check to stop on Ctrl+C
                g_repl_http_server->set_interrupt_check([]() {
                    return g_quit_requested.load();
                });

                // Enter wait loop - processes HTTP commands on main thread
                // This blocks until Ctrl+C or /shutdown
                g_repl_http_server->run_until_stopped();

                // Restore previous signal handler
                std::signal(SIGINT, old_handler);
#ifdef _WIN32
                std::signal(SIGBREAK, old_break_handler);
#endif
                g_quit_requested.store(false);  // Reset for continued REPL use

                return "HTTP server stopped. Returning to REPL.\n";
            };

            callbacks.http_stop = []() -> std::string {
                if (g_repl_http_server && g_repl_http_server->is_running()) {
                    g_repl_http_server->stop();
                    return "HTTP server stopped\n";
                }
                return "HTTP server not running\n";
            };

            std::string output;
            auto result = idasql::handle_command(line, callbacks, output);

            switch (result) {
                case idasql::CommandResult::QUIT:
                    goto exit_repl;  // Exit the while loop
                case idasql::CommandResult::HANDLED:
                    if (!output.empty()) {
                        std::cout << output;
                        if (output.back() != '\n') std::cout << "\n";
                    }
                    continue;
                case idasql::CommandResult::NOT_HANDLED:
                    // Fall through to standard handling
                    break;
            }
#else
            // Non-agent mode: basic command handling
            if (line == ".quit" || line == ".exit") break;
            if (line == ".tables") { show_tables(db); continue; }
            if (line == ".info") { std::cout << db.info(); continue; }
            if (line == ".help") { show_help(); continue; }
            if (line == ".clear") {
                std::cout << "Session cleared\n";
                continue;
            }
            if (line.substr(0, 7) == ".schema") {
                std::string table = line.length() > 8 ? line.substr(8) : "";
                while (!table.empty() && table[0] == ' ') table = table.substr(1);
                if (table.empty()) {
                    std::cerr << "Usage: .schema <table_name>\n";
                } else {
                    show_schema(db, table);
                }
                continue;
            }
            std::cerr << "Unknown command: " << line << "\n";
            continue;
#endif
        }

#ifdef IDASQL_HAS_AI_AGENT
        // In agent mode, use query for main-thread safety
        if (agent_mode && agent) {
            std::string result = agent->query(line);
            if (!result.empty()) {
                std::cout << result << "\n";
            }

            // Check if we were interrupted
            if (agent->quit_requested()) {
                std::cout << "Interrupted.\n";
                break;
            }
            continue;
        }
#endif

        // Standard SQL mode: accumulate query
        query += line + " ";

        // Execute if complete (ends with ;)
        size_t last = line.length() - 1;
        while (last > 0 && (line[last] == ' ' || line[last] == '\t')) last--;
        if (line[last] == ';') {
            auto result = db.query(query);
            if (result.success) {
                TablePrinter printer;
                add_query_result_rows(printer, result);
                printer.print();
                print_query_warnings(std::cout, result);
            } else {
                std::cerr << "Error: " << db.error() << "\n";
            }
            query.clear();
        }
    }

#ifdef IDASQL_HAS_AI_AGENT
exit_repl:
    if (agent) {
        agent->stop();
        g_agent = nullptr;
    }
    // Restore default signal handler
    std::signal(SIGINT, SIG_DFL);
#endif
}

// ============================================================================
// Export to SQL
// ============================================================================

// Parse table list from string (comma or semicolon separated)
static std::vector<std::string> parse_table_list(const std::string& spec) {
    std::vector<std::string> tables;
    std::string current;
    for (char c : spec) {
        if (c == ',' || c == ';') {
            if (!current.empty()) {
                tables.push_back(current);
                current.clear();
            }
        } else if (c != ' ' && c != '\t') {
            current += c;
        }
    }
    if (!current.empty()) {
        tables.push_back(current);
    }
    return tables;
}

// Export tables to SQL file
static bool export_to_sql(idasql::Database& db, const char* path,
                          const std::string& table_spec) {
    std::vector<std::string> tables;
    if (!(table_spec.empty() || table_spec == "*")) {
        tables = parse_table_list(table_spec);
    }

    std::string error;
    if (!db.export_tables(tables, path, error)) {
        std::cerr << "Error: " << error << "\n";
        return false;
    }

    std::cerr << "Export complete: " << path << "\n";
    return true;
}

// ============================================================================
// File Execution
// ============================================================================

static bool execute_file(idasql::Database& db, const char* path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Cannot open file: " << path << "\n";
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    std::vector<xsql::StatementResult> results;
    std::string error;
    if (!db.execute_script(content, results, error)) {
        std::cerr << "Error: " << error << "\n";
        return false;
    }

    for (const auto& res : results) {
        if (res.columns.empty()) {
            continue;
        }
        TablePrinter printer;
        for (const auto& row : res.rows) {
            printer.add_row(res.columns, row);
        }
        printer.print();
        std::cout << "\n";
    }

    return true;
}

// ============================================================================
// HTTP Server Mode
// ============================================================================

static xsql::thinclient::server* g_http_server = nullptr;
static std::atomic<bool> g_http_stop_requested{false};

static void http_signal_handler(int) {
    g_http_stop_requested.store(true);
    if (g_http_server) g_http_server->stop();
}

// Command queue for main-thread execution (needed for Hex-Rays decompiler)
struct HttpPendingCommand {
    std::string sql;
    std::string result;
    bool started = false;
    bool canceled = false;
    bool completed = false;
    std::mutex done_mutex;
    std::condition_variable done_cv;
};

static std::mutex g_http_queue_mutex;
static std::condition_variable g_http_queue_cv;
static std::deque<std::shared_ptr<HttpPendingCommand>> g_http_pending_commands;
static std::atomic<bool> g_http_running{false};

// Queue a command and wait for main thread to execute it
static std::string http_queue_and_wait(const std::string& sql) {
    if (!g_http_running.load()) {
        return xsql::json{{"success", false}, {"error", "Server not running"}}.dump();
    }

    auto cmd = std::make_shared<HttpPendingCommand>();
    cmd->sql = sql;
    cmd->completed = false;

    {
        std::lock_guard<std::mutex> lock(g_http_queue_mutex);
        const size_t max_queue = idasql::runtime_settings().max_queue();
        if (max_queue > 0 && g_http_pending_commands.size() >= max_queue) {
            return xsql::json{
                {"success", false},
                {"error", "Queue full"},
                {"hint", "Raise PRAGMA idasql.max_queue or reduce request concurrency"}
            }.dump();
        }
        g_http_pending_commands.push_back(cmd);
    }
    g_http_queue_cv.notify_one();

    // Wait for completion (or queue admission timeout).
    const int timeout_ms = idasql::runtime_settings().queue_admission_timeout_ms();
    std::unique_lock<std::mutex> lock(cmd->done_mutex);
    if (timeout_ms <= 0) {
        while (!cmd->completed) {
            cmd->done_cv.wait_for(lock, std::chrono::milliseconds(100));
        }
    } else {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (!cmd->completed) {
            if (cmd->started) {
                cmd->done_cv.wait_for(lock, std::chrono::milliseconds(100));
                continue;
            }

            if (cmd->done_cv.wait_until(lock, deadline,
                                        [&]() { return cmd->completed || cmd->started; })) {
                continue;
            }

            // Timed out before command admission: mark canceled and remove from pending queue.
            if (!cmd->completed && !cmd->started) {
                cmd->canceled = true;
            }
            lock.unlock();
            {
                std::lock_guard<std::mutex> qlock(g_http_queue_mutex);
                auto it = std::find(g_http_pending_commands.begin(), g_http_pending_commands.end(), cmd);
                if (it != g_http_pending_commands.end()) {
                    g_http_pending_commands.erase(it);
                }
            }

            return xsql::json{
                {"success", false},
                {"error", "Request timed out while waiting in queue"},
                {"hint", "Raise PRAGMA idasql.queue_admission_timeout_ms or reduce request concurrency"}
            }.dump();
        }
    }

    return cmd->result;
}

static std::string query_result_to_json(idasql::Database& db, const std::string& sql) {
    auto result = db.query(sql);
    xsql::json j = {{"success", result.success}};

    if (result.success) {
        j["columns"] = result.columns;

        xsql::json rows = xsql::json::array();
        for (const auto& row : result.rows) {
            rows.push_back(row.values);  // Row::values is std::vector<std::string>
        }
        j["rows"] = rows;
        j["row_count"] = result.rows.size();
        if (!result.warnings.empty()) {
            j["warnings"] = result.warnings;
        }
        if (result.timed_out) {
            j["timed_out"] = true;
        }
        if (result.partial) {
            j["partial"] = true;
        }
        if (result.elapsed_ms > 0) {
            j["elapsed_ms"] = result.elapsed_ms;
        }
    } else {
        j["error"] = result.error;
    }

    return j.dump();
}

static const char* IDASQL_HELP_TEXT = R"(IDASQL HTTP REST API
====================

SQL interface for IDA Pro databases via HTTP.

Endpoints:
  GET  /         - Welcome message
  GET  /help     - This documentation (for LLM discovery)
  POST /query    - Execute SQL (body = raw SQL, response = JSON)
  GET  /status   - Server health
  POST /shutdown - Stop server

Tables:
  funcs           - Functions with address, size, flags
  segments        - Segment/section information
  imports         - Imported functions
  exports         - Exported functions
  names           - Named locations
  strings         - String references
  comments        - User comments
  xrefs           - Cross references
  structs         - Structure definitions
  struct_members  - Structure members
  enums           - Enumeration definitions
  enum_members    - Enumeration values
  localvars       - Local variables (requires Hex-Rays)
  pseudocode      - Decompiled pseudocode (requires Hex-Rays)

Example Queries:
  SELECT name, start_ea, size FROM funcs ORDER BY size DESC LIMIT 10;
  SELECT * FROM imports WHERE name LIKE '%malloc%';
  SELECT s.name, COUNT(*) FROM structs s JOIN struct_members m ON s.id = m.struct_id GROUP BY s.id;

Response Format:
  Success: {"success": true, "columns": [...], "rows": [[...]], "row_count": N}
  Error:   {"success": false, "error": "message"}

Authentication (if enabled):
  Header: Authorization: Bearer <token>
  Or:     X-XSQL-Token: <token>

Example:
  curl http://localhost:8081/help
  curl -X POST http://localhost:8081/query -d "SELECT name FROM funcs LIMIT 5"
)";

static int run_http_mode(idasql::Database& db, int port, const std::string& bind_addr, const std::string& auth_token) {
    xsql::thinclient::server_config cfg;
    cfg.port = port;
    cfg.bind_address = bind_addr.empty() ? "127.0.0.1" : bind_addr;
    if (!auth_token.empty()) cfg.auth_token = auth_token;
    // Allow non-loopback binds if explicitly requested (with warning)
    if (!bind_addr.empty() && bind_addr != "127.0.0.1" && bind_addr != "localhost") {
        cfg.allow_insecure_no_auth = auth_token.empty();
        std::cerr << "WARNING: Binding to non-loopback address " << bind_addr << "\n";
        if (auth_token.empty()) {
            std::cerr << "WARNING: No authentication token set. Server is accessible without authentication.\n";
            std::cerr << "         Consider using --token <secret> for remote access.\n";
        }
    }

    cfg.setup_routes = [&auth_token, port](httplib::Server& svr) {
        svr.Get("/", [port](const httplib::Request&, httplib::Response& res) {
            std::string welcome = "IDASQL HTTP Server\n\nEndpoints:\n"
                "  GET  /help     - API documentation\n"
                "  POST /query    - Execute SQL query\n"
                "  GET  /status   - Health check\n"
                "  POST /shutdown - Stop server\n\n"
                "Example: curl -X POST http://localhost:" + std::to_string(port) + "/query -d \"SELECT name FROM funcs LIMIT 5\"\n";
            res.set_content(welcome, "text/plain");
        });

        svr.Get("/help", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(IDASQL_HELP_TEXT, "text/plain");
        });

        // POST /query - Queue command for main thread execution
        // This is necessary because IDA's Hex-Rays decompiler has thread affinity
        svr.Post("/query", [&auth_token](const httplib::Request& req, httplib::Response& res) {
            if (!auth_token.empty()) {
                std::string token;
                if (req.has_header("X-XSQL-Token")) token = req.get_header_value("X-XSQL-Token");
                else if (req.has_header("Authorization")) {
                    auto auth = req.get_header_value("Authorization");
                    if (auth.rfind("Bearer ", 0) == 0) token = auth.substr(7);
                }
                if (token != auth_token) {
                    res.status = 401;
                    res.set_content(xsql::json{{"success", false}, {"error", "Unauthorized"}}.dump(), "application/json");
                    return;
                }
            }
            if (req.body.empty()) {
                res.status = 400;
                res.set_content(xsql::json{{"success", false}, {"error", "Empty query"}}.dump(), "application/json");
                return;
            }
            // Queue command for main thread execution
            res.set_content(http_queue_and_wait(req.body), "application/json");
        });

        // GET /status - Also needs main thread for db.query()
        svr.Get("/status", [&auth_token](const httplib::Request& req, httplib::Response& res) {
            if (!auth_token.empty()) {
                std::string token;
                if (req.has_header("X-XSQL-Token")) token = req.get_header_value("X-XSQL-Token");
                else if (req.has_header("Authorization")) {
                    auto auth = req.get_header_value("Authorization");
                    if (auth.rfind("Bearer ", 0) == 0) token = auth.substr(7);
                }
                if (token != auth_token) {
                    res.status = 401;
                    res.set_content(xsql::json{{"success", false}, {"error", "Unauthorized"}}.dump(), "application/json");
                    return;
                }
            }
            // Queue for main thread
            std::string result = http_queue_and_wait("SELECT COUNT(*) FROM funcs");
            // Parse result to extract count
            try {
                auto j = xsql::json::parse(result);
                if (j.value("success", false) && j.contains("rows") && !j["rows"].empty()) {
                    int count = std::stoi(j["rows"][0][0].get<std::string>());
                    res.set_content(xsql::json{{"success", true}, {"status", "ok"}, {"tool", "idasql"}, {"functions", count}}.dump(), "application/json");
                    return;
                }
            } catch (...) {}
            res.set_content(xsql::json{{"success", true}, {"status", "ok"}, {"tool", "idasql"}, {"functions", "?"}}.dump(), "application/json");
        });

        svr.Post("/shutdown", [&svr, &auth_token](const httplib::Request& req, httplib::Response& res) {
            if (!auth_token.empty()) {
                std::string token;
                if (req.has_header("X-XSQL-Token")) token = req.get_header_value("X-XSQL-Token");
                else if (req.has_header("Authorization")) {
                    auto auth = req.get_header_value("Authorization");
                    if (auth.rfind("Bearer ", 0) == 0) token = auth.substr(7);
                }
                if (token != auth_token) {
                    res.status = 401;
                    res.set_content(xsql::json{{"success", false}, {"error", "Unauthorized"}}.dump(), "application/json");
                    return;
                }
            }
            res.set_content(xsql::json{{"success", true}, {"message", "Shutting down"}}.dump(), "application/json");
            g_http_stop_requested.store(true);
            g_http_queue_cv.notify_all();
            std::thread([&svr] {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                svr.stop();
            }).detach();
        });
    };

    xsql::thinclient::server http_server(cfg);
    g_http_server = &http_server;
    g_http_running.store(true);
    g_http_stop_requested.store(false);

    auto old_handler = std::signal(SIGINT, http_signal_handler);
#ifdef _WIN32
    auto old_break_handler = std::signal(SIGBREAK, http_signal_handler);
#else
    auto old_term_handler = std::signal(SIGTERM, http_signal_handler);
#endif

    // Start HTTP server on a background thread (resolves random port)
    http_server.run_async();
    int actual_port = http_server.port();

    std::cout << "IDASQL HTTP server listening on http://" << cfg.bind_address << ":" << actual_port << "\n";
    std::cout << "Database: " << db.info() << "\n";
    std::cout << "Endpoints: /help, /query, /status, /shutdown\n";
    std::cout << "Example: curl http://localhost:" << actual_port << "/help\n";
    std::cout << "Press Ctrl+C to stop.\n\n";
    std::cout.flush();

    // Main thread processes the command queue (required for Hex-Rays thread affinity)
    while (g_http_running.load() && !g_http_stop_requested.load()) {
        std::shared_ptr<HttpPendingCommand> cmd;

        {
            std::unique_lock<std::mutex> lock(g_http_queue_mutex);
            if (g_http_queue_cv.wait_for(lock, std::chrono::milliseconds(100),
                                          []() { return !g_http_pending_commands.empty() ||
                                                        g_http_stop_requested.load(); })) {
                if (!g_http_pending_commands.empty()) {
                    cmd = g_http_pending_commands.front();
                    g_http_pending_commands.pop_front();
                }
            }
        }

        if (cmd) {
            bool should_execute = false;
            {
                std::lock_guard<std::mutex> lock(cmd->done_mutex);
                if (!cmd->completed && !cmd->canceled) {
                    cmd->started = true;
                    should_execute = true;
                } else if (!cmd->completed && cmd->canceled) {
                    cmd->completed = true;
                }
            }

            if (should_execute) {
                // Execute query on main thread - safe for Hex-Rays decompiler
                std::string result = query_result_to_json(db, cmd->sql);
                {
                    std::lock_guard<std::mutex> lock(cmd->done_mutex);
                    cmd->result = std::move(result);
                    cmd->completed = true;
                }
            }

            cmd->done_cv.notify_one();
        }
    }

    // Cleanup
    g_http_running.store(false);
    g_http_queue_cv.notify_all();

    // Complete any pending commands with error
    std::deque<std::shared_ptr<HttpPendingCommand>> pending;
    {
        std::lock_guard<std::mutex> lock(g_http_queue_mutex);
        pending.swap(g_http_pending_commands);
    }
    while (!pending.empty()) {
        auto cmd = pending.front();
        pending.pop_front();
        if (!cmd) continue;
        {
            std::lock_guard<std::mutex> dlock(cmd->done_mutex);
            if (!cmd->completed) {
                cmd->result = xsql::json{{"success", false}, {"error", "Server stopped"}}.dump();
                cmd->completed = true;
            }
        }
        cmd->done_cv.notify_one();
    }

    // Stop HTTP server (run_async thread joined internally)
    http_server.stop();

    std::signal(SIGINT, old_handler);
#ifdef _WIN32
    std::signal(SIGBREAK, old_break_handler);
#else
    std::signal(SIGTERM, old_term_handler);
#endif
    g_http_server = nullptr;
    std::cout << "\nHTTP server stopped.\n";
    return 0;
}

// ============================================================================
// Main
// ============================================================================

static void print_usage() {
    std::cerr << "idasql v" IDASQL_VERSION_STRING " - SQL interface to IDA databases\n\n"
              << "Usage: idasql -s <database> [-q <query>] [-f <file>] [-i] [--export <file>]\n\n"
              << "Options:\n"
              << "  -s <file>            IDA database file (.idb/.i64) for local mode\n"
              << "  --token <token>      Auth token for HTTP/MCP server mode (if server requires it)\n"
              << "  -q <sql>             Execute single SQL query\n"
              << "  -f <file>            Execute SQL from file\n"
              << "  -i                   Interactive REPL mode\n"
              << "  -w, --write          Save database on exit (persist changes)\n"
              << "  --export <file>      Export tables to SQL file (local mode only)\n"
              << "  --export-tables=X    Tables to export: * (all, default) or table1,table2,...\n"
              << "  --http [port]        Start HTTP REST server (default: 8080, local mode only)\n"
              << "  --bind <addr>        Bind address for HTTP/MCP server (default: 127.0.0.1)\n"
#ifdef IDASQL_HAS_AI_AGENT
              << "  --mcp [port]         Start MCP server (default: random port, use in -i mode)\n"
              << "                       Or use .mcp start in interactive mode\n"
#endif
#ifdef IDASQL_HAS_AI_AGENT
              << "  --prompt <text>      Natural language query (uses AI agent)\n"
              << "  --agent              Enable AI agent mode in interactive REPL\n"
              << "  --provider <name>    Override AI provider (claude, copilot)\n"
              << "  --config [path] [val] View/set agent configuration\n"
              << "  -v, --verbose        Show agent debug logs\n"
              << "\n"
              << "Agent settings stored in: ~/.idasql/agent_settings.json\n"
              << "Configure via: .agent provider, .agent byok, .agent timeout\n"
#endif
              << "  -h, --help           Show this help\n"
              << "  --version            Show version\n\n"
              << "Examples:\n"
              << "  idasql -s test.i64 -q \"SELECT name, size FROM funcs LIMIT 10\"\n"
              << "  idasql -s test.i64 -f queries.sql\n"
              << "  idasql -s test.i64 -i\n"
              << "  idasql -s test.i64 --export dump.sql\n"
              << "  idasql -s test.i64 --http 8080\n"
#ifdef IDASQL_HAS_AI_AGENT
              << "  idasql -s test.i64 --prompt \"Find the largest functions\"\n"
              << "  idasql -s test.i64 -i --agent\n"
              << "  idasql -s test.i64 --provider copilot --prompt \"How many functions?\"\n"
#endif
              << "  idasql -s test.i64 --mcp 9000\n";
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Enable UTF-8 output on Windows console for proper Unicode display
    SetConsoleOutputCP(CP_UTF8);
#endif

    // Check for help/version first - before any IDA initialization
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        }
        if (strcmp(argv[i], "--version") == 0) {
            std::cout << "idasql v" IDASQL_VERSION_STRING "\n";
            return 0;
        }
    }

    std::string db_path;
    std::string query;
    std::string sql_file;
    std::string export_file;
    std::string export_tables = "*";  // Default: all tables
    std::string auth_token;           // --token for HTTP/MCP mode
    std::string bind_addr;            // --bind for HTTP/MCP mode
    bool interactive = false;
    bool write_mode = false;          // -w/--write to save on exit
    bool http_mode = false;
    int http_port = 8080;
    bool mcp_mode = false;
    int mcp_port = 0;                 // 0 = random port
#ifdef IDASQL_HAS_AI_AGENT
    std::string nl_prompt;            // --prompt for natural language
    bool agent_mode = false;          // --agent for interactive mode
    bool verbose_mode = false;        // -v for verbose agent output
    std::string provider_override;    // --provider overrides stored setting
#endif

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-s") == 0) && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            auth_token = argv[++i];
        } else if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            query = argv[++i];
        } else if ((strcmp(argv[i], "-f") == 0) && i + 1 < argc) {
            sql_file = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0) {
            interactive = true;
        } else if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--write") == 0) {
            write_mode = true;
        } else if (strcmp(argv[i], "--export") == 0 && i + 1 < argc) {
            export_file = argv[++i];
        } else if (strncmp(argv[i], "--export-tables=", 16) == 0) {
            export_tables = argv[i] + 16;
#ifdef IDASQL_HAS_AI_AGENT
        } else if (strcmp(argv[i], "--prompt") == 0 && i + 1 < argc) {
            nl_prompt = argv[++i];
        } else if (strcmp(argv[i], "--agent") == 0) {
            agent_mode = true;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose_mode = true;
        } else if (strcmp(argv[i], "--provider") == 0 && i + 1 < argc) {
            provider_override = argv[++i];
            // Validate provider name
            if (provider_override != "copilot" && provider_override != "Copilot" &&
                provider_override != "claude" && provider_override != "Claude") {
                std::cerr << "Unknown provider: " << provider_override << "\n";
                std::cerr << "Available providers: claude, copilot\n";
                return 1;
            }
        } else if (strcmp(argv[i], "--config") == 0) {
            // Handle --config [path] [value] and exit immediately
            std::string config_path = (i + 1 < argc && argv[i + 1][0] != '-') ? argv[++i] : "";
            std::string config_value = (i + 1 < argc && argv[i + 1][0] != '-') ? argv[++i] : "";
            auto [ok, output, code] = idasql::handle_config_command(config_path, config_value);
            std::cout << output;
            return code;
#endif
        } else if (strcmp(argv[i], "--http") == 0) {
            http_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                http_port = std::stoi(argv[++i]);
            }
        } else if (strcmp(argv[i], "--mcp") == 0) {
            mcp_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                mcp_port = std::stoi(argv[++i]);
            }
        } else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
            bind_addr = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            // Already handled above, but skip here to avoid "unknown option"
            continue;
        } else {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            print_usage();
            return 1;
        }
    }

    // Validate arguments
    if (db_path.empty()) {
        std::cerr << "Error: Database path required (-s)\n\n";
        print_usage();
        return 1;
    }

    bool has_action = !query.empty() || !sql_file.empty() || interactive || !export_file.empty() || http_mode || mcp_mode;
#ifdef IDASQL_HAS_AI_AGENT
    has_action = has_action || !nl_prompt.empty();
#endif
    if (!has_action) {
        std::cerr << "Error: Specify -q, -f, -i, --export, --http, --mcp"
#ifdef IDASQL_HAS_AI_AGENT
                  << ", or --prompt"
#endif
                  << "\n\n";
        print_usage();
        return 1;
    }

    //=========================================================================
    // Local mode - requires IDA SDK
    //=========================================================================
    std::cerr << "Opening: " << db_path << "..." << std::endl;
    idasql::Database db;
    if (!db.open(db_path.c_str())) {
        std::cerr << "Error: " << db.error() << std::endl;
        return 1;
    }
    std::cerr << "Database opened successfully." << std::endl;

    // HTTP server mode
    if (http_mode) {
        int http_result = run_http_mode(db, http_port, bind_addr, auth_token);
        db.close();
        return http_result;
    }

    // MCP server mode (standalone, not interactive REPL)
#ifdef IDASQL_HAS_AI_AGENT
    if (mcp_mode) {
        // SQL executor - will be called on main thread via wait()
        idasql::QueryCallback sql_cb = [&db](const std::string& sql) -> std::string {
            auto result = db.query(sql);
            if (result.success) {
                return result.to_string();
            }
            return "Error: " + result.error;
        };

        // Create MCP agent for natural language queries
        auto mcp_agent = std::make_unique<idasql::AIAgent>(sql_cb);
        mcp_agent->start();

        idasql::AskCallback ask_cb = [&mcp_agent](const std::string& question) -> std::string {
            if (!mcp_agent) return "Error: AI agent not available";
            return mcp_agent->query(question);
        };

        // Create and start MCP server with use_queue=true
        idasql::IDAMCPServer mcp_server;
        int port = mcp_server.start(mcp_port, sql_cb, ask_cb,
                                    bind_addr.empty() ? "127.0.0.1" : bind_addr, true);
        if (port <= 0) {
            std::cerr << "Error: Failed to start MCP server\n";
            db.close();
            return 1;
        }

        std::cout << idasql::format_mcp_info(port, true);
        std::cout << "Press Ctrl+C to stop...\n\n";
        std::cout.flush();

        // Set up signal handler
        g_quit_requested.store(false);
        std::signal(SIGINT, signal_handler);
#ifdef _WIN32
        std::signal(SIGBREAK, signal_handler);
#endif

        // Set interrupt check
        mcp_server.set_interrupt_check([]() {
            return g_quit_requested.load();
        });

        // Enter wait loop - processes MCP commands on main thread
        mcp_server.run_until_stopped();

        std::signal(SIGINT, SIG_DFL);
        mcp_agent->stop();
        std::cout << "\nMCP server stopped.\n";
        db.close();
        return 0;
    }
#else
    if (mcp_mode) {
        std::cerr << "Error: MCP mode not available. Rebuild with -DIDASQL_WITH_AI_AGENT=ON\n";
        db.close();
        return 1;
    }
#endif

    int result = 0;

    // Execute based on mode
    if (!export_file.empty()) {
        // Export mode
        if (!export_to_sql(db, export_file.c_str(), export_tables)) {
            result = 1;
        }
#ifdef IDASQL_HAS_AI_AGENT
    } else if (!nl_prompt.empty()) {
        // Natural language query mode (one-shot)
        auto executor = [&db](const std::string& sql) -> std::string {
            return execute_sql_to_string(db, sql);
        };

        // Load settings (includes BYOK, provider, timeout)
        idasql::AgentSettings settings = idasql::LoadAgentSettings();

        // Apply provider override from CLI if specified
        if (!provider_override.empty()) {
            try {
                settings.default_provider = idasql::ParseProviderType(provider_override);
            } catch (...) {
                // Already validated in argument parsing
            }
        }

        idasql::AIAgent agent(executor, settings, verbose_mode);

        // Register signal handler
        g_agent = &agent;
        std::signal(SIGINT, signal_handler);

        agent.start();
        std::string response = agent.query(nl_prompt);
        agent.stop();

        g_agent = nullptr;
        std::signal(SIGINT, SIG_DFL);

        std::cout << response << "\n";
#endif
    } else if (!query.empty()) {
        // Single query mode
        auto query_result = db.query(query);
        if (query_result.success) {
            TablePrinter printer;
            add_query_result_rows(printer, query_result);
            printer.print();
            print_query_warnings(std::cout, query_result);
        } else {
            std::cerr << "Error: " << db.error() << "\n";
            result = 1;
        }
    } else if (!sql_file.empty()) {
        // File execution mode
        if (!execute_file(db, sql_file.c_str())) {
            result = 1;
        }
    } else if (interactive) {
        // Interactive REPL
#ifdef IDASQL_HAS_AI_AGENT
        run_repl(db, agent_mode, verbose_mode, provider_override);
#else
        run_repl(db);
#endif
    }

    // Save database if -w/--write was specified
    if (write_mode) {
        if (save_database()) {
            std::cerr << "Database saved.\n";
        } else {
            std::cerr << "Warning: Failed to save database.\n";
        }
    }

    db.close();
    return result;
}
