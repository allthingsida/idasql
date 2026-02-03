/**
 * idasql CLI - Command-line SQL interface to IDA databases
 *
 * Usage:
 *   idasql -s database.i64 -q "SELECT * FROM funcs"     # Single query (local)
 *   idasql -s database.i64 -c "SELECT * FROM funcs"     # Same as -q (Python-style)
 *   idasql -s database.i64 -f script.sql                # Execute SQL file
 *   idasql -s database.i64 -i                           # Interactive mode
 *   idasql -s database.i64 --export out.sql             # Export all tables to SQL
 *   idasql -s database.i64 --export out.sql --export-tables=funcs,segments
 *   idasql --remote localhost:13337 -q "SELECT * FROM funcs"  # Remote mode
 *
 * Switches:
 *   -s <file>            IDA database file (.idb/.i64) for local mode
 *   --remote <host:port> Connect to IDASQL plugin server
 *   -q <sql>             Execute single SQL query
 *   -c <sql>             Execute single SQL query (alias for -q)
 *   -f <file>            Execute SQL from file
 *   -i                   Interactive REPL mode
 *   --export <file>      Export tables to SQL file (local only)
 *   --export-tables=...  Tables to export (* for all, or table1,table2,...)
 *   -h                   Show help
 *
 * Architecture Note:
 *   Remote mode (--remote) is a thin client that only uses sockets - no IDA
 *   functions are called. However, ida.dll must still be in PATH because the
 *   executable links against it (delayed loading is not possible due to
 *   data symbol imports like callui).
 */

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
#include <queue>
#include <thread>
#include <chrono>

// Windows UTF-8 console support
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

// Socket client for remote mode (shared library, no IDA dependency)
#include <xsql/socket/client.hpp>
#ifdef IDASQL_HAS_HTTP
#include <xsql/thinclient/server.hpp>
#endif

#include "../common/sqlite_utils.hpp"

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

static int print_callback(void*, int argc, char** argv, char** colNames) {
    for (int i = 0; i < argc; i++) {
        std::cout << colNames[i] << " = " << (argv[i] ? argv[i] : "NULL");
        if (i < argc - 1) std::cout << " | ";
    }
    std::cout << std::endl;
    return 0;
}

// Table-style output
struct TablePrinter {
    std::vector<std::string> columns;
    std::vector<std::vector<std::string>> rows;
    std::vector<size_t> widths;
    bool first_row = true;

    void add_row(int argc, char** argv, char** colNames) {
        if (first_row) {
            columns.reserve(argc);
            widths.resize(argc, 0);
            for (int i = 0; i < argc; i++) {
                columns.push_back(colNames[i] ? colNames[i] : "");
                widths[i] = (std::max)(widths[i], columns[i].length());
            }
            first_row = false;
        }

        std::vector<std::string> row;
        row.reserve(argc);
        for (int i = 0; i < argc; i++) {
            std::string val = argv[i] ? argv[i] : "NULL";
            row.push_back(val);
            widths[i] = (std::max)(widths[i], val.length());
        }
        rows.push_back(std::move(row));
    }

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

static TablePrinter* g_printer = nullptr;

static int table_callback(void*, int argc, char** argv, char** colNames) {      
    if (g_printer) {
        g_printer->add_row(argc, argv, colNames);
    }
    return 0;
}

static bool parse_port(const std::string& s, int& port) {
    try {
        size_t idx = 0;
        int v = std::stoi(s, &idx, 10);
        if (idx != s.size()) return false;
        if (v < 1 || v > 65535) return false;
        port = v;
        return true;
    } catch (...) {
        return false;
    }
}

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
// Remote Mode - Pure socket client (NO IDA DEPENDENCIES)
// ============================================================================ 
// This entire section uses only standard C++ and sockets.
// On Windows with delayed loading, ida.dll/idalib.dll are never loaded
// when running in remote mode.

static void print_remote_result(const xsql::socket::RemoteResult& qr) {
    if (qr.rows.empty() && qr.columns.empty()) {
        std::cout << "OK\n";
        return;
    }
    TablePrinter printer;
    for (size_t r = 0; r < qr.rows.size(); r++) {
        std::vector<char*> argv_ptrs(qr.columns.size());
        std::vector<char*> cols_ptrs(qr.columns.size());
        for (size_t c = 0; c < qr.columns.size(); c++) {
            argv_ptrs[c] = const_cast<char*>(qr.rows[r][c].c_str());
            cols_ptrs[c] = const_cast<char*>(qr.columns[c].c_str());
        }
        printer.add_row(static_cast<int>(qr.columns.size()),
                        argv_ptrs.data(), cols_ptrs.data());
    }
    printer.print();
}

static int run_remote_mode(const std::string& host, int port,
                           const std::string& query,
                           const std::string& sql_file,
                           const std::string& auth_token,
                           bool interactive,
                           const std::string& nl_prompt = "",
                           bool verbose_mode = false,
                           const std::string& provider_override = "") {
    std::cerr << "Connecting to " << host << ":" << port << "..." << std::endl;
    xsql::socket::Client remote;
    if (!auth_token.empty()) {
        remote.set_auth_token(auth_token);
    }
    if (!remote.connect(host, port)) {
        std::cerr << "Error: " << remote.error() << std::endl;
        return 1;
    }
    std::cerr << "Connected." << std::endl;

    int result = 0;

#ifdef IDASQL_HAS_AI_AGENT
    if (!nl_prompt.empty()) {
        // Natural language query via remote
        auto executor = [&remote](const std::string& sql) -> std::string {
            auto qr = remote.query(sql);
            if (!qr.success) {
                return "Error: " + qr.error;
            }
            // Format result as string
            std::ostringstream oss;
            if (!qr.columns.empty()) {
                for (size_t i = 0; i < qr.columns.size(); i++) {
                    if (i > 0) oss << " | ";
                    oss << qr.columns[i];
                }
                oss << "\n";
                for (const auto& row : qr.rows) {
                    for (size_t i = 0; i < row.size(); i++) {
                        if (i > 0) oss << " | ";
                        oss << row[i];
                    }
                    oss << "\n";
                }
            }
            return oss.str();
        };

        idasql::AgentSettings settings = idasql::LoadAgentSettings();
        if (!provider_override.empty()) {
            try {
                settings.default_provider = idasql::ParseProviderType(provider_override);
            } catch (...) {}
        }

        idasql::AIAgent agent(executor, settings, verbose_mode);
        g_agent = &agent;
        std::signal(SIGINT, signal_handler);

        agent.start();
        std::string response = agent.query(nl_prompt);
        agent.stop();

        g_agent = nullptr;
        std::signal(SIGINT, SIG_DFL);

        std::cout << response << "\n";
        return 0;
    }
#else
    (void)nl_prompt;
    (void)verbose_mode;
    (void)provider_override;
#endif

    if (!query.empty()) {
        // Single query
        auto qr = remote.query(query);
        if (qr.success) {
            print_remote_result(qr);
        } else {
            std::cerr << "Error: " << qr.error << "\n";
            result = 1;
        }
    } else if (!sql_file.empty()) {
        // File execution (remote)
        std::ifstream file(sql_file);
        if (!file.is_open()) {
            std::cerr << "Cannot open file: " << sql_file << "\n";
            return 1;
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();

        std::vector<std::string> statements;
        std::string parse_error;
        if (!idasql::collect_statements(nullptr, content, statements, parse_error)) {
            std::cerr << "Error parsing SQL file: " << parse_error << "\n";
            return 1;
        }

        for (const auto& stmt : statements) {
            auto qr = remote.query(stmt);
            if (qr.success) {
                print_remote_result(qr);
                std::cout << "\n";
            } else {
                std::cerr << "Error: " << qr.error << "\n";
                std::cerr << "Query: " << stmt << "\n";
                result = 1;
                break;
            }
        }
    } else if (interactive) {
        // Interactive REPL (remote)
        std::string line;
        std::string stmt;
        std::cout << "IDASQL Remote Interactive Mode (" << host << ":" << port << ")\n"
                  << "Type .quit to exit\n\n";

        while (true) {
            std::cout << (stmt.empty() ? "idasql> " : "   ...> ");
            std::cout.flush();
            if (!std::getline(std::cin, line)) break;
            if (line.empty()) continue;

            if (stmt.empty() && line[0] == '.') {
                if (line == ".quit" || line == ".exit") break;
                if (line == ".tables") {
                    auto qr = remote.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;");
                    if (qr.success) {
                        std::cout << "Tables:\n";
                        for (const auto& row : qr.rows) {
                            std::cout << "  " << row[0] << "\n";
                        }
                    }
                    continue;
                }
                if (line == ".help") {
                    std::cout << R"(
Commands:
  .tables             List all tables
  .clear              Clear session
  .quit / .exit       Exit interactive mode
  .help               Show this help

SQL queries end with semicolon (;)
)" << std::endl;
                    continue;
                }
                if (line == ".clear") {
                    std::cout << "Session cleared\n";
                    continue;
                }
                std::cerr << "Unknown command: " << line << "\n";
                continue;
            }

            stmt += line + " ";
            size_t last = line.length() - 1;
            while (last > 0 && (line[last] == ' ' || line[last] == '\t')) last--;
            if (line[last] == ';') {
                auto qr = remote.query(stmt);
                if (qr.success) {
                    print_remote_result(qr);
                } else {
                    std::cerr << "Error: " << qr.error << "\n";
                }
                stmt.clear();
            }
        }
    }

    return result;
}

// ============================================================================
// Local Mode - Uses IDA SDK (delay-loaded on Windows)
// ============================================================================
// From here on, code may call IDA functions. On Windows with /DELAYLOAD,
// ida.dll and idalib.dll are loaded on first use.
//
// Platform-specific include order:
// - Windows: json before IDA (IDA poisons stdlib functions)
// - macOS: IDA before json (system headers define processor_t typedef)

#ifdef __APPLE__
#include <idasql/database.hpp>
#include <xsql/json.hpp>
#else
#include <xsql/json.hpp>
#include <idasql/database.hpp>
#endif

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
    std::cout << "Tables:\n";
    db.exec(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;",
        [](void*, int, char** argv, char**) -> int {
            std::cout << "  " << (argv[0] ? argv[0] : "") << "\n";
            return 0;
        },
        nullptr
    );
}

static void show_schema(idasql::Database& db, const std::string& table) {
    if (!is_safe_table_name(table)) {
        std::cerr << "Invalid table name\n";
        return;
    }

    std::string sql = "SELECT sql FROM sqlite_master WHERE type='table' AND name='" + table + "';";
    db.exec(sql.c_str(),
        [](void*, int, char** argv, char**) -> int {
            std::cout << (argv[0] ? argv[0] : "Not found") << "\n";
            return 0;
        },
        nullptr
    );
}

// Helper to execute SQL and format results as string (for AI agent)
static std::string execute_sql_to_string(idasql::Database& db, const std::string& sql) {
    std::stringstream ss;
    TablePrinter printer;
    g_printer = &printer;
    int rc = db.exec(sql.c_str(), table_callback, nullptr);
    g_printer = nullptr;

    if (rc == SQLITE_OK) {
        // Capture to string instead of stdout
        std::streambuf* old_cout = std::cout.rdbuf(ss.rdbuf());
        printer.print();
        std::cout.rdbuf(old_cout);
        return ss.str();
    } else {
        return "Error: " + std::string(db.error());
    }
}

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

            callbacks.mcp_start = [&db, &agent]() -> std::string {
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
                int port = g_mcp_server->start(0, sql_cb, ask_cb, "127.0.0.1", true);
                if (port <= 0) {
                    g_mcp_agent.reset();
                    return "Error: Failed to start MCP server\n";
                }

                // Print info
                std::cout << idasql::format_mcp_info(port, true);
                std::cout << "Press Ctrl+C to stop MCP server and return to REPL...\n\n";
                std::cout.flush();

                // Set interrupt check to stop on Ctrl+C
                g_mcp_server->set_interrupt_check([]() {
                    return g_quit_requested.load();
                });

                // Enter wait loop - processes MCP commands on main thread
                // This blocks until Ctrl+C or .mcp stop via another client
                g_mcp_server->run_until_stopped();

                // Cleanup
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
            TablePrinter printer;
            g_printer = &printer;
            int rc = db.exec(query.c_str(), table_callback, nullptr);
            g_printer = nullptr;

            if (rc == SQLITE_OK) {
                printer.print();
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
    if (!idasql::export_tables(db.handle(), tables, path, error)) {
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

    std::vector<idasql::StatementResult> results;
    std::string error;
    if (!idasql::execute_script(db.handle(), content, results, error)) {
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

#ifdef IDASQL_HAS_HTTP
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
    bool completed = false;
    std::mutex* done_mutex = nullptr;
    std::condition_variable* done_cv = nullptr;
};

static std::mutex g_http_queue_mutex;
static std::condition_variable g_http_queue_cv;
static std::queue<HttpPendingCommand*> g_http_pending_commands;
static std::atomic<bool> g_http_running{false};

// Queue a command and wait for main thread to execute it
static std::string http_queue_and_wait(const std::string& sql) {
    if (!g_http_running.load()) {
        return xsql::json{{"success", false}, {"error", "Server not running"}}.dump();
    }

    HttpPendingCommand cmd;
    cmd.sql = sql;
    cmd.completed = false;

    std::mutex done_mutex;
    std::condition_variable done_cv;
    cmd.done_mutex = &done_mutex;
    cmd.done_cv = &done_cv;

    {
        std::lock_guard<std::mutex> lock(g_http_queue_mutex);
        g_http_pending_commands.push(&cmd);
    }
    g_http_queue_cv.notify_one();

    // Wait for completion - cleanup code will signal if server stops
    // Timeout after 60s as safety net against shutdown race conditions
    {
        std::unique_lock<std::mutex> lock(done_mutex);
        int wait_count = 0;
        while (!cmd.completed && wait_count < 600) {  // 60 seconds max
            done_cv.wait_for(lock, std::chrono::milliseconds(100));
            wait_count++;
        }
        if (!cmd.completed) {
            // Timed out - likely shutdown race, remove from queue if still there
            std::lock_guard<std::mutex> qlock(g_http_queue_mutex);
            // Can't easily remove from std::queue, but server is stopping anyway
            return xsql::json{{"success", false}, {"error", "Request timed out"}}.dump();
        }
    }

    return cmd.result;
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
  GET  /health   - Alias for /status
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

        // GET /health - Alias for /status
        svr.Get("/health", [&auth_token](const httplib::Request& req, httplib::Response& res) {
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

    std::cout << "IDASQL HTTP server listening on http://" << cfg.bind_address << ":" << port << "\n";
    std::cout << "Database: " << db.info() << "\n";
    std::cout << "Endpoints: /help, /query, /status, /shutdown\n";
    std::cout << "Example: curl http://localhost:" << port << "/help\n";
    std::cout << "Press Ctrl+C to stop.\n\n";
    std::cout.flush();

    // Start HTTP server on a background thread
    std::thread http_thread([&http_server]() {
        http_server.run();
    });

    // Main thread processes the command queue (required for Hex-Rays thread affinity)
    while (g_http_running.load() && !g_http_stop_requested.load()) {
        HttpPendingCommand* cmd = nullptr;

        {
            std::unique_lock<std::mutex> lock(g_http_queue_mutex);
            if (g_http_queue_cv.wait_for(lock, std::chrono::milliseconds(100),
                                          []() { return !g_http_pending_commands.empty() ||
                                                        g_http_stop_requested.load(); })) {
                if (!g_http_pending_commands.empty()) {
                    cmd = g_http_pending_commands.front();
                    g_http_pending_commands.pop();
                }
            }
        }

        if (cmd) {
            // Execute query on main thread - safe for Hex-Rays decompiler
            cmd->result = query_result_to_json(db, cmd->sql);
            if (cmd->done_mutex && cmd->done_cv) {
                {
                    std::lock_guard<std::mutex> lock(*cmd->done_mutex);
                    cmd->completed = true;
                }
                cmd->done_cv->notify_one();
            }
        }
    }

    // Cleanup
    g_http_running.store(false);
    g_http_queue_cv.notify_all();

    // Complete any pending commands with error
    {
        std::lock_guard<std::mutex> lock(g_http_queue_mutex);
        while (!g_http_pending_commands.empty()) {
            HttpPendingCommand* cmd = g_http_pending_commands.front();
            g_http_pending_commands.pop();
            if (!cmd || !cmd->done_mutex || !cmd->done_cv) continue;
            cmd->result = xsql::json{{"success", false}, {"error", "Server stopped"}}.dump();
            {
                std::lock_guard<std::mutex> dlock(*cmd->done_mutex);
                cmd->completed = true;
            }
            cmd->done_cv->notify_one();
        }
    }

    // Stop HTTP server and wait for thread
    http_server.stop();
    if (http_thread.joinable()) {
        http_thread.join();
    }

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
#endif // IDASQL_HAS_HTTP

// ============================================================================
// Main
// ============================================================================

static void print_usage() {
    std::cerr << "IDASQL - SQL interface to IDA databases\n\n"
              << "Usage: idasql -s <database> [-q|-c <query>] [-f <file>] [-i] [--export <file>]\n"
              << "       idasql --remote <host:port> [-q|-c <query>] [-f <file>] [-i]\n\n"
              << "Options:\n"
              << "  -s <file>            IDA database file (.idb/.i64) for local mode\n"
              << "  --remote <host:port> Connect to IDASQL plugin server (e.g., localhost:13337)\n"
              << "  --token <token>      Auth token for remote mode (if server requires it)\n"
              << "  -q <sql>             Execute single SQL query\n"
              << "  -c <sql>             Execute single SQL query (alias for -q)\n"
              << "  -f <file>            Execute SQL from file\n"
              << "  -i                   Interactive REPL mode\n"
              << "  -w, --write          Save database on exit (persist changes)\n"
              << "  --export <file>      Export tables to SQL file (local mode only)\n"
              << "  --export-tables=X    Tables to export: * (all, default) or table1,table2,...\n"
#ifdef IDASQL_HAS_HTTP
              << "  --http [port]        Start HTTP REST server (default: 8080, local mode only)\n"
              << "  --bind <addr>        Bind address for HTTP/MCP server (default: 127.0.0.1)\n"
#endif
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
              << "  -h, --help           Show this help\n\n"
              << "Examples:\n"
              << "  idasql -s test.i64 -q \"SELECT name, size FROM funcs LIMIT 10\"\n"
              << "  idasql -s test.i64 -f queries.sql\n"
              << "  idasql -s test.i64 -i\n"
              << "  idasql -s test.i64 --export dump.sql\n"
              << "  idasql --remote localhost:13337 -q \"SELECT * FROM funcs LIMIT 5\"\n"
#ifdef IDASQL_HAS_AI_AGENT
              << "  idasql -s test.i64 --prompt \"Find the largest functions\"\n"
              << "  idasql -s test.i64 -i --agent\n"
              << "  idasql -s test.i64 --provider copilot --prompt \"How many functions?\"\n"
#endif
              << "  idasql --remote localhost:13337 -i\n";
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Enable UTF-8 output on Windows console for proper Unicode display
    SetConsoleOutputCP(CP_UTF8);
#endif

    // Check for help first - before any IDA initialization
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        }
    }

    std::string db_path;
    std::string query;
    std::string sql_file;
    std::string export_file;
    std::string export_tables = "*";  // Default: all tables
    std::string remote_spec;          // host:port for remote mode
    std::string auth_token;           // --token for remote mode
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
        } else if (strcmp(argv[i], "--remote") == 0 && i + 1 < argc) {
            remote_spec = argv[++i];
        } else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            auth_token = argv[++i];
        } else if ((strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "-c") == 0) && i + 1 < argc) {
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
    bool remote_mode = !remote_spec.empty();

    if (!remote_mode && db_path.empty()) {
        std::cerr << "Error: Database path required (-s) or use --remote\n\n";
        print_usage();
        return 1;
    }

    if (remote_mode && !db_path.empty()) {
        std::cerr << "Error: Cannot use both -s and --remote\n\n";
        print_usage();
        return 1;
    }

    bool has_action = !query.empty() || !sql_file.empty() || interactive || !export_file.empty() || http_mode || mcp_mode;
#ifdef IDASQL_HAS_AI_AGENT
    has_action = has_action || !nl_prompt.empty();
#endif
    if (!has_action) {
        std::cerr << "Error: Specify -q, -c, -f, -i, --export, --http, --mcp"
#ifdef IDASQL_HAS_AI_AGENT
                  << ", or --prompt"
#endif
                  << "\n\n";
        print_usage();
        return 1;
    }

    if (remote_mode && !export_file.empty()) {
        std::cerr << "Error: --export not supported in remote mode\n\n";
        print_usage();
        return 1;
    }

    if (remote_mode && http_mode) {
        std::cerr << "Error: Cannot use both --remote and --http\n\n";
        print_usage();
        return 1;
    }

    //=========================================================================
    // Remote mode - thin client, no IDA kernel loaded
    //=========================================================================
    // IMPORTANT: This path never calls any IDA functions.
    // On Windows with delayed loading, ida.dll/idalib.dll stay unloaded.
    if (remote_mode) {
        // Parse host:port
        std::string host = "127.0.0.1";
        int port = 13337;
        auto colon = remote_spec.find(':');
        if (colon != std::string::npos) {
            host = remote_spec.substr(0, colon);
            std::string port_str = remote_spec.substr(colon + 1);
            if (!parse_port(port_str, port)) {
                std::cerr << "Error: Invalid port in --remote: " << port_str << "\n";
                return 1;
            }
        } else {
            host = remote_spec;
        }
#ifdef IDASQL_HAS_AI_AGENT
        return run_remote_mode(host, port, query, sql_file, auth_token, interactive,
                               nl_prompt, verbose_mode, provider_override);
#else
        return run_remote_mode(host, port, query, sql_file, auth_token, interactive);
#endif
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
#ifdef IDASQL_HAS_HTTP
    if (http_mode) {
        int http_result = run_http_mode(db, http_port, bind_addr, auth_token);
        db.close();
        return http_result;
    }
#else
    if (http_mode) {
        std::cerr << "Error: HTTP mode not available. Rebuild with -DIDASQL_WITH_HTTP=ON\n";
        db.close();
        return 1;
    }
#endif

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
        TablePrinter printer;
        g_printer = &printer;
        int rc = db.exec(query.c_str(), table_callback, nullptr);
        g_printer = nullptr;

        if (rc == SQLITE_OK) {
            printer.print();
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
