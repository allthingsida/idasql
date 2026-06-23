// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

#include <xsql/json.hpp>
#include <xsql/query_script.hpp>
#include <xsql/thinclient/server.hpp>
#include "../common/http_server.hpp"
#include "../common/idasql_commands.hpp"
#include "../common/pin_commands.hpp"
#include <idasql/autostart_pin.hpp>
#include "../common/json_utils.hpp"
#include "../common/sql_script.hpp"
#include "../common/welcome_query.hpp"

#include "../common/idasql_version.hpp"

// MCP integration (optional, enabled via IDASQL_WITH_MCP)
#ifdef IDASQL_HAS_MCP
#include "../common/mcp_server.hpp"
#endif

// Global signal handler state
namespace {
    std::atomic<bool> g_quit_requested{false};
#ifdef IDASQL_HAS_MCP
    std::unique_ptr<idasql::IDAMCPServer> g_mcp_server;
#endif
    std::unique_ptr<idasql::IDAHTTPServer> g_repl_http_server;
}

extern "C" void signal_handler(int sig) {
    (void)sig;
    g_quit_requested.store(true);
}

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
#include <idasql/idapython.hpp>
#include <idalib.hpp>
#include <loader.hpp>  // save_database()

static void print_query_warnings(std::ostream& os, const idasql::QueryResult& result);

struct idapython_runtime_guard_t {
    bool acquired = false;
    ~idapython_runtime_guard_t() {
        if (acquired) {
            idasql::idapython::runtime_release();
        }
    }
};

static void add_query_result_rows(TablePrinter& printer, const idasql::QueryResult& result) {
    for (const auto& row : result.rows) {
        printer.add_row(result.columns, row.values);
    }
}

static bool print_query_result_table(const idasql::QueryResult& result) {
    if (result.columns.empty()) {
        return false;
    }

    TablePrinter printer;
    add_query_result_rows(printer, result);
    printer.print();
    print_query_warnings(std::cout, result);
    return true;
}

static void print_script_statement_table(const xsql::ScriptStatementResult& stmt) {
    if (stmt.columns.empty()) return;
    TablePrinter printer;
    for (const auto& row : stmt.rows) {
        printer.add_row(stmt.columns, row);
    }
    printer.print();
}

static void print_script_result_tables(const xsql::ScriptResult& script_result) {
    if (!script_result.parse_error.empty()) {
        std::cerr << "Error: " << script_result.parse_error << "\n";
        return;
    }
    bool wrote_result = false;
    for (const auto& stmt : script_result.results) {
        if (!stmt.success) {
            if (wrote_result) std::cout << "\n";
            std::cerr << "Error in statement " << (stmt.statement_index + 1)
                      << ": " << stmt.error << "\n";
            wrote_result = true;
            continue;
        }
        if (stmt.columns.empty()) continue;
        if (wrote_result) std::cout << "\n";
        print_script_statement_table(stmt);
        wrote_result = true;
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

static void run_repl(idasql::Database& db) {
    std::string line;
    std::string query;
    std::cout << "IDASQL Interactive Mode\n"
              << "Type .help for commands, .quit to exit\n\n";

    while (true) {
        if (g_quit_requested.load()) {
            std::cout << "\nInterrupted.\n";
            break;
        }

        // Prompt
        std::cout << (query.empty() ? "idasql> " : "   ...> ");
        std::cout.flush();

        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        // Handle dot commands
        if (query.empty() && !line.empty() && line[0] == '.') {
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
                if (result.success && !result.rows.empty() && result.rows[0].size() > 0) {
                    return std::string(result.rows[0][0]);
                }
                return "Table not found: " + table;
            };
            callbacks.get_info = [&db]() -> std::string {
                return db.info();
            };

#ifdef IDASQL_HAS_MCP
            // MCP server callbacks
            callbacks.mcp_status = []() -> std::string {
                if (g_mcp_server && g_mcp_server->is_running()) {
                    return idasql::format_mcp_status(
                        g_mcp_server->port(), true, g_mcp_server->bind_addr());
                } else {
                    return "MCP server not running\nUse '.mcp start' to start\n";
                }
            };

            callbacks.mcp_start = [&db](int req_port, const std::string& bind_addr) -> std::string {
                if (g_mcp_server && g_mcp_server->is_running()) {
                    return idasql::format_mcp_status(
                        g_mcp_server->port(), true, g_mcp_server->bind_addr());
                }

                // Create MCP server if needed
                if (!g_mcp_server) {
                    g_mcp_server = std::make_unique<idasql::IDAMCPServer>();
                }

                // With no explicit port, fall back to the pinned host/port.
                std::string addr = bind_addr;
                if (req_port == 0) {
                    idasql::autostart::PinConfig pin = idasql::autostart::load();
                    if (pin.mcp.port != 0) {
                        req_port = pin.mcp.port;
                        addr = pin.mcp.host;
                    }
                }

                // SQL executor - will be called on main thread via wait()
                idasql::QueryCallback sql_cb = [&db](const std::string& sql) -> std::string {
                    auto result = idasql::run_sql_script(db, sql);
                    return xsql::script_result_to_text(result);
                };

                // Start with use_queue=true for CLI mode (main thread execution)
                int port = g_mcp_server->start(req_port, sql_cb, addr, true);
                if (port <= 0) {
                    return "Error: Failed to start MCP server\n";
                }

                // Print info
                std::cout << idasql::format_mcp_info(port, g_mcp_server->bind_addr());
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
                g_quit_requested.store(false);  // Reset for continued REPL use

                return "MCP server stopped. Returning to REPL.\n";
            };

            callbacks.mcp_stop = []() -> std::string {
                if (g_mcp_server && g_mcp_server->is_running()) {
                    g_mcp_server->stop();
                    return "MCP server stopped\n";
                }
                return "MCP server not running\n";
            };
#endif

            // HTTP server callbacks
            callbacks.http_status = []() -> std::string {
                if (g_repl_http_server && g_repl_http_server->is_running()) {
                    return idasql::format_http_status(
                        g_repl_http_server->port(), true, g_repl_http_server->bind_addr());
                }
                return "HTTP server not running\nUse '.http start' to start\n";
            };

            callbacks.http_start = [&db](int req_port, const std::string& bind_addr) -> std::string {
                if (g_repl_http_server && g_repl_http_server->is_running()) {
                    return idasql::format_http_status(
                        g_repl_http_server->port(), true, g_repl_http_server->bind_addr());
                }

                // Create HTTP server if needed
                if (!g_repl_http_server) {
                    g_repl_http_server = std::make_unique<idasql::IDAHTTPServer>();
                }

                // With no explicit port, fall back to the pinned host/port.
                std::string addr = bind_addr;
                if (req_port == 0) {
                    idasql::autostart::PinConfig pin = idasql::autostart::load();
                    if (pin.http.port != 0) {
                        req_port = pin.http.port;
                        addr = pin.http.host;
                    }
                }

                // SQL executor - called on main thread via run_until_stopped()
                idasql::HTTPStatementExecutor sql_cb =
                    [&db](const std::string& stmt, xsql::ScriptStatementResult& out) {
                        idasql::QueryResult r = db.query(stmt);
                        out.columns = r.columns;
                        out.rows.reserve(r.rows.size());
                        for (const auto& row : r.rows) out.rows.push_back(row.values);
                        out.elapsed_ms = static_cast<double>(r.elapsed_ms);
                        out.success = r.success;
                        out.error = r.error;
                    };

                // Start with use_queue=true (CLI mode)
                int port = g_repl_http_server->start(req_port, sql_cb, addr, true);
                if (port <= 0) {
                    return "Error: Failed to start HTTP server\n";
                }

                // Print info
                std::cout << idasql::format_http_info(
                    port, g_repl_http_server->bind_addr(), "Press Ctrl+C to stop and return to REPL.");
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

            // Pin commands work in the CLI too (writes persist only with
            // -w/--write, like any other IDB edit); autostart-on-load is
            // plugin-only.
            idasql::wire_pin_callbacks(callbacks);

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
        }

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

exit_repl:
    return;
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

static std::atomic<bool> g_http_stop_requested{false};

static void http_signal_handler(int) {
    g_http_stop_requested.store(true);
}


// CLI --http server, on the shared libxsql thinclient (use_queue=true: queries
// run on this main thread via run_until_stopped, for Hex-Rays thread affinity).
static int run_http_mode(idasql::Database& db, int port, const std::string& bind_addr, const std::string& auth_token) {
    idasql::IDAHTTPServer server;
    idasql::HTTPStatementExecutor exec =
        [&db](const std::string& stmt, xsql::ScriptStatementResult& out) {
            idasql::QueryResult r = db.query(stmt);
            out.columns = r.columns;
            out.rows.reserve(r.rows.size());
            for (const auto& row : r.rows) out.rows.push_back(row.values);
            out.elapsed_ms = static_cast<double>(r.elapsed_ms);
            out.success = r.success;
            out.error = r.error;
        };

    int actual_port = server.start(port, exec, bind_addr, /*use_queue=*/true, auth_token);
    if (actual_port < 0) {
        std::cerr << "Error: Failed to start HTTP server\n";
        return 1;
    }

    g_http_stop_requested.store(false);
    auto old_handler = std::signal(SIGINT, http_signal_handler);
#ifdef _WIN32
    auto old_break = std::signal(SIGBREAK, http_signal_handler);
#else
    auto old_term = std::signal(SIGTERM, http_signal_handler);
#endif
    server.set_interrupt_check([]() { return g_http_stop_requested.load(); });

    std::cout << "IDASQL HTTP server: http://" << (bind_addr.empty() ? "127.0.0.1" : bind_addr)
              << ":" << actual_port << "\n";
    std::cout << "Database: " << db.info() << "\n";
    std::cout << "Press Ctrl+C to stop.\n\n";
    std::cout.flush();

    server.run_until_stopped();
    server.stop();

    std::signal(SIGINT, old_handler);
#ifdef _WIN32
    std::signal(SIGBREAK, old_break);
#else
    std::signal(SIGTERM, old_term);
#endif
    std::cout << "\nHTTP server stopped.\n";
    return 0;
}


// ============================================================================
// Main
// ============================================================================

static std::string make_upgrade_json(const idasql::Database& db, const std::string& input) {
    const std::string message =
        "Database upgraded from 32-bit .idb to 64-bit .i64; reopen with -s <reopen_with>.";
    return xsql::json{
        {"status", "upgraded"},
        {"input", input},
        {"reopen_with", db.upgraded_i64_path()},
        {"upgrade_log", db.upgrade_log_path()},
        {"message", message}
    }.dump();
}

static void print_usage() {
    std::cerr << "idasql v" IDASQL_VERSION_STRING " - SQL interface to IDA databases\n\n"
              << "Usage: idasql -s <file> [-q <query>] [-f <file>] [-i] [--export <file>]\n\n"
              << "Options:\n"
              << "  -s <file>            IDA database (.idb/.i64) OR raw binary (.exe/.dll/firmware/etc.)\n"
              << "                       — raw binaries trigger fresh idalib analysis and string-list rebuild\n"
              << "                       — legacy 32-bit .idb files upgrade to .i64 and require an explicit reopen\n"
              << "  --token <token>      Auth token for HTTP/MCP server mode (if server requires it)\n"
              << "  -q <sql>             Execute SQL query or semicolon-separated script\n"
              << "  -f <file>            Execute SQL from file\n"
              << "  -i                   Interactive REPL mode\n"
              << "  -w, --write          Save database on exit (persist changes)\n"
              << "  --export <file>      Export tables to SQL file (local mode only)\n"
              << "  --export-tables=X    Tables to export: * (all, default) or table1,table2,...\n"
              << "  --http [port]        Start HTTP REST server (default: 8080, local mode only)\n"
              << "  --bind <addr>        Bind address for HTTP/MCP server (default: 127.0.0.1)\n"
#ifdef IDASQL_HAS_MCP
              << "  --mcp [port]         Start MCP server (default: random port, use in -i mode)\n"
              << "                       Or use .mcp start in interactive mode\n"
#endif
              << "  -h, --help           Show this help\n"
              << "  --version            Show version\n\n"
              << "Examples:\n"
              << "  idasql -s test.i64 -q \"SELECT name, size FROM funcs LIMIT 10\"\n"
              << "  idasql -s test.i64 -f queries.sql\n"
              << "  idasql -s test.i64 -i\n"
              << "  idasql -s test.i64 --export dump.sql\n"
              << "  idasql -s test.i64 --http 8080\n"
              << "  idasql -s sample.exe --http            # raw PE: idalib auto-analyzes, then serves SQL (default port 8080)\n"
              << "  idasql -s firmware.bin -q \"SELECT * FROM welcome\"\n"
#ifdef IDASQL_HAS_MCP
              << "  idasql -s test.i64 --mcp 9000\n";
#else
              ;
#endif
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
        } else if (strcmp(argv[i], "--http") == 0) {
            http_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                http_port = std::stoi(argv[++i]);
            }
#ifdef IDASQL_HAS_MCP
        } else if (strcmp(argv[i], "--mcp") == 0) {
            mcp_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                mcp_port = std::stoi(argv[++i]);
            }
#else
        } else if (strcmp(argv[i], "--mcp") == 0) {
            std::cerr << "Error: MCP mode not available. Rebuild with -DIDASQL_WITH_MCP=ON\n";
            return 1;
#endif
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
    if (!has_action) {
        std::cerr << "Error: Specify -q, -f, -i, --export, --http";
#ifdef IDASQL_HAS_MCP
        std::cerr << ", or --mcp";
#endif
        std::cerr << "\n\n";
        print_usage();
        return 1;
    }

    //=========================================================================
    // Local mode - requires IDA SDK
    //=========================================================================
    int init_rc = init_library();
    if (init_rc != 0) {
        std::cerr << "Error: Failed to initialize IDA library: " << init_rc << std::endl;
        return 1;
    }

    std::cerr << "Opening: " << db_path << "..." << std::endl;
    idasql::Database db;
    if (!db.open(db_path.c_str())) {
        if (db.open_outcome() == idasql::OpenOutcome::UpgradedReopenRequired) {
            std::cout << make_upgrade_json(db, db_path) << std::endl;
            std::cerr << "Database was upgraded to 64-bit. Reopen with: -s "
                      << db.upgraded_i64_path() << std::endl;
            return 3;
        }
        std::cerr << "Error: " << db.error() << std::endl;
        return 1;
    }
    if (!db.open_notice().empty()) {
        std::cerr << db.open_notice() << std::endl;
    }
    std::cerr << "Database opened successfully." << std::endl;

    idapython_runtime_guard_t idapython_runtime;
    std::string idapython_runtime_error;
    idapython_runtime.acquired = idasql::idapython::runtime_acquire(&idapython_runtime_error);
    if (!idapython_runtime.acquired) {
        std::cerr << "Warning: IDAPython capture runtime init failed: "
                  << idapython_runtime_error << std::endl;
    }

    auto save_if_requested = [&]() {
        if (!write_mode)
            return;
        if (save_database()) {
            std::cerr << "Database saved.\n";
        } else {
            std::cerr << "Warning: Failed to save database.\n";
        }
    };

    // HTTP server mode
    if (http_mode) {
        int http_result = run_http_mode(db, http_port, bind_addr, auth_token);
        save_if_requested();
        db.close();
        return http_result;
    }

    // MCP server mode (standalone, not interactive REPL)
#ifdef IDASQL_HAS_MCP
    if (mcp_mode) {
        // SQL executor - will be called on main thread via wait()
        idasql::QueryCallback sql_cb = [&db](const std::string& sql) -> std::string {
            auto result = idasql::run_sql_script(db, sql);
            return xsql::script_result_to_text(result);
        };

        // Create and start MCP server with use_queue=true
        idasql::IDAMCPServer mcp_server;
        int port = mcp_server.start(mcp_port, sql_cb,
                                    bind_addr.empty() ? "127.0.0.1" : bind_addr, true);
        if (port <= 0) {
            std::cerr << "Error: Failed to start MCP server\n";
            db.close();
            return 1;
        }

        std::cout << idasql::format_mcp_info(port, mcp_server.bind_addr());
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
        std::cout << "\nMCP server stopped.\n";
        save_if_requested();
        db.close();
        return 0;
    }
#else
    if (mcp_mode) {
        std::cerr << "Error: MCP mode not available. Rebuild with -DIDASQL_WITH_MCP=ON\n";
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
    } else if (!query.empty()) {
        // Query mode: single-statement and multi-statement go through the same
        // canonical envelope; output is table form.
        auto query_result = idasql::run_sql_script(db, query);
        print_script_result_tables(query_result);
        if (!query_result.success) {
            result = 1;
        }
    } else if (!sql_file.empty()) {
        // File execution mode
        if (!execute_file(db, sql_file.c_str())) {
            result = 1;
        }
    } else if (interactive) {
        // Interactive REPL
        run_repl(db);
    }

    // Save database if -w/--write was specified.
    save_if_requested();

    db.close();
    return result;
}
