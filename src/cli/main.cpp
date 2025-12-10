/**
 * idasql CLI - Command-line SQL interface to IDA databases
 *
 * Usage:
 *   idasql -s database.i64 -q "SELECT * FROM funcs"     # Single query
 *   idasql -s database.i64 -c "SELECT * FROM funcs"     # Same as -q (Python-style)
 *   idasql -s database.i64 -f script.sql                # Execute SQL file
 *   idasql -s database.i64 -i                           # Interactive mode
 *   idasql -s database.i64 --export out.sql             # Export all tables to SQL
 *   idasql -s database.i64 --export out.sql --export-tables=funcs,segments
 *
 * Switches:
 *   -s <file>            IDA database file (.idb/.i64)
 *   -q <sql>             Execute single SQL query
 *   -c <sql>             Execute single SQL query (alias for -q)
 *   -f <file>            Execute SQL from file
 *   -i                   Interactive REPL mode
 *   --export <file>      Export tables to SQL file
 *   --export-tables=...  Tables to export (* for all, or table1,table2,...)
 *   -h                   Show help
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <vector>

#include <idasql/database.hpp>

// ============================================================================
// Output Formatting
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
                widths[i] = std::max(widths[i], columns[i].length());
            }
            first_row = false;
        }

        std::vector<std::string> row;
        row.reserve(argc);
        for (int i = 0; i < argc; i++) {
            std::string val = argv[i] ? argv[i] : "NULL";
            row.push_back(val);
            widths[i] = std::max(widths[i], val.length());
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

// ============================================================================
// REPL - Interactive Mode
// ============================================================================

static void show_help() {
    std::cout << R"(
Commands:
  .tables             List all tables
  .schema [table]     Show table schema
  .info               Show database info
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
    std::string sql = "SELECT sql FROM sqlite_master WHERE type='table' AND name='" + table + "';";
    db.exec(sql.c_str(),
        [](void*, int, char** argv, char**) -> int {
            std::cout << (argv[0] ? argv[0] : "Not found") << "\n";
            return 0;
        },
        nullptr
    );
}

static void run_repl(idasql::Database& db) {
    std::string line;
    std::string query;

    std::cout << "IDASQL Interactive Mode\n"
              << "Type .help for commands, .quit to exit\n\n";

    while (true) {
        // Prompt
        std::cout << (query.empty() ? "idasql> " : "   ...> ");
        std::cout.flush();

        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        // Handle dot commands
        if (query.empty() && !line.empty() && line[0] == '.') {
            if (line == ".quit" || line == ".exit") break;
            if (line == ".tables") { show_tables(db); continue; }
            if (line == ".info") { std::cout << db.info(); continue; }
            if (line == ".help") { show_help(); continue; }
            if (line.substr(0, 7) == ".schema") {
                std::string table = line.length() > 8 ? line.substr(8) : "";
                // Trim whitespace
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
        }

        // Accumulate query
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
}

// ============================================================================
// Export to SQL
// ============================================================================

// Escape string for SQL (double single quotes)
static std::string sql_escape(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 10);
    for (char c : s) {
        if (c == '\'') {
            result += "''";
        } else {
            result += c;
        }
    }
    return result;
}

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

// Get all table names from database
static std::vector<std::string> get_all_tables(idasql::Database& db) {
    std::vector<std::string> tables;
    db.exec(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;",
        [](void* data, int, char** argv, char**) -> int {
            auto* vec = static_cast<std::vector<std::string>*>(data);
            if (argv[0]) vec->push_back(argv[0]);
            return 0;
        },
        &tables
    );
    return tables;
}

// Export tables to SQL file
static bool export_to_sql(idasql::Database& db, const char* path,
                          const std::string& table_spec) {
    std::ofstream out(path);
    if (!out.is_open()) {
        std::cerr << "Error: Cannot open output file: " << path << "\n";
        return false;
    }

    // Determine which tables to export
    std::vector<std::string> tables;
    if (table_spec.empty() || table_spec == "*") {
        tables = get_all_tables(db);
    } else {
        tables = parse_table_list(table_spec);
    }

    out << "-- IDASQL Export\n";
    out << "-- Source: IDA database\n";
    out << "-- Tables: " << tables.size() << "\n\n";

    for (const auto& table : tables) {
        std::cerr << "Exporting: " << table << "...\n";

        // Get schema
        std::string schema;
        std::string schema_sql = "SELECT sql FROM sqlite_master WHERE type='table' AND name='" +
                                  sql_escape(table) + "';";
        db.exec(schema_sql.c_str(),
            [](void* data, int, char** argv, char**) -> int {
                if (argv[0]) *static_cast<std::string*>(data) = argv[0];
                return 0;
            },
            &schema
        );

        if (schema.empty()) {
            std::cerr << "Warning: Table '" << table << "' not found, skipping.\n";
            continue;
        }

        // Write CREATE TABLE (convert virtual table to regular table)
        // Virtual tables have "CREATE VIRTUAL TABLE ... USING module"
        // We want "CREATE TABLE ... (columns)"
        out << "-- Table: " << table << "\n";
        out << "DROP TABLE IF EXISTS " << table << ";\n";

        // Get column info by querying the table
        std::vector<std::string> columns;
        std::string pragma = "PRAGMA table_info(" + table + ");";
        db.exec(pragma.c_str(),
            [](void* data, int, char** argv, char**) -> int {
                auto* cols = static_cast<std::vector<std::string>*>(data);
                if (argv[1]) cols->push_back(argv[1]);  // column name
                return 0;
            },
            &columns
        );

        // Write CREATE TABLE with columns
        out << "CREATE TABLE " << table << " (\n";
        for (size_t i = 0; i < columns.size(); i++) {
            out << "    " << columns[i] << " TEXT";
            if (i < columns.size() - 1) out << ",";
            out << "\n";
        }
        out << ");\n\n";

        // Export data as INSERT statements
        struct ExportContext {
            std::ofstream* out;
            std::string table;
            size_t col_count;
            size_t row_count;
        } ctx = { &out, table, columns.size(), 0 };

        std::string select = "SELECT * FROM " + table + ";";
        db.exec(select.c_str(),
            [](void* data, int argc, char** argv, char**) -> int {
                auto* ctx = static_cast<ExportContext*>(data);
                *ctx->out << "INSERT INTO " << ctx->table << " VALUES (";
                for (int i = 0; i < argc; i++) {
                    if (argv[i]) {
                        *ctx->out << "'" << sql_escape(argv[i]) << "'";
                    } else {
                        *ctx->out << "NULL";
                    }
                    if (i < argc - 1) *ctx->out << ", ";
                }
                *ctx->out << ");\n";
                ctx->row_count++;
                return 0;
            },
            &ctx
        );

        out << "-- " << ctx.row_count << " rows exported\n\n";
    }

    out << "-- Export complete\n";
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

    // Split by semicolons and execute each statement
    std::string query;
    for (char c : content) {
        query += c;
        if (c == ';') {
            TablePrinter printer;
            g_printer = &printer;
            int rc = db.exec(query.c_str(), table_callback, nullptr);
            g_printer = nullptr;

            if (rc == SQLITE_OK) {
                printer.print();
                std::cout << "\n";
            } else {
                std::cerr << "Error: " << db.error() << "\n";
                std::cerr << "Query: " << query << "\n";
                return false;
            }
            query.clear();
        }
    }

    return true;
}

// ============================================================================
// Main
// ============================================================================

static void print_usage(const char* prog) {
    std::cerr << "IDASQL - SQL interface to IDA databases\n\n"
              << "Usage: " << prog << " -s <database> [-q|-c <query>] [-f <file>] [-i] [--export <file>]\n\n"
              << "Options:\n"
              << "  -s <file>            IDA database file (.idb/.i64) [required]\n"
              << "  -q <sql>             Execute single SQL query\n"
              << "  -c <sql>             Execute single SQL query (alias for -q)\n"
              << "  -f <file>            Execute SQL from file\n"
              << "  -i                   Interactive REPL mode\n"
              << "  --export <file>      Export tables to SQL file\n"
              << "  --export-tables=X    Tables to export: * (all, default) or table1,table2,...\n"
              << "  -h                   Show this help\n\n"
              << "Examples:\n"
              << "  " << prog << " -s test.i64 -q \"SELECT name, size FROM funcs LIMIT 10\"\n"
              << "  " << prog << " -s test.i64 -f queries.sql\n"
              << "  " << prog << " -s test.i64 -i\n"
              << "  " << prog << " -s test.i64 --export dump.sql\n"
              << "  " << prog << " -s test.i64 --export dump.sql --export-tables=funcs,segments,xrefs\n";
}

int main(int argc, char* argv[]) {
    std::string db_path;
    std::string query;
    std::string sql_file;
    std::string export_file;
    std::string export_tables = "*";  // Default: all tables
    bool interactive = false;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-s") == 0) && i + 1 < argc) {
            db_path = argv[++i];
        } else if ((strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "-c") == 0) && i + 1 < argc) {
            query = argv[++i];
        } else if ((strcmp(argv[i], "-f") == 0) && i + 1 < argc) {
            sql_file = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0) {
            interactive = true;
        } else if (strcmp(argv[i], "--export") == 0 && i + 1 < argc) {
            export_file = argv[++i];
        } else if (strncmp(argv[i], "--export-tables=", 16) == 0) {
            export_tables = argv[i] + 16;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Validate arguments
    if (db_path.empty()) {
        std::cerr << "Error: Database path required (-s)\n\n";
        print_usage(argv[0]);
        return 1;
    }

    if (query.empty() && sql_file.empty() && !interactive && export_file.empty()) {
        std::cerr << "Error: Specify -q, -c, -f, -i, or --export\n\n";
        print_usage(argv[0]);
        return 1;
    }

    // Open database
    std::cerr << "Opening: " << db_path << "..." << std::endl;  // Flush immediately
    idasql::Database db;
    if (!db.open(db_path.c_str())) {
        std::cerr << "Error: " << db.error() << std::endl;
        return 1;
    }
    std::cerr << "Database opened successfully." << std::endl;

    int result = 0;

    // Execute based on mode
    if (!export_file.empty()) {
        // Export mode
        if (!export_to_sql(db, export_file.c_str(), export_tables)) {
            result = 1;
        }
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
        run_repl(db);
    }

    db.close();
    return result;
}
