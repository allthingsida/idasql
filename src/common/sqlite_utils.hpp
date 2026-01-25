#pragma once

#include <sqlite3.h>

#include <functional>
#include <string>
#include <vector>

namespace idasql {

// Result set for a single SQL statement
struct StatementResult {
    std::vector<std::string> columns;
    std::vector<std::vector<std::string>> rows;
};

// Quote an identifier with double quotes ("" -> """")
std::string quote_identifier(const std::string& name);

// Split a SQL script into individual statements using SQLite's parser
// Returns false on syntax error and sets error string.
bool collect_statements(sqlite3* db,
                        const std::string& script,
                        std::vector<std::string>& statements,
                        std::string& error);

// Execute a SQL script, collecting results for statements that produce rows.
// Non-result statements are executed and ignored.
bool execute_script(sqlite3* db,
                    const std::string& script,
                    std::vector<StatementResult>& results,
                    std::string& error);

// Export the specified tables (or all tables if list is empty) to a SQL file.
// Preserves column types, defaults, nullability, and emits BLOBs as hex.
bool export_tables(sqlite3* db,
                   const std::vector<std::string>& tables,
                   const std::string& output_path,
                   std::string& error);

} // namespace idasql
