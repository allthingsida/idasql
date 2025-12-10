/**
 * test_utils.hpp - Test utilities for IDASQL
 *
 * Provides:
 *   - SQL file loading
 *   - Database fixtures
 *   - Result comparison helpers
 */

#pragma once

#include <sqlite3.h>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <functional>

namespace idasql {
namespace testing {

// ============================================================================
// SQL File Loader
// ============================================================================

/**
 * Load SQL from a file.
 * Searches in: ./sql/, ../sql/, ../tests/sql/
 */
std::string load_sql(const std::string& filename);

/**
 * Load SQL and substitute parameters.
 * Parameters are in the form ${name}.
 */
std::string load_sql(const std::string& filename,
                     const std::map<std::string, std::string>& params);

// ============================================================================
// Query Result Types
// ============================================================================

struct QueryRow {
    std::vector<std::string> values;
    std::string operator[](size_t idx) const {
        return idx < values.size() ? values[idx] : "";
    }
};

struct QueryResult {
    std::vector<std::string> columns;
    std::vector<QueryRow> rows;

    size_t row_count() const { return rows.size(); }
    size_t col_count() const { return columns.size(); }

    bool empty() const { return rows.empty(); }

    // Get column index by name
    int col_index(const std::string& name) const;

    // Get value at row, column
    std::string get(size_t row, size_t col) const;
    std::string get(size_t row, const std::string& col_name) const;

    // Get first row, first column (for scalar queries)
    std::string scalar() const { return get(0, 0); }
    int64_t scalar_int() const;
    double scalar_double() const;
};

// ============================================================================
// Query Execution
// ============================================================================

/**
 * Execute SQL and collect results.
 */
QueryResult exec_query(sqlite3* db, const std::string& sql);

/**
 * Execute SQL (no results expected).
 */
bool exec_sql(sqlite3* db, const std::string& sql);

/**
 * Execute SQL from file.
 */
QueryResult exec_sql_file(sqlite3* db, const std::string& filename);
QueryResult exec_sql_file(sqlite3* db, const std::string& filename,
                          const std::map<std::string, std::string>& params);

// ============================================================================
// Assertion Helpers
// ============================================================================

/**
 * Check if result contains expected value in any row/column.
 */
bool result_contains(const QueryResult& result, const std::string& value);

/**
 * Check if result column contains expected value.
 */
bool column_contains(const QueryResult& result, const std::string& col_name,
                     const std::string& value);

/**
 * Check first row matches expected values.
 */
bool first_row_matches(const QueryResult& result,
                       const std::vector<std::string>& expected);

} // namespace testing
} // namespace idasql
