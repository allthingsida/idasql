/**
 * test_utils.cpp - Implementation of test utilities
 */

#include "test_utils.hpp"
#include <filesystem>
#include <regex>

namespace idasql {
namespace testing {

// ============================================================================
// SQL File Loader
// ============================================================================

static std::vector<std::string> sql_search_paths = {
    "sql/",
    "../sql/",
    "../../sql/",           // From build/RelWithDebInfo/ to build/sql/
    "../tests/sql/",
    "../../tests/sql/",
    "../../../tests/sql/",  // From build/RelWithDebInfo/ to tests/sql/
};

std::string load_sql(const std::string& filename) {
    // Try each search path
    for (const auto& path : sql_search_paths) {
        std::string full_path = path + filename;
        std::ifstream file(full_path);
        if (file.is_open()) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            return buffer.str();
        }
    }

    // Try absolute path
    std::ifstream file(filename);
    if (file.is_open()) {
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    return "";  // File not found
}

std::string load_sql(const std::string& filename,
                     const std::map<std::string, std::string>& params) {
    std::string sql = load_sql(filename);

    // Replace ${param} with values
    for (const auto& [key, value] : params) {
        std::string placeholder = "${" + key + "}";
        size_t pos = 0;
        while ((pos = sql.find(placeholder, pos)) != std::string::npos) {
            sql.replace(pos, placeholder.length(), value);
            pos += value.length();
        }
    }

    return sql;
}

// ============================================================================
// Query Result
// ============================================================================

int QueryResult::col_index(const std::string& name) const {
    for (size_t i = 0; i < columns.size(); i++) {
        if (columns[i] == name) return static_cast<int>(i);
    }
    return -1;
}

std::string QueryResult::get(size_t row, size_t col) const {
    if (row >= rows.size()) return "";
    if (col >= rows[row].values.size()) return "";
    return rows[row].values[col];
}

std::string QueryResult::get(size_t row, const std::string& col_name) const {
    int idx = col_index(col_name);
    if (idx < 0) return "";
    return get(row, static_cast<size_t>(idx));
}

int64_t QueryResult::scalar_int() const {
    std::string val = scalar();
    if (val.empty()) return 0;
    return std::stoll(val);
}

double QueryResult::scalar_double() const {
    std::string val = scalar();
    if (val.empty()) return 0.0;
    return std::stod(val);
}

// ============================================================================
// Query Execution
// ============================================================================

static int query_callback(void* data, int argc, char** argv, char** col_names) {
    auto* result = static_cast<QueryResult*>(data);

    // Store column names on first row
    if (result->columns.empty()) {
        for (int i = 0; i < argc; i++) {
            result->columns.push_back(col_names[i] ? col_names[i] : "");
        }
    }

    // Store row values
    QueryRow row;
    for (int i = 0; i < argc; i++) {
        row.values.push_back(argv[i] ? argv[i] : "");
    }
    result->rows.push_back(row);

    return 0;
}

QueryResult exec_query(sqlite3* db, const std::string& sql) {
    QueryResult result;
    char* err_msg = nullptr;

    int rc = sqlite3_exec(db, sql.c_str(), query_callback, &result, &err_msg);
    if (rc != SQLITE_OK && err_msg) {
        // Store error in result
        result.columns.push_back("error");
        QueryRow row;
        row.values.push_back(err_msg);
        result.rows.push_back(row);
        sqlite3_free(err_msg);
    }

    return result;
}

bool exec_sql(sqlite3* db, const std::string& sql) {
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err_msg);
    if (err_msg) sqlite3_free(err_msg);
    return rc == SQLITE_OK;
}

QueryResult exec_sql_file(sqlite3* db, const std::string& filename) {
    std::string sql = load_sql(filename);
    if (sql.empty()) {
        QueryResult err;
        err.columns.push_back("error");
        QueryRow row;
        row.values.push_back("File not found: " + filename);
        err.rows.push_back(row);
        return err;
    }
    return exec_query(db, sql);
}

QueryResult exec_sql_file(sqlite3* db, const std::string& filename,
                          const std::map<std::string, std::string>& params) {
    std::string sql = load_sql(filename, params);
    if (sql.empty()) {
        QueryResult err;
        err.columns.push_back("error");
        QueryRow row;
        row.values.push_back("File not found: " + filename);
        err.rows.push_back(row);
        return err;
    }
    return exec_query(db, sql);
}

// ============================================================================
// Assertion Helpers
// ============================================================================

bool result_contains(const QueryResult& result, const std::string& value) {
    for (const auto& row : result.rows) {
        for (const auto& val : row.values) {
            if (val == value) return true;
        }
    }
    return false;
}

bool column_contains(const QueryResult& result, const std::string& col_name,
                     const std::string& value) {
    int idx = result.col_index(col_name);
    if (idx < 0) return false;

    for (const auto& row : result.rows) {
        if (static_cast<size_t>(idx) < row.values.size() &&
            row.values[idx] == value) {
            return true;
        }
    }
    return false;
}

bool first_row_matches(const QueryResult& result,
                       const std::vector<std::string>& expected) {
    if (result.rows.empty()) return expected.empty();

    const auto& row = result.rows[0];
    if (row.values.size() != expected.size()) return false;

    for (size_t i = 0; i < expected.size(); i++) {
        if (row.values[i] != expected[i]) return false;
    }
    return true;
}

} // namespace testing
} // namespace idasql
