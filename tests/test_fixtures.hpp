/**
 * test_fixtures.hpp - Test fixtures for IDASQL tests
 *
 * Provides:
 *   - IDADatabaseTest: Base fixture with IDA database loaded
 *   - SQLiteOnlyTest: SQLite-only tests (no IDA database)
 *   - MetadataTest: Tests for metadata tables
 *
 * NOTE: Standard library headers MUST come before IDA SDK headers
 * because IDA SDK redefines some C functions (fgetc, getenv, etc.)
 */

#pragma once

// Standard library headers FIRST
#include <string>
#include <map>
#include <vector>

#include <gtest/gtest.h>
#include <sqlite3.h>

// IDA SDK (must come after standard headers)
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <auto.hpp>
#include <idalib.hpp>

// IDASQL headers (new namespace)
#include <idasql/vtable.hpp>
#include <idasql/entities.hpp>
#include <idasql/metadata.hpp>
#include "test_utils.hpp"

namespace idasql {
namespace testing {

// ============================================================================
// Test Database Path (set via command line or env)
// ============================================================================

inline std::string& get_test_database_path() {
    static std::string path;
    return path;
}

inline void set_test_database_path(const std::string& path) {
    get_test_database_path() = path;
}

// ============================================================================
// SQLite-Only Test Fixture
// Tests virtual table framework without IDA database
// ============================================================================

class SQLiteOnlyTest : public ::testing::Test {
protected:
    sqlite3* db_ = nullptr;

    void SetUp() override {
        int rc = sqlite3_open(":memory:", &db_);
        ASSERT_EQ(rc, SQLITE_OK) << "Failed to open SQLite database";
    }

    void TearDown() override {
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

    // Helper to execute SQL
    QueryResult query(const std::string& sql) {
        return exec_query(db_, sql);
    }

    // Helper to execute SQL from file
    QueryResult query_file(const std::string& filename) {
        return exec_sql_file(db_, filename);
    }

    QueryResult query_file(const std::string& filename,
                           const std::map<std::string, std::string>& params) {
        return exec_sql_file(db_, filename, params);
    }
};

// ============================================================================
// IDA Database Test Fixture
// Full tests with IDA database loaded
// ============================================================================

class IDADatabaseTest : public ::testing::Test {
protected:
    sqlite3* db_ = nullptr;
    entities::TableRegistry* entities_ = nullptr;
    metadata::MetadataRegistry* metadata_ = nullptr;

    static bool ida_initialized_;
    static bool database_loaded_;

    static void SetUpTestSuite() {
        if (!ida_initialized_) {
            int rc = init_library();
            ASSERT_EQ(rc, 0) << "Failed to initialize IDA library";
            ida_initialized_ = true;
        }

        if (!database_loaded_ && !get_test_database_path().empty()) {
            int rc = open_database(get_test_database_path().c_str(), true, nullptr);
            ASSERT_EQ(rc, 0) << "Failed to open database: " << get_test_database_path();
            auto_wait();
            database_loaded_ = true;
        }
    }

    static void TearDownTestSuite() {
        if (database_loaded_) {
            close_database(false);
            database_loaded_ = false;
        }
    }

    void SetUp() override {
        // Open in-memory SQLite
        int rc = sqlite3_open(":memory:", &db_);
        ASSERT_EQ(rc, SQLITE_OK) << "Failed to open SQLite database";

        // Register entity tables
        entities_ = new entities::TableRegistry();
        entities_->register_all(db_);

        // Register metadata tables
        metadata_ = new metadata::MetadataRegistry();
        metadata_->register_all(db_);
    }

    void TearDown() override {
        delete entities_;
        delete metadata_;
        entities_ = nullptr;
        metadata_ = nullptr;

        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

    // Helper to execute SQL
    QueryResult query(const std::string& sql) {
        return exec_query(db_, sql);
    }

    // Helper to execute SQL from file
    QueryResult query_file(const std::string& filename) {
        return exec_sql_file(db_, filename);
    }

    QueryResult query_file(const std::string& filename,
                           const std::map<std::string, std::string>& params) {
        return exec_sql_file(db_, filename, params);
    }

    // Expect query to return at least N rows
    void expect_min_rows(const std::string& sql, size_t min_count) {
        auto result = query(sql);
        EXPECT_GE(result.row_count(), min_count)
            << "Query: " << sql;
    }

    // Expect query to return exactly N rows
    void expect_row_count(const std::string& sql, size_t expected) {
        auto result = query(sql);
        EXPECT_EQ(result.row_count(), expected)
            << "Query: " << sql;
    }
};

// Static member initialization
inline bool IDADatabaseTest::ida_initialized_ = false;
inline bool IDADatabaseTest::database_loaded_ = false;

// ============================================================================
// Metadata-Only Test Fixture
// Tests that work with just metadata (may not need full database)
// ============================================================================

class MetadataTest : public IDADatabaseTest {
    // Same as IDADatabaseTest, just a semantic distinction
};

} // namespace testing
} // namespace idasql
