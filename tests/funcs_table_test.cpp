/**
 * funcs_table_test.cpp - Tests for the funcs virtual table
 */

// Standard headers FIRST (before IDA SDK via test_fixtures.hpp)
#include <string>
#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include "test_fixtures.hpp"

using namespace idasql::testing;

class FuncsTableTest : public IDADatabaseTest {};

// ============================================================================
// Basic Tests
// ============================================================================

TEST_F(FuncsTableTest, TableExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='table' AND name='funcs'");
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_EQ(result.scalar(), "funcs");
}

TEST_F(FuncsTableTest, HasFunctions) {
    auto result = query("SELECT COUNT(*) FROM funcs");
    EXPECT_GT(result.scalar_int(), 0) << "Database should have at least one function";
}

TEST_F(FuncsTableTest, CountFromFile) {
    auto result = query_file("funcs_count.sql");
    ASSERT_GE(result.row_count(), 1) << "Should return at least one row";
    // The SQL returns 'count' column - use scalar_int() which handles conversion
    EXPECT_GT(result.scalar_int(), 0);
}

// ============================================================================
// Column Tests
// ============================================================================

TEST_F(FuncsTableTest, HasRequiredColumns) {
    auto result = query("SELECT address, name, size, end_ea, flags FROM funcs LIMIT 1");
    ASSERT_GE(result.row_count(), 1);
    EXPECT_EQ(result.col_count(), 5);
}

TEST_F(FuncsTableTest, AddressesAreValid) {
    auto result = query("SELECT address FROM funcs WHERE address <= 0");
    EXPECT_EQ(result.row_count(), 0) << "All addresses should be positive";
}

TEST_F(FuncsTableTest, SizesArePositive) {
    auto result = query("SELECT COUNT(*) FROM funcs WHERE size <= 0");
    // Some functions might have 0 size (thunks), but most should be positive
    auto total = query("SELECT COUNT(*) FROM funcs");
    auto zero_size = result.scalar_int();
    auto total_count = total.scalar_int();
    EXPECT_LT(zero_size, total_count / 2) << "Most functions should have positive size";
}

TEST_F(FuncsTableTest, EndEaAfterStartEa) {
    auto result = query("SELECT COUNT(*) FROM funcs WHERE end_ea < address");
    EXPECT_EQ(result.scalar_int(), 0) << "end_ea should always be >= address";
}

// ============================================================================
// Query Tests
// ============================================================================

TEST_F(FuncsTableTest, Top10LargestFromFile) {
    auto result = query_file("funcs_top10_largest.sql");
    // Should return up to 10 functions (or fewer if database has less)
    EXPECT_GE(result.row_count(), 1) << "Should have at least 1 function";
    EXPECT_LE(result.row_count(), 10) << "Should return at most 10";

    // Verify ordering (largest first)
    if (result.row_count() >= 2) {
        int64_t first_size = std::stoll(result.get(0, "size"));
        int64_t second_size = std::stoll(result.get(1, "size"));
        EXPECT_GE(first_size, second_size) << "Results should be ordered by size DESC";
    }
}

TEST_F(FuncsTableTest, FilterByPrefix) {
    // Get any function name to use as prefix
    auto funcs = query("SELECT name FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string first_name = funcs.get(0, "name");
    std::string prefix = first_name.substr(0, std::min(size_t(3), first_name.size()));

    auto result = query_file("funcs_by_prefix.sql", {{"prefix", prefix}});
    // All results should start with the prefix
    for (size_t i = 0; i < result.row_count(); i++) {
        std::string name = result.get(i, "name");
        EXPECT_EQ(name.substr(0, prefix.size()), prefix)
            << "Function should start with '" << prefix << "'";
    }
}

TEST_F(FuncsTableTest, FilterBySize) {
    auto result = query(
        "SELECT name, size FROM funcs "
        "WHERE size > 100 AND size < 500 "
        "ORDER BY size DESC LIMIT 5"
    );

    for (size_t i = 0; i < result.row_count(); i++) {
        int64_t size = std::stoll(result.get(i, "size"));
        EXPECT_GT(size, 100);
        EXPECT_LT(size, 500);
    }
}

TEST_F(FuncsTableTest, GroupBySize) {
    auto result = query(
        "SELECT "
        "  CASE "
        "    WHEN size < 16 THEN 'tiny' "
        "    WHEN size < 64 THEN 'small' "
        "    WHEN size < 256 THEN 'medium' "
        "    ELSE 'large' "
        "  END as category, "
        "  COUNT(*) as count "
        "FROM funcs "
        "GROUP BY category"
    );

    EXPECT_GE(result.row_count(), 1) << "Should have at least one size category";
}

// ============================================================================
// Pagination Tests
// ============================================================================

TEST_F(FuncsTableTest, PaginationWorks) {
    // Get page 1
    auto page1 = query("SELECT address FROM funcs ORDER BY address LIMIT 10 OFFSET 0");
    // Get page 2
    auto page2 = query("SELECT address FROM funcs ORDER BY address LIMIT 10 OFFSET 10");

    if (page1.row_count() >= 10 && page2.row_count() >= 1) {
        // First item of page 2 should be different from first item of page 1
        EXPECT_NE(page1.get(0, "address"), page2.get(0, "address"));

        // Last item of page 1 should be before first item of page 2
        int64_t last_p1 = std::stoll(page1.get(9, "address"));
        int64_t first_p2 = std::stoll(page2.get(0, "address"));
        EXPECT_LT(last_p1, first_p2);
    }
}

// ============================================================================
// Name Search Tests
// ============================================================================

TEST_F(FuncsTableTest, NameSearchWithLike) {
    auto result = query("SELECT name FROM funcs WHERE name LIKE '%main%' LIMIT 5");
    for (size_t i = 0; i < result.row_count(); i++) {
        std::string name = result.get(i, "name");
        EXPECT_NE(name.find("main"), std::string::npos)
            << "Name should contain 'main': " << name;
    }
}
