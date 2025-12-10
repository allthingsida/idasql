/**
 * xrefs_table_test.cpp - Tests for the xrefs virtual table
 */

// Standard headers FIRST (before IDA SDK via test_fixtures.hpp)
#include <string>
#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include "test_fixtures.hpp"

using namespace idasql::testing;

class XrefsTableTest : public IDADatabaseTest {};

TEST_F(XrefsTableTest, TableExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='table' AND name='xrefs'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(XrefsTableTest, HasXrefs) {
    auto result = query("SELECT COUNT(*) FROM xrefs");
    EXPECT_GT(result.scalar_int(), 0);
}

TEST_F(XrefsTableTest, HasRequiredColumns) {
    auto result = query("SELECT from_ea, to_ea, type, is_code FROM xrefs LIMIT 1");
    EXPECT_EQ(result.col_count(), 4);
}

TEST_F(XrefsTableTest, MostCalledFromFile) {
    auto result = query_file("xrefs_most_called.sql");
    EXPECT_GT(result.row_count(), 0);

    // Verify ordering
    if (result.row_count() >= 2) {
        int64_t first = std::stoll(result.get(0, "caller_count"));
        int64_t second = std::stoll(result.get(1, "caller_count"));
        EXPECT_GE(first, second);
    }
}

TEST_F(XrefsTableTest, LeastCalledFromFile) {
    auto result = query_file("xrefs_least_called.sql");
    EXPECT_GT(result.row_count(), 0);

    // Verify ordering (ascending)
    if (result.row_count() >= 2) {
        int64_t first = std::stoll(result.get(0, "caller_count"));
        int64_t second = std::stoll(result.get(1, "caller_count"));
        EXPECT_LE(first, second);
    }
}

TEST_F(XrefsTableTest, IsCodeIsBinary) {
    auto result = query("SELECT COUNT(*) FROM xrefs WHERE is_code NOT IN (0, 1)");
    EXPECT_EQ(result.scalar_int(), 0) << "is_code should be 0 or 1";
}

TEST_F(XrefsTableTest, CodeXrefsPointToFunctions) {
    // Most code xrefs should point to function starts
    auto total_code = query("SELECT COUNT(*) FROM xrefs WHERE is_code = 1");
    auto to_funcs = query(
        "SELECT COUNT(*) FROM xrefs x "
        "WHERE x.is_code = 1 "
        "AND EXISTS (SELECT 1 FROM funcs f WHERE f.address = x.to_ea)"
    );

    if (total_code.scalar_int() > 0) {
        double ratio = static_cast<double>(to_funcs.scalar_int()) /
                       static_cast<double>(total_code.scalar_int());
        EXPECT_GT(ratio, 0.5) << "Most code xrefs should point to functions";
    }
}

TEST_F(XrefsTableTest, JoinWithFuncs) {
    auto result = query(
        "SELECT f.name, x.from_ea, x.type "
        "FROM funcs f "
        "JOIN xrefs x ON f.address = x.to_ea "
        "WHERE x.is_code = 1 "
        "LIMIT 10"
    );
    EXPECT_GT(result.row_count(), 0);
}

TEST_F(XrefsTableTest, CallerCountAggregation) {
    auto result = query(
        "SELECT to_ea, COUNT(*) as cnt "
        "FROM xrefs "
        "WHERE is_code = 1 "
        "GROUP BY to_ea "
        "ORDER BY cnt DESC "
        "LIMIT 5"
    );
    EXPECT_GT(result.row_count(), 0);
}
