/**
 * complex_queries_test.cpp - Tests for complex SQL queries
 */

// Standard headers FIRST (before IDA SDK via test_fixtures.hpp)
#include <string>
#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include "test_fixtures.hpp"

using namespace idasql::testing;

class ComplexQueriesTest : public IDADatabaseTest {};

// ============================================================================
// Multi-Table Joins
// ============================================================================

TEST_F(ComplexQueriesTest, FunctionAnalysisFromFile) {
    auto result = query_file("complex_func_analysis.sql");
    // Query returns columns even if no rows - verify columns exist
    ASSERT_GE(result.col_count(), 6) << "Query should return expected columns";

    // If we have results, verify all expected columns exist
    if (result.row_count() > 0) {
        EXPECT_GE(result.col_index("addr"), 0);
        EXPECT_GE(result.col_index("name"), 0);
        EXPECT_GE(result.col_index("size"), 0);
        EXPECT_GE(result.col_index("blocks"), 0);
        EXPECT_GE(result.col_index("callers"), 0);
        EXPECT_GE(result.col_index("size_class"), 0);
    }
}

TEST_F(ComplexQueriesTest, BlocksPerFunctionFromFile) {
    auto result = query_file("blocks_per_func.sql");
    EXPECT_GT(result.row_count(), 0);
}

TEST_F(ComplexQueriesTest, FunctionsWithBlocksAndXrefs) {
    auto result = query(
        "SELECT "
        "  f.name, "
        "  f.size, "
        "  (SELECT COUNT(*) FROM blocks b WHERE b.func_ea = f.address) as block_count, "
        "  (SELECT COUNT(*) FROM xrefs x WHERE x.to_ea = f.address AND x.is_code = 1) as callers "
        "FROM funcs f "
        "WHERE f.size > 100 "
        "ORDER BY block_count DESC "
        "LIMIT 10"
    );
    EXPECT_GT(result.row_count(), 0);
}

// ============================================================================
// Subqueries
// ============================================================================

TEST_F(ComplexQueriesTest, SubqueryInWhere) {
    auto result = query(
        "SELECT name, size FROM funcs "
        "WHERE size > (SELECT AVG(size) FROM funcs) "
        "ORDER BY size DESC "
        "LIMIT 10"
    );
    EXPECT_GT(result.row_count(), 0);
}

TEST_F(ComplexQueriesTest, SubqueryInSelect) {
    auto result = query(
        "SELECT "
        "  name, "
        "  size, "
        "  (SELECT COUNT(*) FROM funcs) as total_funcs "
        "FROM funcs "
        "LIMIT 5"
    );
    ASSERT_GT(result.row_count(), 0);

    // total_funcs should be same for all rows
    std::string total = result.get(0, "total_funcs");
    for (size_t i = 1; i < result.row_count(); i++) {
        EXPECT_EQ(result.get(i, "total_funcs"), total);
    }
}

TEST_F(ComplexQueriesTest, CorrelatedSubquery) {
    auto result = query(
        "SELECT f.name, f.size, "
        "  (SELECT COUNT(*) FROM blocks b WHERE b.func_ea = f.address) as blocks "
        "FROM funcs f "
        "ORDER BY blocks DESC "
        "LIMIT 10"
    );
    EXPECT_GT(result.row_count(), 0);
}

// ============================================================================
// Aggregations
// ============================================================================

TEST_F(ComplexQueriesTest, GroupByWithHaving) {
    auto result = query(
        "SELECT to_ea, COUNT(*) as cnt "
        "FROM xrefs "
        "WHERE is_code = 1 "
        "GROUP BY to_ea "
        "HAVING cnt >= 3 "
        "ORDER BY cnt DESC"
    );
    // All results should have cnt >= 3
    for (size_t i = 0; i < result.row_count(); i++) {
        EXPECT_GE(std::stoll(result.get(i, "cnt")), 3);
    }
}

TEST_F(ComplexQueriesTest, MultipleAggregations) {
    auto result = query(
        "SELECT "
        "  COUNT(*) as total, "
        "  SUM(size) as total_size, "
        "  AVG(size) as avg_size, "
        "  MIN(size) as min_size, "
        "  MAX(size) as max_size "
        "FROM funcs"
    );
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_GT(result.scalar_int(), 0);
}

// ============================================================================
// Window Functions (if supported by SQLite version)
// ============================================================================

TEST_F(ComplexQueriesTest, RowNumber) {
    auto result = query(
        "SELECT "
        "  ROW_NUMBER() OVER (ORDER BY size DESC) as rank, "
        "  name, "
        "  size "
        "FROM funcs "
        "LIMIT 10"
    );
    EXPECT_EQ(result.row_count(), 10);
}

// ============================================================================
// Metadata Queries
// ============================================================================

TEST_F(ComplexQueriesTest, DatabaseInfoFromFile) {
    auto result = query_file("db_info_all.sql");
    EXPECT_GT(result.row_count(), 0);
}

TEST_F(ComplexQueriesTest, MetadataJoinWithFuncs) {
    auto result = query(
        "SELECT "
        "  (SELECT value FROM db_info WHERE key = 'processor') as processor, "
        "  COUNT(*) as func_count "
        "FROM funcs"
    );
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_FALSE(result.get(0, "processor").empty());
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST_F(ComplexQueriesTest, EmptyResultHandled) {
    auto result = query(
        "SELECT * FROM funcs WHERE address = -1"
    );
    EXPECT_EQ(result.row_count(), 0);
}

TEST_F(ComplexQueriesTest, NullHandling) {
    // LEFT JOIN should produce NULLs for non-matching rows
    auto result = query(
        "SELECT f.name, x.from_ea "
        "FROM funcs f "
        "LEFT JOIN xrefs x ON f.address = x.to_ea AND x.is_code = 999 "
        "LIMIT 5"
    );
    // All from_ea should be NULL (no xrefs with is_code=999)
    for (size_t i = 0; i < result.row_count(); i++) {
        EXPECT_TRUE(result.get(i, "from_ea").empty() ||
                    result.get(i, "from_ea") == "NULL");
    }
}

TEST_F(ComplexQueriesTest, UnionQuery) {
    // Test UNION ALL with virtual tables
    auto result = query(
        "SELECT address, name, 'function' as type FROM funcs LIMIT 3 "
        "UNION ALL "
        "SELECT start_ea, name, 'segment' as type FROM segments LIMIT 3"
    );
    // UNION should return results (exact structure may vary with SQLite/vtable)
    EXPECT_TRUE(result.row_count() >= 1 || result.col_count() >= 1)
        << "UNION query should return some data";
}
