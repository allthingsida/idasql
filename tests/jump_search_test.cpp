/**
 * jump_search_test.cpp - Tests for jump_search unified entity search
 */

// Standard headers FIRST (before IDA SDK via test_fixtures.hpp)
#include <string>
#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include "test_fixtures.hpp"

using namespace idasql::testing;

class JumpSearchTest : public IDADatabaseTest {};

// ============================================================================
// jump_query Function Tests (returns SQL string)
// ============================================================================

TEST_F(JumpSearchTest, JumpQueryReturnsSQL) {
    auto result = query("SELECT jump_query('test', 'prefix', 10, 0)");
    ASSERT_EQ(result.row_count(), 1);
    std::string sql = result.scalar();
    EXPECT_TRUE(sql.find("SELECT") != std::string::npos) << "Should return a SELECT statement";
    EXPECT_TRUE(sql.find("LIKE 'test%'") != std::string::npos) << "Should use prefix pattern";
}

TEST_F(JumpSearchTest, JumpQueryContainsMode) {
    auto result = query("SELECT jump_query('test', 'contains', 10, 0)");
    ASSERT_EQ(result.row_count(), 1);
    std::string sql = result.scalar();
    EXPECT_TRUE(sql.find("LIKE '%test%'") != std::string::npos) << "Should use contains pattern";
}

TEST_F(JumpSearchTest, JumpQueryLimitOffset) {
    auto result = query("SELECT jump_query('x', 'prefix', 50, 100)");
    ASSERT_EQ(result.row_count(), 1);
    std::string sql = result.scalar();
    EXPECT_TRUE(sql.find("LIMIT 50") != std::string::npos) << "Should include LIMIT";
    EXPECT_TRUE(sql.find("OFFSET 100") != std::string::npos) << "Should include OFFSET";
}

TEST_F(JumpSearchTest, JumpQueryEscapesSingleQuotes) {
    auto result = query("SELECT jump_query('test''quote', 'prefix', 10, 0)");
    ASSERT_EQ(result.row_count(), 1);
    std::string sql = result.scalar();
    // Should have escaped quotes
    EXPECT_TRUE(sql.find("''''") != std::string::npos || sql.find("test''quote") != std::string::npos)
        << "Should escape single quotes";
}

// ============================================================================
// jump_search Function Tests (returns JSON)
// ============================================================================

TEST_F(JumpSearchTest, JumpSearchReturnsJSON) {
    auto result = query("SELECT jump_search('main', 'prefix', 10, 0)");
    ASSERT_EQ(result.row_count(), 1);
    std::string json = result.scalar();
    EXPECT_TRUE(json[0] == '[') << "Should return a JSON array";
    EXPECT_TRUE(json.back() == ']') << "JSON should end with ]";
}

TEST_F(JumpSearchTest, JumpSearchFindsFunction) {
    // First, get a real function name from the database
    auto funcs = query("SELECT name FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string func_name = funcs.scalar();

    // Take first 3 chars as prefix
    std::string prefix = func_name.substr(0, std::min(size_t(3), func_name.size()));

    // Search for it
    std::string sql = "SELECT jump_search('" + prefix + "', 'prefix', 50, 0)";
    auto result = query(sql);
    ASSERT_EQ(result.row_count(), 1);
    std::string json = result.scalar();

    // Should find at least one result with kind "function"
    EXPECT_TRUE(json.find("\"kind\":\"function\"") != std::string::npos)
        << "Should find at least one function";
}

TEST_F(JumpSearchTest, JumpSearchFindsStruct) {
    // Check if there are any structs
    auto structs = query("SELECT name FROM types WHERE is_struct = 1 LIMIT 1");
    if (structs.row_count() == 0) {
        GTEST_SKIP() << "No structs in database";
    }
    std::string struct_name = structs.scalar();

    // Take first 3 chars as prefix
    std::string prefix = struct_name.substr(0, std::min(size_t(3), struct_name.size()));

    // Search for it
    std::string sql = "SELECT jump_search('" + prefix + "', 'prefix', 50, 0)";
    auto result = query(sql);
    ASSERT_EQ(result.row_count(), 1);
    std::string json = result.scalar();

    // Should find at least one result with kind "struct"
    EXPECT_TRUE(json.find("\"kind\":\"struct\"") != std::string::npos)
        << "Should find at least one struct";
}

TEST_F(JumpSearchTest, JumpSearchPagination) {
    // Get a common prefix
    auto result1 = query("SELECT jump_search('sub_', 'prefix', 5, 0)");
    auto result2 = query("SELECT jump_search('sub_', 'prefix', 5, 5)");

    // Both should be valid JSON arrays
    std::string json1 = result1.scalar();
    std::string json2 = result2.scalar();

    EXPECT_TRUE(json1[0] == '[' && json1.back() == ']') << "Page 1 should be valid JSON array";
    EXPECT_TRUE(json2[0] == '[' && json2.back() == ']') << "Page 2 should be valid JSON array";
}

TEST_F(JumpSearchTest, JumpSearchContainsModeWorks) {
    // Get a function name with at least 4 chars
    auto funcs = query("SELECT name FROM funcs WHERE length(name) > 6 LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No long function names in database";
    }
    std::string func_name = funcs.scalar();

    // Take middle chars as contains pattern
    std::string pattern = func_name.substr(2, 3);

    // Search with contains mode
    std::string sql = "SELECT jump_search('" + pattern + "', 'contains', 50, 0)";
    auto result = query(sql);
    std::string json = result.scalar();

    // Should find at least one result
    EXPECT_NE(json, "[]") << "Contains search should find results for pattern: " << pattern;
}

TEST_F(JumpSearchTest, JumpSearchEmptyPrefixReturnsEmptyArray) {
    auto result = query("SELECT jump_search('', 'prefix', 10, 0)");
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_EQ(result.scalar(), "[]") << "Empty prefix should return empty array";
}

TEST_F(JumpSearchTest, JumpSearchCaseInsensitive) {
    // Get a function name
    auto funcs = query("SELECT name FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string func_name = funcs.scalar();

    // Convert to uppercase for search
    std::string upper_prefix;
    for (char c : func_name.substr(0, 3)) {
        upper_prefix += std::toupper(c);
    }

    // Search with uppercase
    std::string sql = "SELECT jump_search('" + upper_prefix + "', 'prefix', 50, 0)";
    auto result = query(sql);
    std::string json = result.scalar();

    // Should find results (case insensitive)
    EXPECT_NE(json, "[]") << "Case-insensitive search should find results";
}

// ============================================================================
// Generated Query Execution Tests
// ============================================================================

TEST_F(JumpSearchTest, GeneratedQueryExecutesSuccessfully) {
    // Get the query
    auto query_result = query("SELECT jump_query('main', 'prefix', 10, 0)");
    std::string sql = query_result.scalar();

    // Execute the generated query directly
    auto result = query(sql);

    // Should succeed (even if no results)
    EXPECT_GE(result.row_count(), 0) << "Generated query should execute successfully";
}

TEST_F(JumpSearchTest, ResultColumnsCorrect) {
    // Get the query
    auto query_result = query("SELECT jump_query('a', 'prefix', 5, 0)");
    std::string sql = query_result.scalar();

    // Execute the generated query directly
    auto result = query(sql);

    if (result.row_count() > 0) {
        // Check column count
        EXPECT_EQ(result.col_count(), 6) << "Should have 6 columns";

        // Check column names
        EXPECT_NE(result.col_index("name"), -1);
        EXPECT_NE(result.col_index("kind"), -1);
        EXPECT_NE(result.col_index("address"), -1);
        EXPECT_NE(result.col_index("ordinal"), -1);
        EXPECT_NE(result.col_index("parent_name"), -1);
        EXPECT_NE(result.col_index("full_name"), -1);
    }
}
