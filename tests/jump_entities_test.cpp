/**
 * jump_entities_test.cpp - Tests for jump_entities table-valued function
 *
 * Tests the virtual table interface for unified entity search.
 */

// Standard headers FIRST (before IDA SDK via test_fixtures.hpp)
#include <string>
#include <vector>
#include <set>

#include <gtest/gtest.h>
#include "test_fixtures.hpp"

using namespace idasql::testing;

class JumpEntitiesTest : public IDADatabaseTest {};

// ============================================================================
// Basic Functionality Tests
// ============================================================================

TEST_F(JumpEntitiesTest, TableExists) {
    // Should be able to query the virtual table
    auto result = query("SELECT * FROM jump_entities('x', 'prefix') LIMIT 0");
    EXPECT_EQ(result.row_count(), 0) << "Empty result for unlikely pattern is OK";
}

TEST_F(JumpEntitiesTest, ReturnsCorrectColumns) {
    // Get column info by querying with a known function
    auto funcs = query("SELECT name FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string prefix = funcs.scalar().substr(0, 3);

    auto result = query(
        "SELECT name, kind, address, ordinal, parent_name, full_name "
        "FROM jump_entities('" + prefix + "', 'prefix') LIMIT 1"
    );

    ASSERT_GE(result.row_count(), 1) << "Should find at least one match";
    EXPECT_EQ(result.column_count(), 6) << "Should have 6 columns";
}

TEST_F(JumpEntitiesTest, PrefixModeWorks) {
    auto funcs = query("SELECT name FROM funcs WHERE name LIKE 'sub_%' LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No sub_ functions in database";
    }

    auto result = query("SELECT * FROM jump_entities('sub_', 'prefix') LIMIT 10");
    EXPECT_GE(result.row_count(), 1) << "Should find sub_ functions";

    // Verify all results start with 'sub_' (case-insensitive)
    for (const auto& row : result) {
        std::string name = row[0];
        std::string lower_name;
        for (char c : name) lower_name += std::tolower(c);
        EXPECT_TRUE(lower_name.substr(0, 4) == "sub_")
            << "Name '" << name << "' should start with 'sub_'";
    }
}

TEST_F(JumpEntitiesTest, ContainsModeWorks) {
    // Search for 'main' anywhere in name
    auto result = query("SELECT * FROM jump_entities('main', 'contains') LIMIT 20");

    // Verify all results contain 'main' (case-insensitive)
    for (const auto& row : result) {
        std::string name = row[0];
        std::string lower_name;
        for (char c : name) lower_name += std::tolower(c);
        EXPECT_TRUE(lower_name.find("main") != std::string::npos)
            << "Name '" << name << "' should contain 'main'";
    }
}

TEST_F(JumpEntitiesTest, EmptyPatternReturnsEmpty) {
    auto result = query("SELECT * FROM jump_entities('', 'prefix') LIMIT 10");
    EXPECT_EQ(result.row_count(), 0) << "Empty pattern should return no results";
}

TEST_F(JumpEntitiesTest, DefaultsToPrefixMode) {
    // If mode is not 'contains', should default to prefix
    auto funcs = query("SELECT name FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string prefix = funcs.scalar().substr(0, 3);

    // Use 'prefix' mode explicitly
    auto result1 = query("SELECT COUNT(*) FROM jump_entities('" + prefix + "', 'prefix') LIMIT 100");

    // Use an invalid mode - should default to prefix
    auto result2 = query("SELECT COUNT(*) FROM jump_entities('" + prefix + "', 'invalid') LIMIT 100");

    EXPECT_EQ(result1.scalar(), result2.scalar()) << "Invalid mode should default to prefix";
}

// ============================================================================
// Entity Kind Tests
// ============================================================================

TEST_F(JumpEntitiesTest, FindsFunctions) {
    auto funcs = query("SELECT name FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string prefix = funcs.scalar().substr(0, 3);

    auto result = query(
        "SELECT * FROM jump_entities('" + prefix + "', 'prefix') "
        "WHERE kind = 'function' LIMIT 10"
    );
    EXPECT_GE(result.row_count(), 1) << "Should find at least one function";
}

TEST_F(JumpEntitiesTest, FindsStructs) {
    auto types = query("SELECT name FROM types WHERE is_struct = 1 LIMIT 1");
    if (types.row_count() == 0) {
        GTEST_SKIP() << "No structs in database";
    }
    std::string prefix = types.scalar().substr(0, 3);

    auto result = query(
        "SELECT * FROM jump_entities('" + prefix + "', 'prefix') "
        "WHERE kind = 'struct' LIMIT 10"
    );
    EXPECT_GE(result.row_count(), 1) << "Should find at least one struct";
}

TEST_F(JumpEntitiesTest, FindsMembers) {
    auto members = query("SELECT member_name FROM types_members LIMIT 1");
    if (members.row_count() == 0) {
        GTEST_SKIP() << "No struct members in database";
    }
    std::string prefix = members.scalar().substr(0, 3);

    auto result = query(
        "SELECT * FROM jump_entities('" + prefix + "', 'prefix') "
        "WHERE kind = 'member' LIMIT 10"
    );
    EXPECT_GE(result.row_count(), 1) << "Should find at least one member";

    // Verify parent_name and full_name are populated for members
    for (const auto& row : result) {
        if (row[1] == "member") {
            EXPECT_FALSE(row[4].empty()) << "Member should have parent_name";
            EXPECT_TRUE(row[5].find('.') != std::string::npos)
                << "Member full_name should contain '.'";
        }
    }
}

TEST_F(JumpEntitiesTest, FindsEnums) {
    auto enums = query("SELECT name FROM types WHERE is_enum = 1 LIMIT 1");
    if (enums.row_count() == 0) {
        GTEST_SKIP() << "No enums in database";
    }
    std::string prefix = enums.scalar().substr(0, 3);

    auto result = query(
        "SELECT * FROM jump_entities('" + prefix + "', 'prefix') "
        "WHERE kind = 'enum' LIMIT 10"
    );
    EXPECT_GE(result.row_count(), 1) << "Should find at least one enum";
}

TEST_F(JumpEntitiesTest, FindsEnumMembers) {
    auto members = query("SELECT value_name FROM types_enum_values LIMIT 1");
    if (members.row_count() == 0) {
        GTEST_SKIP() << "No enum values in database";
    }
    std::string prefix = members.scalar().substr(0, 3);

    auto result = query(
        "SELECT * FROM jump_entities('" + prefix + "', 'prefix') "
        "WHERE kind = 'enum_member' LIMIT 10"
    );
    EXPECT_GE(result.row_count(), 1) << "Should find at least one enum member";
}

TEST_F(JumpEntitiesTest, KindColumnValues) {
    // Get all unique kinds from a broad search
    auto result = query(
        "SELECT DISTINCT kind FROM jump_entities('a', 'prefix') LIMIT 100"
    );

    std::set<std::string> valid_kinds = {
        "function", "label", "segment", "struct", "union", "enum", "member", "enum_member"
    };

    for (const auto& row : result) {
        EXPECT_TRUE(valid_kinds.count(row[0]) > 0)
            << "Kind '" << row[0] << "' should be a valid entity kind";
    }
}

// ============================================================================
// Pagination Tests
// ============================================================================

TEST_F(JumpEntitiesTest, LimitWorks) {
    auto result = query("SELECT * FROM jump_entities('sub', 'prefix') LIMIT 3");
    EXPECT_LE(result.row_count(), 3) << "Should respect LIMIT";
}

TEST_F(JumpEntitiesTest, OffsetWorks) {
    // Get first 5 results
    auto page1 = query("SELECT name FROM jump_entities('sub', 'prefix') LIMIT 5");
    if (page1.row_count() < 5) {
        GTEST_SKIP() << "Not enough results for pagination test";
    }

    // Get next 5 results
    auto page2 = query("SELECT name FROM jump_entities('sub', 'prefix') LIMIT 5 OFFSET 5");

    // First result of page2 should not be in page1
    if (page2.row_count() > 0) {
        std::string page2_first = page2[0][0];
        bool found_in_page1 = false;
        for (const auto& row : page1) {
            if (row[0] == page2_first) {
                found_in_page1 = true;
                break;
            }
        }
        EXPECT_FALSE(found_in_page1) << "Page 2 results should not overlap with page 1";
    }
}

// ============================================================================
// SQL Composability Tests (JOINs, WHERE, etc.)
// ============================================================================

TEST_F(JumpEntitiesTest, WhereClauseWorks) {
    auto result = query(
        "SELECT * FROM jump_entities('sub', 'prefix') "
        "WHERE kind = 'function' LIMIT 10"
    );

    for (const auto& row : result) {
        EXPECT_EQ(row[1], "function") << "WHERE filter should work";
    }
}

TEST_F(JumpEntitiesTest, JoinWithFuncsWorks) {
    auto result = query(
        "SELECT j.name, j.kind, f.size "
        "FROM jump_entities('sub', 'prefix') j "
        "LEFT JOIN funcs f ON j.address = f.address "
        "WHERE j.kind = 'function' "
        "LIMIT 5"
    );

    for (const auto& row : result) {
        EXPECT_FALSE(row[2].empty()) << "JOIN should get function size";
    }
}

TEST_F(JumpEntitiesTest, CountWorks) {
    auto result = query(
        "SELECT COUNT(*) FROM jump_entities('sub', 'prefix') LIMIT 100"
    );
    ASSERT_EQ(result.row_count(), 1);
    int count = std::stoi(result.scalar());
    EXPECT_GE(count, 0) << "COUNT should return a valid number";
}

TEST_F(JumpEntitiesTest, GroupByWorks) {
    auto result = query(
        "SELECT kind, COUNT(*) as cnt "
        "FROM jump_entities('a', 'prefix') "
        "GROUP BY kind "
        "LIMIT 20"
    );

    // Should have at least one group
    EXPECT_GE(result.row_count(), 1) << "GROUP BY should produce groups";
}

TEST_F(JumpEntitiesTest, OrderByWorks) {
    auto result = query(
        "SELECT name FROM jump_entities('sub', 'prefix') "
        "ORDER BY name ASC LIMIT 10"
    );

    if (result.row_count() >= 2) {
        std::string prev = result[0][0];
        for (size_t i = 1; i < result.row_count(); i++) {
            std::string curr = result[i][0];
            EXPECT_LE(prev, curr) << "Results should be in ascending order";
            prev = curr;
        }
    }
}

// ============================================================================
// Case Sensitivity Tests
// ============================================================================

TEST_F(JumpEntitiesTest, CaseInsensitiveSearch) {
    auto funcs = query("SELECT name FROM funcs WHERE name LIKE 'sub_%' LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No sub_ functions";
    }

    // Search with uppercase
    auto upper = query("SELECT COUNT(*) FROM jump_entities('SUB', 'prefix') LIMIT 100");
    // Search with lowercase
    auto lower = query("SELECT COUNT(*) FROM jump_entities('sub', 'prefix') LIMIT 100");
    // Search with mixed case
    auto mixed = query("SELECT COUNT(*) FROM jump_entities('SuB', 'prefix') LIMIT 100");

    EXPECT_EQ(upper.scalar(), lower.scalar()) << "Search should be case-insensitive";
    EXPECT_EQ(upper.scalar(), mixed.scalar()) << "Search should be case-insensitive";
}

// ============================================================================
// Edge Case Tests
// ============================================================================

TEST_F(JumpEntitiesTest, SpecialCharactersInPattern) {
    // Search for pattern with underscore (common in C names)
    auto result = query("SELECT * FROM jump_entities('sub_', 'prefix') LIMIT 5");
    // Should not crash, may or may not find results
    EXPECT_GE(result.row_count(), 0);
}

TEST_F(JumpEntitiesTest, VeryLongPatternHandled) {
    std::string long_pattern(100, 'a');
    auto result = query(
        "SELECT * FROM jump_entities('" + long_pattern + "', 'prefix') LIMIT 5"
    );
    // Should return empty (no match) but not crash
    EXPECT_EQ(result.row_count(), 0);
}

TEST_F(JumpEntitiesTest, SingleCharacterPattern) {
    auto result = query("SELECT * FROM jump_entities('a', 'prefix') LIMIT 10");
    // Should return results (many things start with 'a')
    EXPECT_GE(result.row_count(), 0);
}

// ============================================================================
// Address and Ordinal Tests
// ============================================================================

TEST_F(JumpEntitiesTest, FunctionsHaveAddresses) {
    auto result = query(
        "SELECT name, address FROM jump_entities('sub', 'prefix') "
        "WHERE kind = 'function' LIMIT 5"
    );

    for (const auto& row : result) {
        EXPECT_FALSE(row[1].empty()) << "Functions should have addresses";
        EXPECT_NE(row[1], "NULL") << "Function address should not be NULL";
    }
}

TEST_F(JumpEntitiesTest, TypesHaveOrdinals) {
    auto types = query("SELECT name FROM types WHERE is_struct = 1 LIMIT 1");
    if (types.row_count() == 0) {
        GTEST_SKIP() << "No structs in database";
    }
    std::string prefix = types.scalar().substr(0, 3);

    auto result = query(
        "SELECT name, ordinal FROM jump_entities('" + prefix + "', 'prefix') "
        "WHERE kind = 'struct' LIMIT 5"
    );

    for (const auto& row : result) {
        EXPECT_FALSE(row[1].empty()) << "Structs should have ordinals";
        EXPECT_NE(row[1], "NULL") << "Struct ordinal should not be NULL";
    }
}

TEST_F(JumpEntitiesTest, MembersHaveParentNames) {
    auto members = query("SELECT member_name FROM types_members LIMIT 1");
    if (members.row_count() == 0) {
        GTEST_SKIP() << "No members in database";
    }
    std::string prefix = members.scalar().substr(0, 3);

    auto result = query(
        "SELECT name, parent_name, full_name FROM jump_entities('" + prefix + "', 'prefix') "
        "WHERE kind = 'member' LIMIT 5"
    );

    for (const auto& row : result) {
        EXPECT_FALSE(row[1].empty()) << "Members should have parent_name";
        EXPECT_TRUE(row[2].find('.') != std::string::npos)
            << "Member full_name '" << row[2] << "' should be parent.member format";
    }
}
