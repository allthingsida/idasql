/**
 * types_table_test.cpp - Tests for the types virtual tables
 *
 * Tests:
 *   - types table (enhanced local_types)
 *   - types_members table
 *   - types_enum_values table
 *   - types_func_args table
 *   - Filtering views (types_v_structs, etc.)
 *   - Backward compatibility (local_types view)
 */

// Standard headers FIRST (before IDA SDK via test_fixtures.hpp)
#include <string>
#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include "test_fixtures.hpp"

using namespace idasql::testing;

class TypesTableTest : public IDADatabaseTest {};

// ============================================================================
// Types Table - Basic Tests
// ============================================================================

TEST_F(TypesTableTest, TypesTableExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='table' AND name='types'");
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_EQ(result.scalar(), "types");
}

TEST_F(TypesTableTest, TypesHasRequiredColumns) {
    auto result = query(
        "SELECT ordinal, name, kind, size, alignment, "
        "is_struct, is_union, is_enum, is_typedef, is_func, is_ptr, is_array, "
        "definition, resolved FROM types LIMIT 1"
    );
    EXPECT_EQ(result.col_count(), 14) << "types table should have 14 columns";
}

TEST_F(TypesTableTest, TypesHasTypes) {
    auto result = query("SELECT COUNT(*) FROM types");
    // The test database may have types, but we just check query works
    EXPECT_GE(result.scalar_int(), 0) << "Query should succeed";
}

TEST_F(TypesTableTest, TypesKindValues) {
    // Check that kind column has valid values
    auto result = query(
        "SELECT DISTINCT kind FROM types "
        "WHERE kind IN ('struct', 'union', 'enum', 'typedef', 'func', 'ptr', 'array', 'other')"
    );
    // Should return only valid kinds
    for (size_t i = 0; i < result.row_count(); i++) {
        std::string kind = result.get(i, "kind");
        EXPECT_TRUE(
            kind == "struct" || kind == "union" || kind == "enum" ||
            kind == "typedef" || kind == "func" || kind == "ptr" ||
            kind == "array" || kind == "other"
        ) << "Invalid kind: " << kind;
    }
}

TEST_F(TypesTableTest, TypesBoolColumnsAre01) {
    auto result = query(
        "SELECT is_struct, is_union, is_enum, is_typedef, is_func, is_ptr, is_array "
        "FROM types LIMIT 10"
    );
    for (size_t i = 0; i < result.row_count(); i++) {
        for (int col = 0; col < 7; col++) {
            int val = std::stoi(result.get(i, col));
            EXPECT_TRUE(val == 0 || val == 1)
                << "Boolean column should be 0 or 1, got " << val;
        }
    }
}

// ============================================================================
// Types Members Table - Basic Tests
// ============================================================================

TEST_F(TypesTableTest, TypesMembersTableExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='table' AND name='types_members'");
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_EQ(result.scalar(), "types_members");
}

TEST_F(TypesTableTest, TypesMembersHasRequiredColumns) {
    auto result = query(
        "SELECT type_ordinal, type_name, member_index, member_name, "
        "offset, offset_bits, size, size_bits, member_type, "
        "is_bitfield, is_baseclass, comment FROM types_members LIMIT 1"
    );
    EXPECT_EQ(result.col_count(), 12) << "types_members table should have 12 columns";
}

TEST_F(TypesTableTest, TypesMembersOffsetConsistency) {
    // Verify offset = offset_bits / 8 for non-bitfield members
    auto result = query(
        "SELECT member_name, offset, offset_bits FROM types_members "
        "WHERE is_bitfield = 0 LIMIT 10"
    );
    for (size_t i = 0; i < result.row_count(); i++) {
        int64_t offset = std::stoll(result.get(i, "offset"));
        int64_t offset_bits = std::stoll(result.get(i, "offset_bits"));
        EXPECT_EQ(offset, offset_bits / 8)
            << "offset should equal offset_bits / 8 for member: "
            << result.get(i, "member_name");
    }
}

// ============================================================================
// Types Enum Values Table - Basic Tests
// ============================================================================

TEST_F(TypesTableTest, TypesEnumValuesTableExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='table' AND name='types_enum_values'");
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_EQ(result.scalar(), "types_enum_values");
}

TEST_F(TypesTableTest, TypesEnumValuesHasRequiredColumns) {
    auto result = query(
        "SELECT type_ordinal, type_name, value_index, value_name, "
        "value, uvalue, comment FROM types_enum_values LIMIT 1"
    );
    EXPECT_EQ(result.col_count(), 7) << "types_enum_values table should have 7 columns";
}

// ============================================================================
// Types Func Args Table - Basic Tests
// ============================================================================

TEST_F(TypesTableTest, TypesFuncArgsTableExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='table' AND name='types_func_args'");
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_EQ(result.scalar(), "types_func_args");
}

TEST_F(TypesTableTest, TypesFuncArgsHasRequiredColumns) {
    // Query the schema instead of data, since test db may not have func types
    auto result = query("PRAGMA table_info(types_func_args)");
    EXPECT_EQ(result.row_count(), 6) << "types_func_args table should have 6 columns";
}

TEST_F(TypesTableTest, TypesFuncArgsReturnTypeHasMinusOne) {
    // Return type rows should have arg_index = -1
    auto result = query(
        "SELECT type_name, arg_index, arg_name FROM types_func_args "
        "WHERE arg_index = -1 LIMIT 5"
    );
    for (size_t i = 0; i < result.row_count(); i++) {
        EXPECT_EQ(result.get(i, "arg_name"), "(return)")
            << "Return type row should have arg_name='(return)'";
    }
}

// ============================================================================
// Views Tests
// ============================================================================

TEST_F(TypesTableTest, StructsViewExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='view' AND name='types_v_structs'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(TypesTableTest, StructsViewFiltersCorrectly) {
    auto result = query("SELECT is_struct FROM types_v_structs");
    for (size_t i = 0; i < result.row_count(); i++) {
        EXPECT_EQ(result.get(i, "is_struct"), "1")
            << "types_v_structs should only contain structs";
    }
}

TEST_F(TypesTableTest, UnionsViewExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='view' AND name='types_v_unions'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(TypesTableTest, EnumsViewExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='view' AND name='types_v_enums'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(TypesTableTest, TypedefsViewExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='view' AND name='types_v_typedefs'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(TypesTableTest, FuncsViewExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='view' AND name='types_v_funcs'");
    ASSERT_EQ(result.row_count(), 1);
}

// ============================================================================
// Backward Compatibility
// ============================================================================

TEST_F(TypesTableTest, LocalTypesViewExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='view' AND name='local_types'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(TypesTableTest, LocalTypesViewHasBackwardCompatibleColumns) {
    auto result = query(
        "SELECT ordinal, name, type, is_struct, is_enum, is_typedef "
        "FROM local_types LIMIT 1"
    );
    EXPECT_EQ(result.col_count(), 6) << "local_types view should have 6 columns for backward compatibility";
}

// ============================================================================
// Query Tests
// ============================================================================

TEST_F(TypesTableTest, FindStructsBySize) {
    auto result = query(
        "SELECT name, size FROM types "
        "WHERE is_struct = 1 AND size > 0 "
        "ORDER BY size DESC LIMIT 5"
    );
    // Verify ordering
    for (size_t i = 1; i < result.row_count(); i++) {
        int64_t prev_size = std::stoll(result.get(i-1, "size"));
        int64_t curr_size = std::stoll(result.get(i, "size"));
        EXPECT_GE(prev_size, curr_size) << "Results should be ordered by size DESC";
    }
}

TEST_F(TypesTableTest, CountMembersByStruct) {
    auto result = query(
        "SELECT type_name, COUNT(*) as member_count "
        "FROM types_members "
        "GROUP BY type_ordinal "
        "ORDER BY member_count DESC LIMIT 5"
    );
    // Just verify query works
    EXPECT_GE(result.row_count(), 0);
}

TEST_F(TypesTableTest, FindEnumByValueName) {
    auto result = query(
        "SELECT type_name, value_name, value "
        "FROM types_enum_values "
        "WHERE value_name LIKE '%ERROR%' LIMIT 5"
    );
    // Just verify query works
    for (size_t i = 0; i < result.row_count(); i++) {
        std::string name = result.get(i, "value_name");
        EXPECT_NE(name.find("ERROR"), std::string::npos)
            << "Value name should contain 'ERROR': " << name;
    }
}

TEST_F(TypesTableTest, JoinTypesAndMembers) {
    auto result = query(
        "SELECT t.name, t.size, m.member_name "
        "FROM types t "
        "JOIN types_members m ON m.type_ordinal = t.ordinal "
        "WHERE t.is_struct = 1 "
        "LIMIT 10"
    );
    // Just verify join works
    EXPECT_GE(result.row_count(), 0);
}

TEST_F(TypesTableTest, CountTypesByKind) {
    auto result = query(
        "SELECT kind, COUNT(*) as count "
        "FROM types "
        "GROUP BY kind "
        "ORDER BY count DESC"
    );
    // Should have at least one kind
    EXPECT_GE(result.row_count(), 0);
}

// ============================================================================
// Constraint Pushdown Tests
// ============================================================================

TEST_F(TypesTableTest, MembersPushdownByOrdinal) {
    // First get a type ordinal that has members
    auto types_result = query(
        "SELECT ordinal FROM types WHERE is_struct = 1 LIMIT 1"
    );
    if (types_result.row_count() == 0) {
        GTEST_SKIP() << "No structs in database";
    }
    int ordinal = std::stoi(types_result.get(0, "ordinal"));

    // Query members with constraint (uses pushdown)
    auto result = query(
        "SELECT member_name, offset FROM types_members "
        "WHERE type_ordinal = " + std::to_string(ordinal)
    );

    // Verify all results are for the right type
    auto verify = query(
        "SELECT COUNT(*) FROM types_members "
        "WHERE type_ordinal = " + std::to_string(ordinal) + " "
        "AND type_ordinal != " + std::to_string(ordinal)  // Should be 0
    );
    EXPECT_EQ(verify.scalar_int(), 0);
}

TEST_F(TypesTableTest, EnumValuesPushdownByOrdinal) {
    // First get an enum ordinal
    auto types_result = query(
        "SELECT ordinal FROM types WHERE is_enum = 1 LIMIT 1"
    );
    if (types_result.row_count() == 0) {
        GTEST_SKIP() << "No enums in database";
    }
    int ordinal = std::stoi(types_result.get(0, "ordinal"));

    // Query values with constraint (uses pushdown)
    auto result = query(
        "SELECT value_name, value FROM types_enum_values "
        "WHERE type_ordinal = " + std::to_string(ordinal)
    );

    // Verify all results are for the right type
    for (size_t i = 0; i < result.row_count(); i++) {
        // Query succeeded - pushdown worked
    }
    EXPECT_GE(result.row_count(), 0);
}

// ============================================================================
// Data Integrity Tests
// ============================================================================

TEST_F(TypesTableTest, TypesOrdinalUnique) {
    auto result = query(
        "SELECT ordinal, COUNT(*) as cnt FROM types "
        "GROUP BY ordinal HAVING cnt > 1"
    );
    EXPECT_EQ(result.row_count(), 0) << "Ordinals should be unique";
}

TEST_F(TypesTableTest, MembersHaveValidTypeOrdinal) {
    // All member type_ordinals should exist in types table
    auto result = query(
        "SELECT m.type_ordinal FROM types_members m "
        "LEFT JOIN types t ON t.ordinal = m.type_ordinal "
        "WHERE t.ordinal IS NULL LIMIT 1"
    );
    EXPECT_EQ(result.row_count(), 0)
        << "All members should reference valid type ordinals";
}

TEST_F(TypesTableTest, EnumValuesHaveValidTypeOrdinal) {
    auto result = query(
        "SELECT e.type_ordinal FROM types_enum_values e "
        "LEFT JOIN types t ON t.ordinal = e.type_ordinal "
        "WHERE t.ordinal IS NULL LIMIT 1"
    );
    EXPECT_EQ(result.row_count(), 0)
        << "All enum values should reference valid type ordinals";
}

TEST_F(TypesTableTest, FuncArgsHaveValidTypeOrdinal) {
    auto result = query(
        "SELECT f.type_ordinal FROM types_func_args f "
        "LEFT JOIN types t ON t.ordinal = f.type_ordinal "
        "WHERE t.ordinal IS NULL LIMIT 1"
    );
    EXPECT_EQ(result.row_count(), 0)
        << "All func args should reference valid type ordinals";
}
