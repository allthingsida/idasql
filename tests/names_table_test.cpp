/**
 * names_table_test.cpp - Tests for the names virtual table
 */

// Standard headers FIRST (before IDA SDK via test_fixtures.hpp)
#include <string>
#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include "test_fixtures.hpp"

using namespace idasql::testing;

class NamesTableTest : public IDADatabaseTest {};

TEST_F(NamesTableTest, TableExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='table' AND name='names'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(NamesTableTest, HasNames) {
    auto result = query("SELECT COUNT(*) FROM names");
    EXPECT_GT(result.scalar_int(), 0);
}

TEST_F(NamesTableTest, HasRequiredColumns) {
    auto result = query("SELECT address, name FROM names LIMIT 1");
    EXPECT_EQ(result.col_count(), 2);
}

TEST_F(NamesTableTest, NamesAreUnique) {
    auto result = query(
        "SELECT name, COUNT(*) as cnt "
        "FROM names "
        "GROUP BY name "
        "HAVING cnt > 1 "
        "LIMIT 10"
    );
    // Some duplicates might exist (locals), but should be minimal
    EXPECT_LT(result.row_count(), 10) << "Most names should be unique";
}

TEST_F(NamesTableTest, AddressesAreUnique) {
    auto result = query(
        "SELECT address, COUNT(*) as cnt "
        "FROM names "
        "GROUP BY address "
        "HAVING cnt > 1"
    );
    EXPECT_EQ(result.row_count(), 0) << "Each address should have one name";
}

TEST_F(NamesTableTest, NamesNotFuncsFromFile) {
    auto result = query_file("names_not_funcs.sql");
    // Should have some named data locations
    EXPECT_GT(result.row_count(), 0);
}

TEST_F(NamesTableTest, FunctionNamesInNames) {
    // All function starts should be in names
    auto funcs = query("SELECT COUNT(*) FROM funcs");
    auto named_funcs = query(
        "SELECT COUNT(*) FROM funcs f "
        "WHERE EXISTS (SELECT 1 FROM names n WHERE n.address = f.address)"
    );
    // Most functions should be named
    EXPECT_GT(named_funcs.scalar_int(), funcs.scalar_int() / 2);
}
