/**
 * vtable_framework_test.cpp - Tests for the virtual table framework
 */

// Standard headers FIRST (before IDA SDK via test_fixtures.hpp)
#include <string>
#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include "test_fixtures.hpp"

using namespace idasql::testing;

// ============================================================================
// Framework Tests (SQLite only, no IDA database needed)
// ============================================================================

class VTableFrameworkTest : public SQLiteOnlyTest {};

TEST_F(VTableFrameworkTest, CanCreateEmptyTable) {
    // Create a simple virtual table with hardcoded data
    static std::vector<std::pair<int, std::string>> test_data = {
        {1, "one"},
        {2, "two"},
        {3, "three"}
    };

    auto test_table = idasql::table("test_table")
        .count([]() { return test_data.size(); })
        .column_int("id", [](size_t i) { return test_data[i].first; })
        .column_text("name", [](size_t i) { return test_data[i].second; })
        .build();

    idasql::register_vtable(db_, "test_module", &test_table);
    idasql::create_vtable(db_, "test", "test_module");

    auto result = query("SELECT * FROM test");
    EXPECT_EQ(result.row_count(), 3);
}

TEST_F(VTableFrameworkTest, ColumnsAreCorrect) {
    static std::vector<int64_t> numbers = {100, 200, 300};

    auto num_table = idasql::table("numbers")
        .count([]() { return numbers.size(); })
        .column_int64("value", [](size_t i) { return numbers[i]; })
        .column_int64("doubled", [](size_t i) { return numbers[i] * 2; })
        .build();

    idasql::register_vtable(db_, "num_module", &num_table);
    idasql::create_vtable(db_, "nums", "num_module");

    auto result = query("SELECT value, doubled FROM nums WHERE value = 200");
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_EQ(result.get(0, "value"), "200");
    EXPECT_EQ(result.get(0, "doubled"), "400");
}

TEST_F(VTableFrameworkTest, LimitWorks) {
    static std::vector<int> data(100);
    for (int i = 0; i < 100; i++) data[i] = i;

    auto large_table = idasql::table("large")
        .count([]() { return data.size(); })
        .column_int("n", [](size_t i) { return data[i]; })
        .build();

    idasql::register_vtable(db_, "large_module", &large_table);
    idasql::create_vtable(db_, "large", "large_module");

    auto result = query("SELECT * FROM large LIMIT 10");
    EXPECT_EQ(result.row_count(), 10);
}

TEST_F(VTableFrameworkTest, OffsetWorks) {
    static std::vector<int> data(100);
    for (int i = 0; i < 100; i++) data[i] = i;

    auto table = idasql::table("offset_test")
        .count([]() { return data.size(); })
        .column_int("n", [](size_t i) { return data[i]; })
        .build();

    idasql::register_vtable(db_, "offset_module", &table);
    idasql::create_vtable(db_, "offset_test", "offset_module");

    auto result = query("SELECT n FROM offset_test LIMIT 5 OFFSET 10");
    ASSERT_EQ(result.row_count(), 5);
    EXPECT_EQ(result.get(0, "n"), "10");
    EXPECT_EQ(result.get(4, "n"), "14");
}

TEST_F(VTableFrameworkTest, OrderByWorks) {
    static std::vector<std::pair<int, std::string>> data = {
        {3, "charlie"},
        {1, "alice"},
        {2, "bob"}
    };

    auto table = idasql::table("sort_test")
        .count([]() { return data.size(); })
        .column_int("id", [](size_t i) { return data[i].first; })
        .column_text("name", [](size_t i) { return data[i].second; })
        .build();

    idasql::register_vtable(db_, "sort_module", &table);
    idasql::create_vtable(db_, "sort_test", "sort_module");

    auto result = query("SELECT name FROM sort_test ORDER BY id ASC");
    ASSERT_EQ(result.row_count(), 3);
    EXPECT_EQ(result.get(0, "name"), "alice");
    EXPECT_EQ(result.get(1, "name"), "bob");
    EXPECT_EQ(result.get(2, "name"), "charlie");
}

TEST_F(VTableFrameworkTest, AggregationWorks) {
    static std::vector<int> values = {10, 20, 30, 40, 50};

    auto table = idasql::table("agg_test")
        .count([]() { return values.size(); })
        .column_int("val", [](size_t i) { return values[i]; })
        .build();

    idasql::register_vtable(db_, "agg_module", &table);
    idasql::create_vtable(db_, "agg_test", "agg_module");

    auto sum_result = query("SELECT SUM(val) as total FROM agg_test");
    EXPECT_EQ(sum_result.scalar(), "150");

    auto avg_result = query("SELECT AVG(val) as average FROM agg_test");
    EXPECT_EQ(avg_result.scalar(), "30.0");

    auto count_result = query("SELECT COUNT(*) as cnt FROM agg_test");
    EXPECT_EQ(count_result.scalar(), "5");
}
