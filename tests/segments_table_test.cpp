/**
 * segments_table_test.cpp - Tests for the segments virtual table
 */

// Standard headers FIRST (before IDA SDK via test_fixtures.hpp)
#include <string>
#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include "test_fixtures.hpp"

using namespace idasql::testing;

class SegmentsTableTest : public IDADatabaseTest {};

TEST_F(SegmentsTableTest, TableExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='table' AND name='segments'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(SegmentsTableTest, HasSegments) {
    auto result = query("SELECT COUNT(*) FROM segments");
    EXPECT_GT(result.scalar_int(), 0) << "Database should have at least one segment";
}

TEST_F(SegmentsTableTest, HasRequiredColumns) {
    auto result = query("SELECT start_ea, end_ea, name, class, perm FROM segments LIMIT 1");
    EXPECT_EQ(result.col_count(), 5);
}

TEST_F(SegmentsTableTest, SegmentsFromFile) {
    auto result = query_file("segments_all.sql");
    EXPECT_GT(result.row_count(), 0);
}

TEST_F(SegmentsTableTest, SegmentsAreNonOverlapping) {
    auto result = query(
        "SELECT s1.name, s2.name "
        "FROM segments s1, segments s2 "
        "WHERE s1.start_ea < s2.start_ea "
        "  AND s1.end_ea > s2.start_ea"
    );
    EXPECT_EQ(result.row_count(), 0) << "Segments should not overlap";
}

TEST_F(SegmentsTableTest, SegmentSizesArePositive) {
    auto result = query("SELECT COUNT(*) FROM segments WHERE end_ea <= start_ea");
    EXPECT_EQ(result.scalar_int(), 0) << "All segments should have positive size";
}

TEST_F(SegmentsTableTest, SegmentPermissionsValid) {
    // Permissions should be between 0-7 (rwx bits)
    auto result = query("SELECT COUNT(*) FROM segments WHERE perm < 0 OR perm > 7");
    EXPECT_EQ(result.scalar_int(), 0) << "Permissions should be 0-7";
}

TEST_F(SegmentsTableTest, HasCodeSegment) {
    auto result = query("SELECT name FROM segments WHERE class = 'CODE'");
    EXPECT_GE(result.row_count(), 1) << "Should have at least one CODE segment";
}
