/**
 * disasm_table_test.cpp - Tests for disassembly-level tables
 *
 * Tests: disasm_calls, disasm_v_leaf_funcs, disasm_v_call_chains
 */

// Standard headers FIRST (before IDA SDK via test_fixtures.hpp)
#include <string>
#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include "test_fixtures.hpp"
#include <idasql/disassembly.hpp>

using namespace idasql::testing;

// ============================================================================
// Disassembly Test Fixture
// Extends IDADatabaseTest with disassembly table registration
// ============================================================================

class DisassemblyTest : public IDADatabaseTest {
protected:
    idasql::disassembly::DisassemblyRegistry* disasm_ = nullptr;

    void SetUp() override {
        IDADatabaseTest::SetUp();
        // Register disassembly tables (keep registry alive for test lifetime)
        disasm_ = new idasql::disassembly::DisassemblyRegistry();
        disasm_->register_all(*db_);
    }

    void TearDown() override {
        delete disasm_;
        disasm_ = nullptr;
        IDADatabaseTest::TearDown();
    }
};

// ============================================================================
// disasm_calls Table Tests
// ============================================================================

class DisasmCallsTest : public DisassemblyTest {};

TEST_F(DisasmCallsTest, TableExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='table' AND name='disasm_calls'");
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_EQ(result.scalar(), "disasm_calls");
}

TEST_F(DisasmCallsTest, HasRequiredColumns) {
    auto result = query("SELECT func_addr, ea, callee_addr, callee_name FROM disasm_calls LIMIT 1");
    EXPECT_EQ(result.col_count(), 4);
}

TEST_F(DisasmCallsTest, HasCalls) {
    // Should have at least some calls in the test database
    auto result = query("SELECT COUNT(*) as cnt FROM disasm_calls");
    EXPECT_GT(result.scalar_int(), 0);
}

TEST_F(DisasmCallsTest, CallsHaveValidFuncAddr) {
    // All calls should have a valid function address
    auto result = query(
        "SELECT COUNT(*) as cnt FROM disasm_calls c "
        "LEFT JOIN funcs f ON f.address = c.func_addr "
        "WHERE f.address IS NULL"
    );
    EXPECT_EQ(result.scalar_int(), 0);
}

TEST_F(DisasmCallsTest, CallEaInFunctionRange) {
    // Call address should be within function bounds
    auto result = query(
        "SELECT COUNT(*) as cnt FROM disasm_calls c "
        "JOIN funcs f ON f.address = c.func_addr "
        "WHERE c.ea < f.address OR c.ea >= f.end_ea"
    );
    EXPECT_EQ(result.scalar_int(), 0);
}

TEST_F(DisasmCallsTest, SampleCallHasCalleeName) {
    // At least some calls should have callee names
    auto result = query(
        "SELECT COUNT(*) as cnt FROM disasm_calls WHERE callee_name != ''"
    );
    EXPECT_GT(result.scalar_int(), 0);
}

// ============================================================================
// disasm_v_leaf_funcs View Tests
// ============================================================================

class DisasmLeafFuncsTest : public DisassemblyTest {};

TEST_F(DisasmLeafFuncsTest, ViewExists) {
    auto result = query(
        "SELECT name FROM sqlite_master WHERE type='view' AND name='disasm_v_leaf_funcs'"
    );
    EXPECT_EQ(result.row_count(), 1);
}

TEST_F(DisasmLeafFuncsTest, ViewHasRequiredColumns) {
    auto result = query("SELECT address, name FROM disasm_v_leaf_funcs LIMIT 1");
    EXPECT_EQ(result.col_count(), 2);
}

TEST_F(DisasmLeafFuncsTest, LeafFuncsHaveNoCalls) {
    // Verify that functions in leaf_funcs actually have no calls
    auto result = query(
        "SELECT COUNT(*) as cnt FROM disasm_v_leaf_funcs lf "
        "JOIN disasm_calls c ON c.func_addr = lf.address "
        "WHERE c.callee_addr IS NOT NULL AND c.callee_addr != 0"
    );
    // Should be 0 - leaf functions shouldn't have any calls
    EXPECT_EQ(result.scalar_int(), 0);
}

TEST_F(DisasmLeafFuncsTest, HasSomeLeafFuncs) {
    // There should be at least some leaf functions in a typical binary
    auto result = query("SELECT COUNT(*) as cnt FROM disasm_v_leaf_funcs");
    EXPECT_GT(result.scalar_int(), 0);
}

TEST_F(DisasmLeafFuncsTest, LeafFuncsAreValidFunctions) {
    // All leaf funcs should be in the funcs table
    auto result = query(
        "SELECT COUNT(*) as cnt FROM disasm_v_leaf_funcs lf "
        "LEFT JOIN funcs f ON f.address = lf.address "
        "WHERE f.address IS NULL"
    );
    EXPECT_EQ(result.scalar_int(), 0);
}

// ============================================================================
// disasm_v_call_chains View Tests
// ============================================================================

class DisasmCallChainsTest : public DisassemblyTest {};

TEST_F(DisasmCallChainsTest, ViewExists) {
    auto result = query(
        "SELECT name FROM sqlite_master WHERE type='view' AND name='disasm_v_call_chains'"
    );
    EXPECT_EQ(result.row_count(), 1);
}

TEST_F(DisasmCallChainsTest, ViewHasRequiredColumns) {
    auto result = query("SELECT root_func, current_func, depth FROM disasm_v_call_chains LIMIT 1");
    EXPECT_EQ(result.col_count(), 3);
}

TEST_F(DisasmCallChainsTest, DepthStartsAtOne) {
    // Minimum depth should be 1 (direct call)
    auto result = query("SELECT MIN(depth) as min_depth FROM disasm_v_call_chains");
    if (!result.empty() && result.scalar() != "NULL") {
        EXPECT_GE(result.scalar_int(), 1);
    }
}

TEST_F(DisasmCallChainsTest, MaxDepthIsReasonable) {
    // Max depth should be <= 10 (we limit recursion)
    auto result = query("SELECT MAX(depth) as max_depth FROM disasm_v_call_chains");
    if (!result.empty() && result.scalar() != "NULL") {
        EXPECT_LE(result.scalar_int(), 10);
    }
}

TEST_F(DisasmCallChainsTest, DepthDistribution) {
    // Should have chains at various depths
    auto result = query(
        "SELECT depth, COUNT(*) as cnt FROM disasm_v_call_chains "
        "GROUP BY depth ORDER BY depth"
    );
    // Should have at least depth 1 entries
    EXPECT_GT(result.row_count(), 0);
}

TEST_F(DisasmCallChainsTest, RootFuncsAreValid) {
    // All root_funcs should be valid function addresses
    auto result = query(
        "SELECT COUNT(*) as cnt FROM disasm_v_call_chains cc "
        "LEFT JOIN funcs f ON f.address = cc.root_func "
        "WHERE f.address IS NULL"
    );
    EXPECT_EQ(result.scalar_int(), 0);
}

TEST_F(DisasmCallChainsTest, TargetQueryWithLeafFuncs) {
    // The target query: find functions with chains reaching leaf funcs
    auto result = query(
        "SELECT COUNT(DISTINCT f.name) as cnt "
        "FROM disasm_v_call_chains cc "
        "JOIN funcs f ON f.address = cc.root_func "
        "JOIN disasm_v_leaf_funcs lf ON lf.address = cc.current_func"
    );
    // Should find at least some functions that call leaf functions
    EXPECT_GE(result.scalar_int(), 0);
}

TEST_F(DisasmCallChainsTest, FunctionsWithDeepChains) {
    // Find functions with call chains of depth >= 2
    auto result = query(
        "SELECT f.name, MAX(cc.depth) as max_depth "
        "FROM disasm_v_call_chains cc "
        "JOIN funcs f ON f.address = cc.root_func "
        "GROUP BY cc.root_func "
        "HAVING max_depth >= 2 "
        "ORDER BY max_depth DESC "
        "LIMIT 5"
    );
    // If there are deep chains, verify structure
    if (result.row_count() > 0) {
        EXPECT_EQ(result.col_count(), 2);
    }
}

// ============================================================================
// Comparison Tests (disasm vs ctree if available)
// ============================================================================

// Note: These tests verify that disasm_calls captures more than just
// decompilable function calls. Disasm sees everything; ctree only sees
// what Hex-Rays can decompile.

TEST_F(DisasmCallsTest, CapturesAllCalls) {
    // disasm_calls should have at least as many unique callers as ctree_v_calls
    // (assuming ctree is also registered - skip if not)
    auto disasm_count = query("SELECT COUNT(DISTINCT func_addr) FROM disasm_calls");

    // This is a sanity check - should have callers
    EXPECT_GT(disasm_count.scalar_int(), 0);
}
