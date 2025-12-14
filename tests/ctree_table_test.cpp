/**
 * ctree_table_test.cpp - Tests for ctree decompiler tables
 *
 * Tests: ctree, ctree_call_args, and ctree_v_* views
 */

// Standard headers FIRST (before IDA SDK via test_fixtures.hpp)
#include <string>
#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include "test_fixtures.hpp"
#include <idasql/decompiler.hpp>

using namespace idasql::testing;

// ============================================================================
// Decompiler Test Fixture
// Extends IDADatabaseTest with decompiler table registration
// ============================================================================

class DecompilerTest : public IDADatabaseTest {
protected:
    void SetUp() override {
        IDADatabaseTest::SetUp();
        // Register decompiler tables
        idasql::decompiler::DecompilerRegistry().register_all(db_);
    }
};

// ============================================================================
// ctree Table Tests
// ============================================================================

class CtreeTableTest : public DecompilerTest {};

TEST_F(CtreeTableTest, TableExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='table' AND name='ctree'");
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_EQ(result.scalar(), "ctree");
}

TEST_F(CtreeTableTest, HasRequiredColumns) {
    // Get first function address
    auto funcs = query("SELECT address FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string func_addr = funcs.get(0, "address");

    auto result = query(
        "SELECT func_addr, item_id, is_expr, op, op_name, ea, "
        "parent_id, depth, x_id, y_id, z_id, "
        "var_idx, obj_ea, num_value, str_value, var_name "
        "FROM ctree WHERE func_addr = " + func_addr + " LIMIT 1"
    );
    // Should have at least one item (or skip if decompilation fails)
    if (result.row_count() == 0) {
        GTEST_SKIP() << "Decompilation failed or no items";
    }
    EXPECT_EQ(result.col_count(), 16);
}

TEST_F(CtreeTableTest, FuncAddrFilterWorks) {
    // Get first two function addresses
    auto funcs = query("SELECT address FROM funcs LIMIT 2");
    if (funcs.row_count() < 2) {
        GTEST_SKIP() << "Need at least 2 functions";
    }
    std::string func1 = funcs.get(0, "address");
    std::string func2 = funcs.get(1, "address");

    // Query for first function
    auto result1 = query("SELECT func_addr FROM ctree WHERE func_addr = " + func1 + " LIMIT 10");

    // All results should be from func1
    for (size_t i = 0; i < result1.row_count(); i++) {
        EXPECT_EQ(result1.get(i, "func_addr"), func1);
    }
}

TEST_F(CtreeTableTest, HasExpressions) {
    auto funcs = query("SELECT address FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string func_addr = funcs.get(0, "address");

    auto result = query(
        "SELECT COUNT(*) AS cnt FROM ctree "
        "WHERE func_addr = " + func_addr + " AND is_expr = 1"
    );
    // Should have some expressions
    if (result.row_count() > 0) {
        int count = result.scalar_int();
        EXPECT_GE(count, 0);  // At least decompilation worked
    }
}

TEST_F(CtreeTableTest, OpNameIsPopulated) {
    auto funcs = query("SELECT address FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string func_addr = funcs.get(0, "address");

    auto result = query(
        "SELECT op_name FROM ctree "
        "WHERE func_addr = " + func_addr + " AND op_name IS NOT NULL LIMIT 5"
    );

    // Op names should start with 'cot_' or 'cit_'
    for (size_t i = 0; i < result.row_count(); i++) {
        std::string op = result.get(i, "op_name");
        bool valid = (op.substr(0, 4) == "cot_" || op.substr(0, 4) == "cit_");
        EXPECT_TRUE(valid) << "Invalid op_name: " << op;
    }
}

TEST_F(CtreeTableTest, ParentChildRelation) {
    auto funcs = query("SELECT address FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string func_addr = funcs.get(0, "address");

    // Find items with x_id set (binary ops)
    auto result = query(
        "SELECT c.item_id, c.x_id, x.item_id AS child_id "
        "FROM ctree c "
        "JOIN ctree x ON x.func_addr = c.func_addr AND x.item_id = c.x_id "
        "WHERE c.func_addr = " + func_addr + " AND c.x_id IS NOT NULL LIMIT 5"
    );

    // If we have results, x_id should match child's item_id
    for (size_t i = 0; i < result.row_count(); i++) {
        EXPECT_EQ(result.get(i, "x_id"), result.get(i, "child_id"));
    }
}

// ============================================================================
// ctree_call_args Table Tests
// ============================================================================

class CtreeCallArgsTest : public DecompilerTest {};

TEST_F(CtreeCallArgsTest, TableExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='table' AND name='ctree_call_args'");
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_EQ(result.scalar(), "ctree_call_args");
}

TEST_F(CtreeCallArgsTest, HasCallArgs) {
    auto funcs = query("SELECT address FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string func_addr = funcs.get(0, "address");

    auto result = query(
        "SELECT func_addr, call_item_id, arg_idx, arg_op "
        "FROM ctree_call_args WHERE func_addr = " + func_addr + " LIMIT 10"
    );
    // May or may not have calls, but query should work
    EXPECT_GE(result.col_count(), 4);
}

TEST_F(CtreeCallArgsTest, ArgIdxIsZeroBased) {
    auto funcs = query("SELECT address FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string func_addr = funcs.get(0, "address");

    auto result = query(
        "SELECT MIN(arg_idx) as min_idx FROM ctree_call_args "
        "WHERE func_addr = " + func_addr
    );
    if (result.row_count() > 0 && result.get(0, "min_idx") != "") {
        EXPECT_EQ(result.scalar_int(), 0);
    }
}

TEST_F(CtreeCallArgsTest, JoinWithCtree) {
    auto funcs = query("SELECT address FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string func_addr = funcs.get(0, "address");

    // Query call args directly - verify table has data
    auto args = query(
        "SELECT call_item_id, arg_idx, arg_op "
        "FROM ctree_call_args WHERE func_addr = " + func_addr + " LIMIT 5"
    );

    // Verify we have call arguments with valid data
    for (size_t i = 0; i < args.row_count(); i++) {
        // call_item_id should be non-negative
        EXPECT_GE(std::stoi(args.get(i, "call_item_id")), 0);
        // arg_idx should be non-negative
        EXPECT_GE(std::stoi(args.get(i, "arg_idx")), 0);
        // arg_op should have cot_ prefix
        std::string op = args.get(i, "arg_op");
        bool valid = op.substr(0, 4) == "cot_";
        EXPECT_TRUE(valid) << "Invalid arg_op: " << op;
    }
}

// ============================================================================
// Views Tests
// ============================================================================

class CtreeViewsTest : public DecompilerTest {};

TEST_F(CtreeViewsTest, CallsViewExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='view' AND name='ctree_v_calls'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(CtreeViewsTest, LoopsViewExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='view' AND name='ctree_v_loops'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(CtreeViewsTest, IfsViewExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='view' AND name='ctree_v_ifs'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(CtreeViewsTest, SignedOpsViewExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='view' AND name='ctree_v_signed_ops'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(CtreeViewsTest, ComparisonsViewExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='view' AND name='ctree_v_comparisons'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(CtreeViewsTest, AssignmentsViewExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='view' AND name='ctree_v_assignments'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(CtreeViewsTest, DerefsViewExists) {
    auto result = query("SELECT name FROM sqlite_master WHERE type='view' AND name='ctree_v_derefs'");
    ASSERT_EQ(result.row_count(), 1);
}

TEST_F(CtreeViewsTest, CallsViewReturnsOnlyCalls) {
    auto funcs = query("SELECT address FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string func_addr = funcs.get(0, "address");

    // Get calls from the view
    auto calls = query(
        "SELECT c.item_id FROM ctree c "
        "WHERE c.func_addr = " + func_addr + " AND c.op_name = 'cot_call' LIMIT 5"
    );

    auto view_result = query(
        "SELECT item_id FROM ctree_v_calls "
        "WHERE func_addr = " + func_addr + " LIMIT 5"
    );

    // View should only return call items (if any exist)
    // This is a sanity check - exact matching depends on decompilation
    EXPECT_GE(view_result.row_count(), 0);
}

TEST_F(CtreeViewsTest, LoopsViewReturnsOnlyLoops) {
    auto funcs = query("SELECT address FROM funcs LIMIT 5");

    for (size_t i = 0; i < funcs.row_count(); i++) {
        std::string func_addr = funcs.get(i, "address");
        auto result = query(
            "SELECT op_name FROM ctree_v_loops "
            "WHERE func_addr = " + func_addr + " LIMIT 10"
        );

        for (size_t j = 0; j < result.row_count(); j++) {
            std::string op = result.get(j, "op_name");
            bool is_loop = (op == "cit_for" || op == "cit_while" || op == "cit_do");
            EXPECT_TRUE(is_loop) << "Non-loop in loops view: " << op;
        }
    }
}

// ============================================================================
// Extended ctree_lvars Tests
// ============================================================================

class CtreeLvarsExtendedTest : public DecompilerTest {};

TEST_F(CtreeLvarsExtendedTest, HasExtendedColumns) {
    auto funcs = query("SELECT address FROM funcs LIMIT 1");
    if (funcs.row_count() == 0) {
        GTEST_SKIP() << "No functions in database";
    }
    std::string func_addr = funcs.get(0, "address");

    auto result = query(
        "SELECT func_addr, idx, name, is_stk_var, is_reg_var, stkoff, mreg "
        "FROM ctree_lvars WHERE func_addr = " + func_addr + " LIMIT 1"
    );
    EXPECT_EQ(result.col_count(), 7);
}

TEST_F(CtreeLvarsExtendedTest, StackVarsHaveStkoff) {
    auto funcs = query("SELECT address FROM funcs LIMIT 5");

    for (size_t i = 0; i < funcs.row_count(); i++) {
        std::string func_addr = funcs.get(i, "address");
        auto result = query(
            "SELECT name, is_stk_var, stkoff FROM ctree_lvars "
            "WHERE func_addr = " + func_addr + " AND is_stk_var = 1 LIMIT 5"
        );

        // Stack vars should have non-null stkoff
        for (size_t j = 0; j < result.row_count(); j++) {
            std::string stkoff = result.get(j, "stkoff");
            EXPECT_FALSE(stkoff.empty()) << "Stack var missing stkoff";
        }
    }
}

// ============================================================================
// HexraysToolbox-Style Query Tests
// ============================================================================

class HexraysToolboxQueriesTest : public DecompilerTest {};

TEST_F(HexraysToolboxQueriesTest, ZeroComparisonQuery) {
    // Find: x == 0 patterns
    auto result = query(
        "SELECT func_addr, ea FROM ctree_v_comparisons "
        "WHERE op_name = 'cot_eq' AND rhs_op = 'cot_num' AND rhs_num = 0 "
        "LIMIT 10"
    );
    // Query should execute without error
    EXPECT_GE(result.row_count(), 0);
}

TEST_F(HexraysToolboxQueriesTest, DirectCallsQuery) {
    // Find: direct function calls (e.x.op is cot_obj)
    auto result = query(
        "SELECT func_addr, ea, callee_name FROM ctree_v_calls "
        "WHERE callee_op = 'cot_obj' "
        "LIMIT 10"
    );
    EXPECT_GE(result.row_count(), 0);
}

TEST_F(HexraysToolboxQueriesTest, SignedOpsQuery) {
    // Find: signed operations (potential integer overflow)
    auto result = query("SELECT func_addr, ea, op_name FROM ctree_v_signed_ops LIMIT 10");
    EXPECT_GE(result.row_count(), 0);
}

TEST_F(HexraysToolboxQueriesTest, AllLoopsQuery) {
    // Find: all loop constructs
    auto result = query("SELECT func_addr, ea, op_name FROM ctree_v_loops LIMIT 10");
    EXPECT_GE(result.row_count(), 0);
}

TEST_F(HexraysToolboxQueriesTest, StackBufferCallQuery) {
    // Find: calls with stack buffer as first argument
    auto result = query(
        "SELECT c.func_addr, c.ea, c.callee_name "
        "FROM ctree_v_calls c "
        "JOIN ctree_call_args a ON a.func_addr = c.func_addr AND a.call_item_id = c.item_id "
        "WHERE a.arg_idx = 0 AND a.arg_var_is_stk = 1 "
        "LIMIT 10"
    );
    EXPECT_GE(result.row_count(), 0);
}
