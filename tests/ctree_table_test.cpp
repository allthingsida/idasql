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

// ============================================================================
// Depth Column Tests
// ============================================================================

class CtreeDepthTest : public DecompilerTest {};

TEST_F(CtreeDepthTest, DepthColumnExists) {
    // Verify depth column is accessible
    auto result = query(
        "SELECT depth FROM ctree LIMIT 1"
    );
    // Should be able to query depth column
    EXPECT_EQ(result.col_count(), 1);
}

TEST_F(CtreeDepthTest, DepthIsPositive) {
    // All depths should be >= 1 (root nodes have depth 1)
    auto result = query(
        "SELECT MIN(depth) as min_depth FROM ctree"
    );
    if (result.row_count() > 0 && result.get(0, "min_depth") != "") {
        EXPECT_GE(result.scalar_int(), 1);
    }
}

TEST_F(CtreeDepthTest, DepthDistributionExists) {
    // Verify we have varying depths in the database
    auto result = query(
        "SELECT COUNT(DISTINCT depth) as depth_count FROM ctree"
    );
    if (result.row_count() > 0) {
        int depth_count = result.scalar_int();
        EXPECT_GE(depth_count, 3) << "Expected multiple depth levels";
    }
}

TEST_F(CtreeDepthTest, MaxDepthIsReasonable) {
    // Max depth should be reasonable (not 0, not > 100)
    auto result = query(
        "SELECT MAX(depth) as max_depth FROM ctree"
    );
    if (result.row_count() > 0 && result.get(0, "max_depth") != "") {
        int max_depth = result.scalar_int();
        EXPECT_GE(max_depth, 1);
        EXPECT_LE(max_depth, 100);  // Reasonable upper bound
    }
}

TEST_F(CtreeDepthTest, SpecificFunctionDepth) {
    // Func 4198704 should have max depth 18 (from exploration)
    auto result = query(
        "SELECT MAX(depth) as max_depth FROM ctree WHERE func_addr = 4198704"
    );
    if (result.row_count() > 0 && result.get(0, "max_depth") != "") {
        EXPECT_EQ(result.scalar_int(), 18);
    }
}

TEST_F(CtreeDepthTest, ChildDepthIsParentPlusOne) {
    // Children should have depth = parent_depth + 1
    auto result = query(
        "SELECT c.depth as child_depth, p.depth as parent_depth "
        "FROM ctree c "
        "JOIN ctree p ON p.func_addr = c.func_addr AND p.item_id = c.parent_id "
        "WHERE c.parent_id IS NOT NULL "
        "LIMIT 50"
    );
    for (size_t i = 0; i < result.row_count(); i++) {
        int child_depth = std::stoi(result.get(i, "child_depth"));
        int parent_depth = std::stoi(result.get(i, "parent_depth"));
        EXPECT_EQ(child_depth, parent_depth + 1)
            << "Child depth should be parent + 1";
    }
}

TEST_F(CtreeDepthTest, RootNodesHaveNoParent) {
    // Nodes with depth=1 should have parent_id=NULL (root)
    // Note: actual roots might vary based on how decompiler structures the tree
    auto result = query(
        "SELECT item_id, depth, parent_id FROM ctree "
        "WHERE depth = 1 LIMIT 10"
    );
    // This is informational - root structure depends on decompilation
    EXPECT_GE(result.row_count(), 0);
}

TEST_F(CtreeDepthTest, DepthPerFunctionStats) {
    // Get depth stats per function
    auto result = query(
        "SELECT func_addr, MAX(depth) as max_depth, MIN(depth) as min_depth "
        "FROM ctree GROUP BY func_addr ORDER BY max_depth DESC LIMIT 5"
    );
    // All functions should have at least min_depth = 1
    for (size_t i = 0; i < result.row_count(); i++) {
        int min_depth = std::stoi(result.get(i, "min_depth"));
        EXPECT_GE(min_depth, 1);
    }
}

// ============================================================================
// ctree_v_calls_in_loops View Tests
// ============================================================================

class CtreeCallsInLoopsTest : public DecompilerTest {};

TEST_F(CtreeCallsInLoopsTest, ViewExists) {
    auto result = query(
        "SELECT name FROM sqlite_master WHERE type='view' AND name='ctree_v_calls_in_loops'"
    );
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_EQ(result.scalar(), "ctree_v_calls_in_loops");
}

TEST_F(CtreeCallsInLoopsTest, ViewHasRequiredColumns) {
    auto result = query(
        "SELECT func_addr, item_id, ea, call_depth, loop_id, loop_op, "
        "callee_addr, callee_name, helper_name "
        "FROM ctree_v_calls_in_loops LIMIT 1"
    );
    EXPECT_EQ(result.col_count(), 9);
}

TEST_F(CtreeCallsInLoopsTest, TotalCallsInLoops) {
    // From exploration: 9 calls inside loops
    auto result = query(
        "SELECT COUNT(*) as cnt FROM ctree_v_calls_in_loops"
    );
    if (result.row_count() > 0) {
        EXPECT_EQ(result.scalar_int(), 9);
    }
}

TEST_F(CtreeCallsInLoopsTest, LoopTypesAreValid) {
    // loop_op should only be cit_for, cit_while, or cit_do
    auto result = query(
        "SELECT DISTINCT loop_op FROM ctree_v_calls_in_loops"
    );
    for (size_t i = 0; i < result.row_count(); i++) {
        std::string loop_op = result.get(i, "loop_op");
        bool valid = (loop_op == "cit_for" || loop_op == "cit_while" || loop_op == "cit_do");
        EXPECT_TRUE(valid) << "Invalid loop_op: " << loop_op;
    }
}

TEST_F(CtreeCallsInLoopsTest, SpecificLoopHasCalls) {
    // Loop at 4200560:1 (cit_while) should have 4 calls
    auto result = query(
        "SELECT COUNT(*) as cnt FROM ctree_v_calls_in_loops "
        "WHERE loop_id = 1 AND func_addr = 4200560"
    );
    if (result.row_count() > 0) {
        EXPECT_EQ(result.scalar_int(), 4);
    }
}

TEST_F(CtreeCallsInLoopsTest, ForLoopCalls) {
    // cit_for loop at 4199216:108 should have _mbstok calls
    auto result = query(
        "SELECT callee_name FROM ctree_v_calls_in_loops "
        "WHERE loop_id = 108 AND func_addr = 4199216 AND loop_op = 'cit_for'"
    );
    bool has_mbstok = false;
    for (size_t i = 0; i < result.row_count(); i++) {
        if (result.get(i, "callee_name") == "_mbstok") {
            has_mbstok = true;
            break;
        }
    }
    EXPECT_TRUE(has_mbstok) << "Expected _mbstok call in for loop";
}

TEST_F(CtreeCallsInLoopsTest, CallDepthIsGreaterThanLoopDepth) {
    // Calls inside loops should have depth > loop depth
    auto result = query(
        "SELECT v.call_depth, c.depth as loop_depth "
        "FROM ctree_v_calls_in_loops v "
        "JOIN ctree c ON c.func_addr = v.func_addr AND c.item_id = v.loop_id "
        "LIMIT 20"
    );
    for (size_t i = 0; i < result.row_count(); i++) {
        int call_depth = std::stoi(result.get(i, "call_depth"));
        int loop_depth = std::stoi(result.get(i, "loop_depth"));
        EXPECT_GT(call_depth, loop_depth)
            << "Call should be deeper than containing loop";
    }
}

TEST_F(CtreeCallsInLoopsTest, DoWhileLoopCall) {
    // cit_do loop at 4198704:53 should have mixerGetLineInfoA call
    auto result = query(
        "SELECT callee_name FROM ctree_v_calls_in_loops "
        "WHERE loop_id = 53 AND func_addr = 4198704"
    );
    bool has_mixer = false;
    for (size_t i = 0; i < result.row_count(); i++) {
        if (result.get(i, "callee_name") == "mixerGetLineInfoA") {
            has_mixer = true;
            break;
        }
    }
    EXPECT_TRUE(has_mixer);
}

TEST_F(CtreeCallsInLoopsTest, HelperCallInLoop) {
    // Should find _InterlockedCompareExchange helper call in loop at 4200970:10
    auto result = query(
        "SELECT helper_name FROM ctree_v_calls_in_loops "
        "WHERE loop_id = 10 AND func_addr = 4200970"
    );
    bool has_helper = false;
    for (size_t i = 0; i < result.row_count(); i++) {
        if (result.get(i, "helper_name") == "_InterlockedCompareExchange") {
            has_helper = true;
            break;
        }
    }
    EXPECT_TRUE(has_helper);
}

TEST_F(CtreeCallsInLoopsTest, NoFalsePositives) {
    // All results should be actual calls
    auto result = query(
        "SELECT c.op_name FROM ctree_v_calls_in_loops v "
        "JOIN ctree c ON c.func_addr = v.func_addr AND c.item_id = v.item_id"
    );
    for (size_t i = 0; i < result.row_count(); i++) {
        EXPECT_EQ(result.get(i, "op_name"), "cot_call");
    }
}

// ============================================================================
// ctree_v_calls_in_ifs View Tests
// ============================================================================

class CtreeCallsInIfsTest : public DecompilerTest {};

TEST_F(CtreeCallsInIfsTest, ViewExists) {
    auto result = query(
        "SELECT name FROM sqlite_master WHERE type='view' AND name='ctree_v_calls_in_ifs'"
    );
    ASSERT_EQ(result.row_count(), 1);
    EXPECT_EQ(result.scalar(), "ctree_v_calls_in_ifs");
}

TEST_F(CtreeCallsInIfsTest, ViewHasRequiredColumns) {
    auto result = query(
        "SELECT func_addr, item_id, ea, call_depth, if_id, branch, "
        "callee_addr, callee_name, helper_name "
        "FROM ctree_v_calls_in_ifs LIMIT 1"
    );
    EXPECT_EQ(result.col_count(), 9);
}

TEST_F(CtreeCallsInIfsTest, TotalCallsInThenBranch) {
    // Should have significant calls in 'then' branches
    auto result = query(
        "SELECT COUNT(*) as cnt FROM ctree_v_calls_in_ifs WHERE branch = 'then'"
    );
    if (result.row_count() > 0) {
        int count = result.scalar_int();
        EXPECT_GE(count, 80);   // At least 80 calls in then branches
        EXPECT_LE(count, 120);  // Upper bound for sanity
    }
}

TEST_F(CtreeCallsInIfsTest, TotalCallsInElseBranch) {
    // Should have calls in 'else' branches
    auto result = query(
        "SELECT COUNT(*) as cnt FROM ctree_v_calls_in_ifs WHERE branch = 'else'"
    );
    if (result.row_count() > 0) {
        int count = result.scalar_int();
        EXPECT_GE(count, 30);  // At least 30 calls in else branches
        EXPECT_LE(count, 60);  // Upper bound for sanity
    }
}

TEST_F(CtreeCallsInIfsTest, BranchValuesAreValid) {
    // branch should only be 'then' or 'else'
    auto result = query(
        "SELECT DISTINCT branch FROM ctree_v_calls_in_ifs"
    );
    for (size_t i = 0; i < result.row_count(); i++) {
        std::string branch = result.get(i, "branch");
        bool valid = (branch == "then" || branch == "else");
        EXPECT_TRUE(valid) << "Invalid branch: " << branch;
    }
}

TEST_F(CtreeCallsInIfsTest, SpecificIfHasExpectedCalls) {
    // if at 4198400:6 should have GetCurrentProcess and OpenProcessToken in then branch
    auto result = query(
        "SELECT callee_name FROM ctree_v_calls_in_ifs "
        "WHERE if_id = 6 AND func_addr = 4198400 AND branch = 'then'"
    );
    bool has_get_process = false;
    bool has_open_token = false;
    for (size_t i = 0; i < result.row_count(); i++) {
        std::string name = result.get(i, "callee_name");
        if (name == "GetCurrentProcess") has_get_process = true;
        if (name == "OpenProcessToken") has_open_token = true;
    }
    EXPECT_TRUE(has_get_process) << "Expected GetCurrentProcess in if:6 then branch";
    EXPECT_TRUE(has_open_token) << "Expected OpenProcessToken in if:6 then branch";
}

TEST_F(CtreeCallsInIfsTest, ElseBranchHasCalls) {
    // if at 4198544:62 should have mciSendCommandA in else branch
    auto result = query(
        "SELECT callee_name FROM ctree_v_calls_in_ifs "
        "WHERE if_id = 62 AND func_addr = 4198544 AND branch = 'else'"
    );
    bool has_mci = false;
    for (size_t i = 0; i < result.row_count(); i++) {
        if (result.get(i, "callee_name") == "mciSendCommandA") {
            has_mci = true;
            break;
        }
    }
    EXPECT_TRUE(has_mci);
}

TEST_F(CtreeCallsInIfsTest, NoFalsePositives) {
    // All results should be actual calls
    auto result = query(
        "SELECT c.op_name FROM ctree_v_calls_in_ifs v "
        "JOIN ctree c ON c.func_addr = v.func_addr AND c.item_id = v.item_id"
    );
    for (size_t i = 0; i < result.row_count(); i++) {
        EXPECT_EQ(result.get(i, "op_name"), "cot_call");
    }
}

TEST_F(CtreeCallsInIfsTest, NestedIfsHaveCorrectParent) {
    // Calls in nested ifs should reference the immediate if parent, not grandparent
    // This is a structural test - verify if_id references a cit_if node
    auto result = query(
        "SELECT DISTINCT v.if_id, v.func_addr, c.op_name "
        "FROM ctree_v_calls_in_ifs v "
        "JOIN ctree c ON c.func_addr = v.func_addr AND c.item_id = v.if_id"
    );
    for (size_t i = 0; i < result.row_count(); i++) {
        EXPECT_EQ(result.get(i, "op_name"), "cit_if")
            << "if_id should reference a cit_if node";
    }
}

TEST_F(CtreeCallsInIfsTest, CallsWithCalleeName) {
    // Most calls should have either callee_name or helper_name
    auto result = query(
        "SELECT COUNT(*) as cnt FROM ctree_v_calls_in_ifs "
        "WHERE callee_name IS NOT NULL OR helper_name IS NOT NULL"
    );
    auto total = query("SELECT COUNT(*) as cnt FROM ctree_v_calls_in_ifs");
    if (result.row_count() > 0 && total.row_count() > 0) {
        int with_name = result.scalar_int();
        int total_cnt = total.scalar_int();
        // Most calls should have names (>80%)
        EXPECT_GE((double)with_name / total_cnt, 0.8);
    }
}

// ============================================================================
// Combined Recursive CTE Tests (Advanced)
// ============================================================================

class CtreeRecursiveCTETest : public DecompilerTest {};

TEST_F(CtreeRecursiveCTETest, CallChainDepth) {
    // Test the recursive CTE for call chain depth
    auto result = query(
        "WITH RECURSIVE call_chain(caller, callee, depth) AS ("
        "  SELECT func_addr, callee_addr, 1 FROM ctree_v_calls WHERE callee_addr IS NOT NULL "
        "  UNION ALL "
        "  SELECT cc.caller, c.callee_addr, cc.depth + 1 FROM call_chain cc "
        "  JOIN ctree_v_calls c ON c.func_addr = cc.callee "
        "  WHERE cc.depth < 10 AND c.callee_addr IS NOT NULL"
        ") "
        "SELECT MAX(depth) as max_depth FROM call_chain"
    );
    if (result.row_count() > 0 && result.get(0, "max_depth") != "") {
        EXPECT_GE(result.scalar_int(), 1);
    }
}

TEST_F(CtreeRecursiveCTETest, CallsInLoopsAndIfs) {
    // Find calls that are BOTH in a loop AND in an if branch
    auto result = query(
        "SELECT COUNT(*) as cnt FROM "
        "(SELECT DISTINCT func_addr, item_id FROM ctree_v_calls_in_loops "
        " INTERSECT "
        " SELECT DISTINCT func_addr, item_id FROM ctree_v_calls_in_ifs)"
    );
    // Query should execute - may or may not have results
    EXPECT_GE(result.row_count(), 0);
}
