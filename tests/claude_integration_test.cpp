/**
 * Claude Integration Tests for IDASQL
 *
 * These tests use a REAL IDA database (no mocks) and require:
 * - Claude CLI installed (npm install -g @anthropic-ai/claude-code)
 * - ANTHROPIC_API_KEY environment variable set
 * - Network access to Anthropic API
 * - A test IDA database file
 *
 * Tests verify:
 * - SessionHandler integration with Claude agent
 * - SQL passthrough when Claude mode is enabled
 * - Meta commands work in Claude mode
 * - Natural language queries invoke the idasql tool
 * - Multi-turn conversation maintains context
 *
 * Build with: cmake -DIDASQL_WITH_CLAUDE_AGENT=ON
 * Run with: idasql_tests.exe testdb.i64 --gtest_filter=ClaudeIntegration*
 */

// CRITICAL: These STL headers MUST be included FIRST before any IDA SDK headers.
// IDA SDK's fpro.h poisons fgetc/fputc which breaks MSVC's <fstream> implementation.
// Including them here ensures they're processed before the macros are defined.
#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstdio>

// Now include Claude SDK (uses nlohmann_json which needs fstream)
#ifdef IDASQL_HAS_CLAUDE_AGENT
#include <claude/claude.hpp>
#include "../src/common/claude_agent.hpp"
#endif

#include <gtest/gtest.h>

#include "test_fixtures.hpp"

#ifdef IDASQL_HAS_CLAUDE_AGENT
// session_handler.hpp doesn't include nlohmann_json directly, so it's safe here
#include "../src/common/session_handler.hpp"
#endif

namespace idasql {
namespace testing {

#ifdef IDASQL_HAS_CLAUDE_AGENT

/**
 * Format QueryResult as a text table for Claude to understand.
 * Similar to psql/sqlite3 output format.
 */
static std::string format_result(const QueryResult& result) {
    if (result.empty() && result.columns.empty()) {
        return "(0 rows)";
    }

    std::stringstream ss;

    // Calculate column widths
    std::vector<size_t> widths(result.columns.size(), 0);
    for (size_t i = 0; i < result.columns.size(); i++) {
        widths[i] = result.columns[i].length();
    }
    for (const auto& row : result.rows) {
        for (size_t i = 0; i < row.values.size() && i < widths.size(); i++) {
            widths[i] = std::max(widths[i], row.values[i].length());
        }
    }

    // Header
    for (size_t i = 0; i < result.columns.size(); i++) {
        ss << std::left << std::setw(widths[i]) << result.columns[i];
        if (i < result.columns.size() - 1) ss << " | ";
    }
    ss << "\n";

    // Separator
    for (size_t i = 0; i < result.columns.size(); i++) {
        ss << std::string(widths[i], '-');
        if (i < result.columns.size() - 1) ss << "-+-";
    }
    ss << "\n";

    // Rows
    for (const auto& row : result.rows) {
        for (size_t i = 0; i < row.values.size() && i < widths.size(); i++) {
            ss << std::left << std::setw(widths[i]) << row.values[i];
            if (i < widths.size() - 1) ss << " | ";
        }
        ss << "\n";
    }

    ss << "(" << result.rows.size() << " row" << (result.rows.size() != 1 ? "s" : "") << ")";
    return ss.str();
}

/**
 * Claude Integration Test Fixture
 *
 * Uses a real IDA database loaded via idalib.
 * Creates a SessionHandler with Claude enabled and a real SQL executor.
 */
class ClaudeIntegrationTest : public IDADatabaseTest {
protected:
    std::unique_ptr<SessionHandler> session_;

    void SetUp() override {
        IDADatabaseTest::SetUp();

        // Check if Claude is available
        if (!SessionHandler::is_claude_available()) {
            GTEST_SKIP() << "Claude CLI not available - install with: "
                         << "npm install -g @anthropic-ai/claude-code";
        }

        // Create SQL executor that uses the real database
        auto executor = [this](const std::string& sql) -> std::string {
            auto result = query(sql);
            return format_result(result);
        };

        // Create session with Claude enabled
        try {
            session_ = std::make_unique<SessionHandler>(executor, true);
        } catch (const std::exception& e) {
            GTEST_SKIP() << "Claude session failed to start: " << e.what();
        }

        if (!session_->is_claude_enabled()) {
            GTEST_SKIP() << "Claude could not be enabled (check API key)";
        }
    }

    void TearDown() override {
        if (session_) {
            session_->end_session();
            session_.reset();
        }
        IDADatabaseTest::TearDown();
    }

    // Helper to check if result mentions something
    bool result_mentions(const std::string& result, const std::string& term) {
        std::string lower_result = result;
        std::string lower_term = term;
        std::transform(lower_result.begin(), lower_result.end(), lower_result.begin(), ::tolower);
        std::transform(lower_term.begin(), lower_term.end(), lower_term.begin(), ::tolower);
        return lower_result.find(lower_term) != std::string::npos;
    }
};

// =============================================================================
// SQL Passthrough Tests
// These verify that raw SQL goes directly to the database without Claude
// =============================================================================

TEST_F(ClaudeIntegrationTest, SqlPassthrough_Select) {
    // Raw SQL should execute directly
    std::string result = session_->process_line("SELECT COUNT(*) FROM funcs");

    // Should return a count
    EXPECT_FALSE(result.empty());
    EXPECT_TRUE(result.find("row") != std::string::npos)
        << "Expected row count in result: " << result;
}

TEST_F(ClaudeIntegrationTest, SqlPassthrough_Pragma) {
    std::string result = session_->process_line("PRAGMA table_info(funcs)");

    EXPECT_FALSE(result.empty());
    // Should show column info
    EXPECT_TRUE(result.find("address") != std::string::npos ||
                result.find("name") != std::string::npos)
        << "Expected column names in PRAGMA result: " << result;
}

TEST_F(ClaudeIntegrationTest, SqlPassthrough_With) {
    std::string result = session_->process_line(
        "WITH large AS (SELECT * FROM funcs WHERE size > 100) "
        "SELECT COUNT(*) as cnt FROM large");

    EXPECT_FALSE(result.empty());
    EXPECT_TRUE(result.find("cnt") != std::string::npos)
        << "Expected column name 'cnt' in result: " << result;
}

// =============================================================================
// Meta Command Tests
// These verify that .commands work in Claude mode
// =============================================================================

TEST_F(ClaudeIntegrationTest, MetaCommand_Tables) {
    std::string result = session_->process_line(".tables");

    // .tables should return table list without invoking Claude
    EXPECT_TRUE(result.find("funcs") != std::string::npos)
        << "Expected 'funcs' table in result: " << result;
}

TEST_F(ClaudeIntegrationTest, MetaCommand_Schema) {
    std::string result = session_->process_line(".schema funcs");

    // Should show CREATE TABLE or VIRTUAL TABLE statement
    EXPECT_FALSE(result.empty());
    EXPECT_TRUE(result.find("funcs") != std::string::npos)
        << "Expected 'funcs' in schema result: " << result;
}

TEST_F(ClaudeIntegrationTest, MetaCommand_Help) {
    std::string result = session_->process_line(".help");

    // Should return help text without touching database
    EXPECT_TRUE(result.find(".tables") != std::string::npos ||
                result.find("tables") != std::string::npos)
        << "Expected '.tables' or 'tables' in help: " << result;
}

TEST_F(ClaudeIntegrationTest, MetaCommand_Quit) {
    EXPECT_FALSE(session_->is_quit_requested());

    session_->process_line(".quit");

    EXPECT_TRUE(session_->is_quit_requested());
}

// =============================================================================
// Natural Language Query Tests
// These verify Claude understands questions and generates SQL
// =============================================================================

TEST_F(ClaudeIntegrationTest, NaturalLanguage_CountFunctions) {
    std::string result = session_->process_line("How many functions are in this database?");

    std::cout << "\n=== Claude Response ===\n" << result << "\n=== End Response ===\n";

    // Claude should have executed SQL and returned a count
    EXPECT_FALSE(result.empty());

    // Response should contain a number (the count)
    bool has_digit = false;
    for (char c : result) {
        if (std::isdigit(c)) {
            has_digit = true;
            break;
        }
    }
    EXPECT_TRUE(has_digit) << "Expected a number in the response";
}

TEST_F(ClaudeIntegrationTest, NaturalLanguage_LargestFunctions) {
    std::string result = session_->process_line(
        "Show me the 5 largest functions in the database");

    std::cout << "\n=== Claude Response ===\n" << result << "\n=== End Response ===\n";

    EXPECT_FALSE(result.empty());
    // Response should mention function names or sizes
    EXPECT_TRUE(result_mentions(result, "function") ||
                result_mentions(result, "size") ||
                result_mentions(result, "name"))
        << "Expected function-related info in response";
}

TEST_F(ClaudeIntegrationTest, NaturalLanguage_ListTables) {
    std::string result = session_->process_line("What tables are available?");

    std::cout << "\n=== Claude Response ===\n" << result << "\n=== End Response ===\n";

    EXPECT_FALSE(result.empty());
    // Should mention some core tables
    EXPECT_TRUE(result_mentions(result, "funcs") ||
                result_mentions(result, "table"))
        << "Expected table names in response";
}

// =============================================================================
// Multi-turn Conversation Tests
// These verify context is preserved across turns
// =============================================================================

TEST_F(ClaudeIntegrationTest, MultiTurn_FollowUp) {
    // First query establishes context
    std::string result1 = session_->process_line(
        "How many functions are in the database?");
    EXPECT_FALSE(result1.empty());

    std::cout << "\n=== Turn 1 ===\n" << result1 << "\n";

    // Follow-up should use context from first query
    std::string result2 = session_->process_line(
        "What about the largest one?");
    EXPECT_FALSE(result2.empty());

    std::cout << "\n=== Turn 2 ===\n" << result2 << "\n";

    // Claude should understand "the largest one" refers to functions
    // and return info about a specific function
    EXPECT_TRUE(result_mentions(result2, "function") ||
                result_mentions(result2, "size") ||
                result_mentions(result2, "name") ||
                result_mentions(result2, "largest"))
        << "Follow-up should reference functions context";
}

TEST_F(ClaudeIntegrationTest, MultiTurn_Refinement) {
    // Initial query
    std::string result1 = session_->process_line("Show me some functions");
    EXPECT_FALSE(result1.empty());

    std::cout << "\n=== Turn 1 ===\n" << result1 << "\n";

    // Refine the query
    std::string result2 = session_->process_line("Only show the top 3 by size");
    EXPECT_FALSE(result2.empty());

    std::cout << "\n=== Turn 2 ===\n" << result2 << "\n";

    // Should have fewer results in the refined query
    // (we can't easily verify the count, but result should be non-empty)
}

TEST_F(ClaudeIntegrationTest, MultiTurn_ContextPersists) {
    // Simple context test: send a value, ask to recall it
    session_->process_line("Remember this secret code: ALPHA123");

    // Ask to recall - should remember from previous turn
    std::string result = session_->process_line("What was the secret code I just told you?");

    EXPECT_FALSE(result.empty());
    EXPECT_TRUE(result.find("ALPHA123") != std::string::npos)
        << "Should recall the secret code from previous turn. Got: " << result;
}

// =============================================================================
// Error Handling Tests
// =============================================================================

TEST_F(ClaudeIntegrationTest, ErrorHandling_InvalidTable) {
    std::string result = session_->process_line(
        "SELECT * FROM nonexistent_table_xyz123");

    // Should return error from SQLite
    EXPECT_FALSE(result.empty());
    // Either an error message or (0 rows) is acceptable
}

TEST_F(ClaudeIntegrationTest, ErrorHandling_AmbiguousQuery) {
    // Vague query - Claude should still respond reasonably
    std::string result = session_->process_line("Tell me something interesting");

    // Should get some response (might analyze the database or ask for clarification)
    EXPECT_FALSE(result.empty());
}

// =============================================================================
// Real Database Analysis Tests
// These test actual IDA database analysis capabilities
// =============================================================================

TEST_F(ClaudeIntegrationTest, Analysis_FunctionsBySize) {
    // Ask Claude to analyze function sizes
    std::string result = session_->process_line(
        "What is the size distribution of functions? Are there any unusually large ones?");

    std::cout << "\n=== Analysis ===\n" << result << "\n";

    EXPECT_FALSE(result.empty());
    // Should contain some size-related analysis
    EXPECT_TRUE(result_mentions(result, "size") ||
                result_mentions(result, "function") ||
                result_mentions(result, "large") ||
                result_mentions(result, "byte"))
        << "Expected size analysis in response";
}

TEST_F(ClaudeIntegrationTest, Analysis_Segments) {
    std::string result = session_->process_line(
        "What memory segments does this binary have?");

    std::cout << "\n=== Segments ===\n" << result << "\n";

    EXPECT_FALSE(result.empty());
    // Should mention segments
    EXPECT_TRUE(result_mentions(result, "segment") ||
                result_mentions(result, "text") ||
                result_mentions(result, "data") ||
                result_mentions(result, "code"))
        << "Expected segment info in response";
}

// =============================================================================
// Extended Multi-Turn Conversation Test (10 turns)
// Verifies context is preserved across a full analysis session
// =============================================================================

TEST_F(ClaudeIntegrationTest, MultiTurn_TenTurnAnalysisSession) {
    std::cout << "\n========== 10-Turn Analysis Session ==========\n";

    // Turn 1: Count functions
    std::string r1 = session_->process_line("How many functions are in this database?");
    std::cout << "\n--- Turn 1: Function count ---\n" << r1 << "\n";
    EXPECT_FALSE(r1.empty());
    EXPECT_TRUE(result_mentions(r1, "function") || result_mentions(r1, "101"))
        << "Turn 1 should mention functions";

    // Turn 2: Ask about largest (context: functions)
    std::string r2 = session_->process_line("What is the largest one?");
    std::cout << "\n--- Turn 2: Largest function ---\n" << r2 << "\n";
    EXPECT_FALSE(r2.empty());
    EXPECT_TRUE(result_mentions(r2, "main") || result_mentions(r2, "size") ||
                result_mentions(r2, "byte") || result_mentions(r2, "largest"))
        << "Turn 2 should understand 'one' refers to functions";

    // Turn 3: Ask for disassembly (context: the largest function)
    std::string r3 = session_->process_line("Show me its first few instructions");
    std::cout << "\n--- Turn 3: Disassembly ---\n" << r3.substr(0, 500) << "...\n";
    EXPECT_FALSE(r3.empty());
    // Should show some assembly or code-related content
    EXPECT_TRUE(result_mentions(r3, "push") || result_mentions(r3, "mov") ||
                result_mentions(r3, "call") || result_mentions(r3, "instruction") ||
                result_mentions(r3, "disasm") || result_mentions(r3, "main"))
        << "Turn 3 should show disassembly of the function";

    // Turn 4: Switch to strings
    std::string r4 = session_->process_line("What about strings - how many are there?");
    std::cout << "\n--- Turn 4: String count ---\n" << r4 << "\n";
    EXPECT_FALSE(r4.empty());
    EXPECT_TRUE(result_mentions(r4, "string"))
        << "Turn 4 should mention strings";

    // Turn 5: Filter strings
    std::string r5 = session_->process_line("Show me 3 strings that look like command line options");
    std::cout << "\n--- Turn 5: Command strings ---\n" << r5 << "\n";
    EXPECT_FALSE(r5.empty());
    // Should show strings with dashes (command options)
    EXPECT_TRUE(result_mentions(r5, "-") || result_mentions(r5, "command") ||
                result_mentions(r5, "option") || result_mentions(r5, "argument"))
        << "Turn 5 should show command-line strings";

    // Turn 6: Ask about imports
    std::string r6 = session_->process_line("What DLLs does this binary import from?");
    std::cout << "\n--- Turn 6: Imports ---\n" << r6 << "\n";
    EXPECT_FALSE(r6.empty());
    EXPECT_TRUE(result_mentions(r6, "dll") || result_mentions(r6, "kernel32") ||
                result_mentions(r6, "user32") || result_mentions(r6, "import"))
        << "Turn 6 should mention imported DLLs";

    // Turn 7: Synthesize analysis (tests recall of all prior context)
    std::string r7 = session_->process_line("Based on what you've seen so far, what does this program do?");
    std::cout << "\n--- Turn 7: Program analysis ---\n" << r7 << "\n";
    EXPECT_FALSE(r7.empty());
    // Should synthesize: functions + strings + imports = utility description
    EXPECT_TRUE(result_mentions(r7, "command") || result_mentions(r7, "utility") ||
                result_mentions(r7, "system") || result_mentions(r7, "windows") ||
                result_mentions(r7, "tool") || result_mentions(r7, "program"))
        << "Turn 7 should synthesize a program description";

    // Turn 8: Cross-reference query
    std::string r8 = session_->process_line("Can you find what function references the -lock string?");
    std::cout << "\n--- Turn 8: Xref query ---\n" << r8 << "\n";
    EXPECT_FALSE(r8.empty());
    EXPECT_TRUE(result_mentions(r8, "main") || result_mentions(r8, "function") ||
                result_mentions(r8, "reference") || result_mentions(r8, "lock"))
        << "Turn 8 should find xref to -lock";

    // Turn 9: Follow-up on that function (tests pronoun resolution)
    std::string r9 = session_->process_line("What's the size of that function?");
    std::cout << "\n--- Turn 9: Function size ---\n" << r9 << "\n";
    EXPECT_FALSE(r9.empty());
    EXPECT_TRUE(result_mentions(r9, "byte") || result_mentions(r9, "size") ||
                result_mentions(r9, "668") || result_mentions(r9, "main"))
        << "Turn 9 should understand 'that function' from context";

    // Turn 10: Summary (tests full session recall)
    std::string r10 = session_->process_line("Give me a brief summary of what we analyzed");
    std::cout << "\n--- Turn 10: Session summary ---\n" << r10 << "\n";
    EXPECT_FALSE(r10.empty());
    // Should recall key findings from the session
    EXPECT_TRUE(result_mentions(r10, "function") || result_mentions(r10, "string") ||
                result_mentions(r10, "import") || result_mentions(r10, "analysis") ||
                result_mentions(r10, "binary") || result_mentions(r10, "summary"))
        << "Turn 10 should summarize the analysis session";

    std::cout << "\n========== End 10-Turn Session ==========\n";
}

#else // !IDASQL_HAS_CLAUDE_AGENT

// Placeholder test when Claude agent is not built
TEST(ClaudeIntegrationTest, NotBuilt) {
    GTEST_SKIP() << "Claude agent not built (IDASQL_WITH_CLAUDE_AGENT=OFF)";
}

#endif // IDASQL_HAS_CLAUDE_AGENT

} // namespace testing
} // namespace idasql
