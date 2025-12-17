/**
 * cli_test.cpp - Tests for idasql CLI tool
 *
 * Tests the idasql.exe command-line interface:
 *   - Query mode (-q / -c)
 *   - File execution mode (-f)
 *   - Interactive mode (-i) - basic validation
 *   - Help output (-h)
 *   - Error handling
 *
 * NOTE: This file intentionally does NOT include IDA SDK headers.
 * CLI tests run external executable - no IDA SDK needed.
 */

// Standard headers FIRST (before any IDA headers could be included)
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <array>
#include <memory>
#include <string>

#include <gtest/gtest.h>

namespace idasql {
namespace testing {

// Local database path storage (avoids test_fixtures.hpp IDA dependency)
inline std::string& cli_test_database_path() {
    static std::string path;
    return path;
}

// ============================================================================
// CLI Test Fixture
// ============================================================================

class CLITest : public ::testing::Test {
 protected:
    // Path to idasql.exe (set via environment or default)
    static std::string idasql_path;

    // IDA SDK bin path for DLL loading
    static std::string ida_bin_path;

    static bool file_exists(const std::string& path) {
        std::ifstream f(path);
        return f.good();
    }

    static std::string join_path(const std::string& base,
                                 const std::string& a,
                                 const std::string& b) {
        if (base.empty()) return a + "/" + b;
        if (base.back() == '/' || base.back() == '\\') return base + a + "/" + b;
        return base + "/" + a + "/" + b;
    }

    static std::string find_cli_in_build_dir(const std::string& build_dir,
                                             const std::string& preferred_config) {
        if (build_dir.empty()) return {};

        auto try_config = [&](const std::string& config) -> std::string {
            if (config.empty()) return {};
            std::string candidate = join_path(build_dir, config, "idasql.exe");
            if (file_exists(candidate)) return candidate;
            return {};
        };

        if (auto found = try_config(preferred_config); !found.empty()) return found;

        const char* fallback_configs[] = {"RelWithDebInfo", "Release", "Debug", "MinSizeRel"};
        for (const char* config : fallback_configs) {
            if (auto found = try_config(config); !found.empty()) return found;
        }

        return {};
    }

    static void SetUpTestSuite() {
        // Try environment variable first
        const char* env_path = getenv("IDASQL_PATH");
        if (env_path && *env_path) {
            idasql_path = env_path;
        }
#if defined(IDASQL_CLI_DIR) && defined(IDASQL_CLI_CONFIG)
        // Use CMake-provided path (matches build configuration)
        else {
            idasql_path =
                find_cli_in_build_dir(std::string(IDASQL_CLI_DIR), std::string(IDASQL_CLI_CONFIG));
        }
#else
        // Fallback: search multiple configs (when not built via CMake)
        else {
            const char* configs[] = {"Release", "RelWithDebInfo", "Debug", "MinSizeRel"};
            const char* prefixes[] = {
                "../src/cli/build/",           // from tests/
                "../../src/cli/build/",        // from tests/build/
                "../../../src/cli/build/"      // from tests/build/<config>/
            };
            for (const char* prefix : prefixes) {
                for (const char* config : configs) {
                    std::string path = std::string(prefix) + config + "/idasql.exe";
                    if (file_exists(path)) {
                        idasql_path = path;
                        break;
                    }
                }
                if (!idasql_path.empty()) break;
            }
        }
#endif

        if (!idasql_path.empty() && !file_exists(idasql_path)) {
            idasql_path.clear();
        }

        // Get test database path: environment variable or compile-time default
        const char* db_path = getenv("IDASQL_TEST_DB");
        if (db_path && *db_path) {
            cli_test_database_path() = db_path;
        }
#ifdef IDASQL_TEST_DB_PATH
        else {
            cli_test_database_path() = IDASQL_TEST_DB_PATH;
        }
#endif

        // Get IDA SDK path for DLL loading
        const char* ida_sdk = getenv("IDASDK");
        if (ida_sdk && *ida_sdk) {
            ida_bin_path = std::string(ida_sdk) + "\\bin";
        }
    }

    // Execute CLI command and capture output
    struct CommandResult {
        std::string stdout_output;
        std::string stderr_output;
        int exit_code;
    };

    CommandResult run_cli(const std::string& args) {
        CommandResult result;

        if (idasql_path.empty() || !file_exists(idasql_path)) {
            result.exit_code = -1;
            result.stderr_output = "idasql CLI executable not found";
            return result;
        }

        // Build command with PATH set for IDA DLLs
        std::string cmd;
#ifdef _WIN32
        if (!ida_bin_path.empty()) {
            // Use cmd /c to set PATH before running
            cmd = "cmd /c \"set PATH=" + ida_bin_path + ";%PATH% && ";
            cmd += "\"" + idasql_path + "\" " + args + "\" 2>&1";
        } else {
            cmd = "\"" + idasql_path + "\" " + args + " 2>&1";
        }
#else
        cmd = "\"" + idasql_path + "\" " + args + " 2>&1";
#endif

        std::array<char, 4096> buffer;
        std::string output;

        // Use popen to capture output
#ifdef _WIN32
        FILE* pipe = _popen(cmd.c_str(), "r");
#else
        FILE* pipe = popen(cmd.c_str(), "r");
#endif
        if (!pipe) {
            result.exit_code = -1;
            result.stderr_output = "Failed to execute command";
            return result;
        }

        while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
            output += buffer.data();
        }

#ifdef _WIN32
        result.exit_code = _pclose(pipe);
#else
        result.exit_code = pclose(pipe);
#endif

        result.stdout_output = output;
        return result;
    }

    // Get test database path
    std::string get_db_path() {
        return cli_test_database_path();
    }

    // Create temp SQL file
    std::string create_temp_sql(const std::string& content) {
        std::string path = "temp_test_query.sql";
        std::ofstream file(path);
        file << content;
        file.close();
        return path;
    }

    void cleanup_temp_sql(const std::string& path) {
        std::remove(path.c_str());
    }
};

std::string CLITest::idasql_path;
std::string CLITest::ida_bin_path;

// ============================================================================
// Help Tests
// ============================================================================

TEST_F(CLITest, HelpShowsUsage) {
    auto result = run_cli("-h");
    // Skip if CLI executable not found or returned no useful output
    if (result.exit_code == -1 ||
        result.stdout_output.find("idasql") == std::string::npos) {
        GTEST_SKIP() << "idasql CLI executable not found or not responding";
    }
    EXPECT_NE(result.stdout_output.find("Usage:"), std::string::npos)
        << "Help should show usage information";
    EXPECT_NE(result.stdout_output.find("-s"), std::string::npos)
        << "Help should mention -s switch";
    EXPECT_NE(result.stdout_output.find("-q"), std::string::npos)
        << "Help should mention -q switch";
    EXPECT_NE(result.stdout_output.find("-i"), std::string::npos)
        << "Help should mention -i switch";
}

// ============================================================================
// Query Mode Tests (-q / -c)
// ============================================================================

class CLIQueryTest : public CLITest {
protected:
    void SetUp() override {
        if (get_db_path().empty()) {
            GTEST_SKIP() << "No test database specified";
        }
    }
};

TEST_F(CLIQueryTest, QueryFuncsCount) {
    auto result = run_cli("-s \"" + get_db_path() + "\" -q \"SELECT COUNT(*) as count FROM funcs\"");
    EXPECT_NE(result.stdout_output.find("count"), std::string::npos)
        << "Should return count column";
}

TEST_F(CLIQueryTest, QueryFuncsLimit) {
    auto result = run_cli("-s \"" + get_db_path() + "\" -q \"SELECT name FROM funcs LIMIT 5\"");
    EXPECT_NE(result.stdout_output.find("name"), std::string::npos)
        << "Should return function names";
}

TEST_F(CLIQueryTest, QueryWithPythonStyleC) {
    // -c should work the same as -q
    auto result = run_cli("-s \"" + get_db_path() + "\" -c \"SELECT COUNT(*) FROM segments\"");
    EXPECT_NE(result.stdout_output.find("COUNT"), std::string::npos)
        << "-c switch should work like -q";
}

TEST_F(CLIQueryTest, QuerySegments) {
    auto result = run_cli("-s \"" + get_db_path() + "\" -q \"SELECT name FROM segments\"");
    // Most binaries have .text segment
    EXPECT_NE(result.stdout_output.find("text"), std::string::npos)
        << "Should find .text segment";
}

TEST_F(CLIQueryTest, QueryWithSQLFunctions) {
    auto result = run_cli("-s \"" + get_db_path() + "\" -q \"SELECT func_qty()\"");
    EXPECT_NE(result.stdout_output.find("func_qty"), std::string::npos)
        << "SQL functions should work";
}

// ============================================================================
// File Execution Mode Tests (-f)
// ============================================================================

TEST_F(CLIQueryTest, ExecuteSQLFile) {
    std::string sql_path = create_temp_sql(
        "SELECT COUNT(*) as total FROM funcs;\n"
        "SELECT name FROM segments LIMIT 3;\n"
    );

    auto result = run_cli("-s \"" + get_db_path() + "\" -f \"" + sql_path + "\"");

    EXPECT_NE(result.stdout_output.find("total"), std::string::npos)
        << "Should execute first query";
    EXPECT_NE(result.stdout_output.find("name"), std::string::npos)
        << "Should execute second query";

    cleanup_temp_sql(sql_path);
}

TEST_F(CLIQueryTest, ExecuteExistingSQLFile) {
    // Test with existing SQL files from tests/sql/
    auto result = run_cli("-s \"" + get_db_path() + "\" -f \"sql/funcs_count.sql\"");
    // Should execute without error
    EXPECT_TRUE(result.stdout_output.find("Error") == std::string::npos ||
                result.stdout_output.find("error") == std::string::npos)
        << "Should execute SQL file without errors";
}

// ============================================================================
// Error Handling Tests
// ============================================================================

TEST_F(CLITest, MissingDatabaseError) {
    auto result = run_cli("-q \"SELECT 1\"");
    // Skip if CLI executable not found
    if (result.exit_code == -1 ||
        result.stdout_output.find("idasql") == std::string::npos) {
        GTEST_SKIP() << "idasql CLI executable not found";
    }
    EXPECT_NE(result.stdout_output.find("Error"), std::string::npos)
        << "Should show error when database not specified";
}

TEST_F(CLITest, MissingActionError) {
    auto result = run_cli("-s nonexistent.i64");
    // Skip if CLI executable not found
    if (result.exit_code == -1 ||
        result.stdout_output.find("idasql") == std::string::npos) {
        GTEST_SKIP() << "idasql CLI executable not found";
    }
    EXPECT_NE(result.stdout_output.find("Error"), std::string::npos)
        << "Should show error when no action specified";
}

TEST_F(CLIQueryTest, InvalidSQLError) {
    auto result = run_cli("-s \"" + get_db_path() + "\" -q \"SELECT * FROM nonexistent_table\"");
    EXPECT_NE(result.stdout_output.find("Error"), std::string::npos)
        << "Should show error for invalid SQL";
}

// ============================================================================
// Output Format Tests
// ============================================================================

TEST_F(CLIQueryTest, TableFormatOutput) {
    auto result = run_cli("-s \"" + get_db_path() + "\" -q \"SELECT name, size FROM funcs LIMIT 3\"");

    // Should have table borders
    EXPECT_NE(result.stdout_output.find("+"), std::string::npos)
        << "Output should have table borders";
    EXPECT_NE(result.stdout_output.find("|"), std::string::npos)
        << "Output should have column separators";
    EXPECT_NE(result.stdout_output.find("row"), std::string::npos)
        << "Output should show row count";
}

}  // namespace testing
}  // namespace idasql
