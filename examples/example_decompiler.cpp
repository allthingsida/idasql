/**
 * example_decompiler.cpp - Hex-Rays decompiler analysis with IDASQL
 *
 * Demonstrates:
 *   - Querying pseudocode table (line-by-line access)
 *   - Querying ctree_lvars table (local variables)
 *   - Using decompile() SQL function (full text)
 *   - Finding patterns in decompiled code
 *
 * Requires: Hex-Rays decompiler license
 */

#include <iostream>
#include <iomanip>
#include <idasql/database.hpp>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <database.i64>\n";
        std::cerr << "\nNote: Requires Hex-Rays decompiler license.\n";
        return 1;
    }

    idasql::Session session;
    if (!session.open(argv[1])) {
        std::cerr << "Error: " << session.error() << "\n";
        return 1;
    }

    // =========================================================================
    // Decompiler availability check
    // =========================================================================

    std::cout << "=== Decompiler Analysis ===\n\n";

    // Try to decompile a function to check if Hex-Rays is available
    auto test = session.query("SELECT decompile(func_at_index(0)) as code");
    if (!test.success || test.empty() || test.rows[0][0].find("Decompiler") != std::string::npos) {
        std::cerr << "Warning: Hex-Rays decompiler may not be available.\n";
        std::cerr << "Some queries may fail or return empty results.\n\n";
    }

    // =========================================================================
    // Functions by pseudocode line count
    // =========================================================================

    std::cout << "=== Functions by Pseudocode Complexity ===\n";

    auto complex = session.query(
        "SELECT "
        "  func_at(func_addr) as name, "
        "  COUNT(*) as lines "
        "FROM pseudocode "
        "GROUP BY func_addr "
        "ORDER BY lines DESC "
        "LIMIT 10"
    );

    std::cout << std::setw(40) << "Function" << "Lines\n";
    std::cout << std::string(50, '-') << "\n";
    for (const auto& row : complex) {
        std::cout << std::setw(40) << row[0] << row[1] << "\n";
    }

    // =========================================================================
    // Functions with most local variables
    // =========================================================================

    std::cout << "\n=== Functions with Most Local Variables ===\n";

    auto most_vars = session.query(
        "SELECT "
        "  func_at(func_addr) as name, "
        "  COUNT(*) as total_vars, "
        "  SUM(CASE WHEN is_arg = 1 THEN 1 ELSE 0 END) as args, "
        "  SUM(CASE WHEN is_arg = 0 THEN 1 ELSE 0 END) as locals "
        "FROM ctree_lvars "
        "GROUP BY func_addr "
        "ORDER BY total_vars DESC "
        "LIMIT 10"
    );

    std::cout << std::setw(35) << "Function"
              << std::setw(8) << "Total"
              << std::setw(8) << "Args"
              << "Locals\n";
    std::cout << std::string(60, '-') << "\n";
    for (const auto& row : most_vars) {
        std::cout << std::setw(35) << row[0]
                  << std::setw(8) << row[1]
                  << std::setw(8) << row[2]
                  << row[3] << "\n";
    }

    // =========================================================================
    // Variable type analysis
    // =========================================================================

    std::cout << "\n=== Most Common Variable Types ===\n";

    auto var_types = session.query(
        "SELECT type, COUNT(*) as count "
        "FROM ctree_lvars "
        "WHERE type != '' "
        "GROUP BY type "
        "ORDER BY count DESC "
        "LIMIT 15"
    );

    for (const auto& row : var_types) {
        std::cout << std::setw(30) << row[0] << " - " << row[1] << " occurrences\n";
    }

    // =========================================================================
    // Show pseudocode for a specific function
    // =========================================================================

    std::cout << "\n=== Pseudocode for Largest Function (first 30 lines) ===\n";

    auto largest = session.scalar("SELECT address FROM funcs ORDER BY size DESC LIMIT 1");
    std::string pseudocode_sql =
        "SELECT line "
        "FROM pseudocode "
        "WHERE func_addr = " + largest + " "
        "ORDER BY line_num "
        "LIMIT 30";
    auto pseudocode = session.query(pseudocode_sql.c_str());

    for (const auto& row : pseudocode) {
        std::cout << row[0] << "\n";
    }

    // =========================================================================
    // Local variables for a function
    // =========================================================================

    std::cout << "\n=== Variables in Largest Function ===\n";

    std::string vars_sql =
        "SELECT name, type, size, "
        "       CASE WHEN is_arg = 1 THEN 'arg' ELSE 'local' END as kind "
        "FROM ctree_lvars "
        "WHERE func_addr = " + largest + " "
        "ORDER BY is_arg DESC, idx";
    auto vars = session.query(vars_sql.c_str());

    std::cout << std::setw(20) << "Name"
              << std::setw(25) << "Type"
              << std::setw(8) << "Size"
              << "Kind\n";
    std::cout << std::string(60, '-') << "\n";
    for (const auto& row : vars) {
        std::cout << std::setw(20) << row[0]
                  << std::setw(25) << row[1]
                  << std::setw(8) << row[2]
                  << row[3] << "\n";
    }

    // =========================================================================
    // Full decompilation with decompile() function
    // =========================================================================

    std::cout << "\n=== Using decompile() SQL Function ===\n";

    // Find main function
    auto main_addr = session.scalar(
        "SELECT address FROM funcs WHERE name LIKE '%main%' LIMIT 1"
    );

    if (!main_addr.empty()) {
        std::cout << "Decompiling main function:\n\n";
        auto code = session.scalar("SELECT decompile(" + main_addr + ")");
        std::cout << code << "\n";
    } else {
        std::cout << "No 'main' function found.\n";
    }

    // =========================================================================
    // Search pseudocode for patterns
    // =========================================================================

    std::cout << "\n=== Lines Containing 'if' Statements ===\n";

    auto if_lines = session.query(
        "SELECT func_at(func_addr) as func, line "
        "FROM pseudocode "
        "WHERE line LIKE '%if (%' "
        "LIMIT 10"
    );

    for (const auto& row : if_lines) {
        std::cout << "[" << row[0] << "] " << row[1] << "\n";
    }

    std::cout << "\nDone.\n";
    return 0;
}
