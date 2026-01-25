/**
 * example_instructions.cpp - Instruction analysis with IDASQL
 *
 * Demonstrates:
 *   - Querying the instructions table
 *   - Mnemonic distribution analysis
 *   - Finding specific instruction patterns
 *   - Using itype for instruction classification
 */

#include <iostream>
#include <iomanip>
#include <idasql/database.hpp>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <database.i64>\n";
        return 1;
    }

    idasql::Session session;
    if (!session.open(argv[1])) {
        std::cerr << "Error: " << session.error() << "\n";
        return 1;
    }

    // =========================================================================
    // Instruction statistics
    // =========================================================================

    std::cout << "=== Instruction Statistics ===\n";

    // Get stats for the largest function
    auto largest_func = session.scalar("SELECT address FROM funcs ORDER BY size DESC LIMIT 1");
    std::cout << "Analyzing largest function at 0x" << std::hex << std::stoull(largest_func) << std::dec << "\n\n";

    // =========================================================================
    // Mnemonic distribution
    // =========================================================================

    std::cout << "=== Top 20 Most Common Instructions ===\n";

    auto mnemonics = session.query(
        "SELECT mnemonic, COUNT(*) as count "
        "FROM instructions "
        "GROUP BY mnemonic "
        "ORDER BY count DESC "
        "LIMIT 20"
    );

    std::cout << std::left << std::setw(15) << "Mnemonic" << std::setw(10) << "Count" << "\n";
    std::cout << std::string(25, '-') << "\n";

    for (const auto& row : mnemonics) {
        std::cout << std::setw(15) << row[0] << std::setw(10) << row[1] << "\n";
    }

    // =========================================================================
    // Call targets analysis
    // =========================================================================

    std::cout << "\n=== Most Common Call Targets ===\n";

    auto calls = session.query(
        "SELECT operand0, COUNT(*) as count "
        "FROM instructions "
        "WHERE mnemonic = 'call' "
        "GROUP BY operand0 "
        "ORDER BY count DESC "
        "LIMIT 15"
    );

    for (const auto& row : calls) {
        std::cout << std::setw(40) << row[0] << " - called " << row[1] << " times\n";
    }

    // =========================================================================
    // Functions with most NOP instructions (padding/alignment)
    // =========================================================================

    std::cout << "\n=== Functions with Most NOPs ===\n";

    auto nops = session.query(
        "SELECT func_at(func_addr) as name, COUNT(*) as nop_count "
        "FROM instructions "
        "WHERE mnemonic = 'nop' "
        "GROUP BY func_addr "
        "HAVING nop_count > 5 "
        "ORDER BY nop_count DESC "
        "LIMIT 10"
    );

    for (const auto& row : nops) {
        std::cout << std::setw(40) << row[0] << " - " << row[1] << " NOPs\n";
    }

    // =========================================================================
    // Jump instruction analysis
    // =========================================================================

    std::cout << "\n=== Jump Instruction Distribution ===\n";

    auto jumps = session.query(
        "SELECT mnemonic, COUNT(*) as count "
        "FROM instructions "
        "WHERE mnemonic LIKE 'j%' "  // All jump variants
        "GROUP BY mnemonic "
        "ORDER BY count DESC"
    );

    for (const auto& row : jumps) {
        std::cout << std::setw(10) << row[0] << " - " << row[1] << "\n";
    }

    // =========================================================================
    // Suspicious patterns (potential obfuscation)
    // =========================================================================

    std::cout << "\n=== Potential Obfuscation Patterns ===\n";

    // Functions with unusual push/pop ratio
    auto unusual = session.query(
        "SELECT "
        "  func_at(func_addr) as name, "
        "  SUM(CASE WHEN mnemonic = 'push' THEN 1 ELSE 0 END) as pushes, "
        "  SUM(CASE WHEN mnemonic = 'pop' THEN 1 ELSE 0 END) as pops "
        "FROM instructions "
        "GROUP BY func_addr "
        "HAVING pushes > 20 AND ABS(pushes - pops) > 5 "
        "ORDER BY pushes DESC "
        "LIMIT 10"
    );

    std::cout << std::setw(40) << "Function" << std::setw(10) << "Pushes" << "Pops\n";
    std::cout << std::string(60, '-') << "\n";
    for (const auto& row : unusual) {
        std::cout << std::setw(40) << row[0] << std::setw(10) << row[1] << row[2] << "\n";
    }

    // =========================================================================
    // Instruction type (itype) analysis
    // =========================================================================

    std::cout << "\n=== Instruction Types (itype) ===\n";
    std::cout << "(itype 16/17/18 = call variants, 56-111 = jumps)\n\n";

    auto itypes = session.query(
        "SELECT itype, mnemonic, COUNT(*) as count "
        "FROM instructions "
        "WHERE itype IN (16, 17, 18, 56, 57, 58, 59, 60) "  // calls and common jumps
        "GROUP BY itype "
        "ORDER BY count DESC"
    );

    std::cout << std::setw(8) << "itype" << std::setw(12) << "Mnemonic" << "Count\n";
    std::cout << std::string(30, '-') << "\n";
    for (const auto& row : itypes) {
        std::cout << std::setw(8) << row[0] << std::setw(12) << row[1] << row[2] << "\n";
    }

    // =========================================================================
    // Instructions in a specific function
    // =========================================================================

    std::cout << "\n=== Instructions in Largest Function ===\n";

    auto func_insns = session.query(
        "SELECT mnemonic, COUNT(*) as count "
        "FROM instructions "
        "WHERE func_addr = (SELECT address FROM funcs ORDER BY size DESC LIMIT 1) "
        "GROUP BY mnemonic "
        "ORDER BY count DESC "
        "LIMIT 10"
    );

    for (const auto& row : func_insns) {
        std::cout << std::setw(12) << row[0] << " - " << row[1] << "\n";
    }

    std::cout << "\nDone.\n";
    return 0;
}
