/**
 * example_functions.cpp - Function analysis with IDASQL
 *
 * Demonstrates:
 *   - Querying the funcs table
 *   - Using xrefs for call graph analysis
 *   - Using blocks for CFG analysis
 *   - Combining tables with JOINs
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
    // Function size distribution
    // =========================================================================

    std::cout << "=== Function Size Distribution ===\n";

    auto dist = session.query(
        "SELECT "
        "  CASE "
        "    WHEN size < 16 THEN '1. tiny (<16)' "
        "    WHEN size < 64 THEN '2. small (16-64)' "
        "    WHEN size < 256 THEN '3. medium (64-256)' "
        "    WHEN size < 1024 THEN '4. large (256-1K)' "
        "    ELSE '5. huge (>1K)' "
        "  END as category, "
        "  COUNT(*) as count, "
        "  SUM(size) as total_bytes "
        "FROM funcs "
        "GROUP BY category "
        "ORDER BY category"
    );

    std::cout << std::left << std::setw(20) << "Category"
              << std::setw(10) << "Count"
              << std::setw(15) << "Total Bytes" << "\n";
    std::cout << std::string(45, '-') << "\n";

    for (const auto& row : dist) {
        std::cout << std::setw(20) << row[0]
                  << std::setw(10) << row[1]
                  << std::setw(15) << row[2] << "\n";
    }

    // =========================================================================
    // Most called functions (incoming xrefs)
    // =========================================================================

    std::cout << "\n=== Top 10 Most Called Functions ===\n";

    auto most_called = session.query(
        "SELECT f.name, COUNT(*) as callers "
        "FROM funcs f "
        "JOIN xrefs x ON f.address = x.to_ea "
        "WHERE x.is_code = 1 "
        "GROUP BY f.address "
        "ORDER BY callers DESC "
        "LIMIT 10"
    );

    for (const auto& row : most_called) {
        std::cout << std::setw(40) << row[0] << " - " << row[1] << " callers\n";
    }

    // =========================================================================
    // Functions making most calls (outgoing)
    // =========================================================================

    std::cout << "\n=== Top 10 Functions Making Most Calls ===\n";

    auto most_calls = session.query(
        "SELECT func_at(func_addr) as name, COUNT(*) as calls "
        "FROM instructions "
        "WHERE mnemonic = 'call' "
        "GROUP BY func_addr "
        "ORDER BY calls DESC "
        "LIMIT 10"
    );

    for (const auto& row : most_calls) {
        std::cout << std::setw(40) << row[0] << " - " << row[1] << " calls\n";
    }

    // =========================================================================
    // Functions with most basic blocks (complex CFG)
    // =========================================================================

    std::cout << "\n=== Top 10 Functions by Basic Block Count ===\n";

    auto complex = session.query(
        "SELECT "
        "  (SELECT name FROM funcs WHERE address = b.func_ea) as name, "
        "  COUNT(*) as blocks, "
        "  SUM(b.size) as total_size "
        "FROM blocks b "
        "GROUP BY b.func_ea "
        "ORDER BY blocks DESC "
        "LIMIT 10"
    );

    std::cout << std::setw(40) << "Function"
              << std::setw(10) << "Blocks"
              << std::setw(12) << "Size" << "\n";
    std::cout << std::string(62, '-') << "\n";

    for (const auto& row : complex) {
        std::cout << std::setw(40) << row[0]
                  << std::setw(10) << row[1]
                  << std::setw(12) << row[2] << "\n";
    }

    // =========================================================================
    // "Leaf" functions (no outgoing calls)
    // =========================================================================

    std::cout << "\n=== Leaf Functions (no calls, first 10) ===\n";

    auto leaves = session.query(
        "SELECT f.name, f.size "
        "FROM funcs f "
        "WHERE NOT EXISTS ("
        "  SELECT 1 FROM instructions i "
        "  WHERE i.func_addr = f.address AND i.mnemonic = 'call'"
        ") "
        "ORDER BY f.size DESC "
        "LIMIT 10"
    );

    for (const auto& row : leaves) {
        std::cout << std::setw(40) << row[0] << " (" << row[1] << " bytes)\n";
    }

    // =========================================================================
    // Orphan functions (no incoming xrefs)
    // =========================================================================

    std::cout << "\n=== Orphan Functions (no callers, first 10) ===\n";

    auto orphans = session.query(
        "SELECT f.name, printf('0x%X', f.address) as addr "
        "FROM funcs f "
        "WHERE NOT EXISTS ("
        "  SELECT 1 FROM xrefs x WHERE x.to_ea = f.address AND x.is_code = 1"
        ") "
        "LIMIT 10"
    );

    for (const auto& row : orphans) {
        std::cout << row[0] << " at " << row[1] << "\n";
    }

    std::cout << "\nDone.\n";
    return 0;
}
