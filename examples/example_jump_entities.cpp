/**
 * example_jump_entities.cpp - "Jump to Anything" with table-valued function
 *
 * Demonstrates the jump_entities virtual table for unified entity search.
 * Unlike jump_search() which returns JSON, jump_entities returns proper
 * table rows that can be composed with full SQL.
 *
 * Demonstrates:
 *   - Basic entity search with prefix/contains modes
 *   - Filtering by entity kind (function, struct, member, etc.)
 *   - JOINs with other tables for enriched data
 *   - Pagination for virtual scrolling
 *   - Aggregations and grouping
 */

#include <iostream>
#include <iomanip>
#include <idasql/database.hpp>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <database.i64> [search_prefix]\n";
        return 1;
    }

    idasql::Session session;
    if (!session.open(argv[1])) {
        std::cerr << "Error: " << session.error() << "\n";
        return 1;
    }

    std::string prefix = (argc >= 3) ? argv[2] : "sub";

    // =========================================================================
    // Basic Usage - Function Call Syntax
    // =========================================================================

    std::cout << "=== Basic Search: '" << prefix << "' (prefix mode) ===\n\n";

    auto result = session.query(
        "SELECT name, kind, address, ordinal, parent_name, full_name "
        "FROM jump_entities('" + prefix + "', 'prefix') "
        "LIMIT 10"
    );

    std::cout << std::left
              << std::setw(30) << "Name"
              << std::setw(12) << "Kind"
              << std::setw(12) << "Address"
              << "Full Name\n";
    std::cout << std::string(70, '-') << "\n";

    for (const auto& row : result) {
        std::string addr = row[2].empty() ? "-" : row[2];
        std::cout << std::setw(30) << row[0]
                  << std::setw(12) << row[1]
                  << std::setw(12) << addr
                  << row[5] << "\n";
    }

    // =========================================================================
    // Contains Mode - Search Anywhere in Name
    // =========================================================================

    std::cout << "\n=== Contains Mode: 'main' ===\n\n";

    auto contains = session.query(
        "SELECT name, kind, full_name "
        "FROM jump_entities('main', 'contains') "
        "LIMIT 10"
    );

    for (const auto& row : contains) {
        std::cout << std::setw(40) << row[0]
                  << std::setw(12) << row[1]
                  << row[2] << "\n";
    }

    // =========================================================================
    // Filter by Kind - Only Functions
    // =========================================================================

    std::cout << "\n=== Functions Only ===\n\n";

    auto funcs_only = session.query(
        "SELECT name, address "
        "FROM jump_entities('" + prefix + "', 'prefix') "
        "WHERE kind = 'function' "
        "LIMIT 10"
    );

    for (const auto& row : funcs_only) {
        std::cout << std::setw(30) << row[0] << " @ " << row[1] << "\n";
    }

    // =========================================================================
    // Filter by Kind - Only Types (Structs, Unions, Enums)
    // =========================================================================

    std::cout << "\n=== Types Only (struct/union/enum starting with '_') ===\n\n";

    auto types = session.query(
        "SELECT name, kind, ordinal "
        "FROM jump_entities('_', 'prefix') "
        "WHERE kind IN ('struct', 'union', 'enum') "
        "LIMIT 10"
    );

    for (const auto& row : types) {
        std::cout << std::setw(35) << row[0]
                  << std::setw(10) << row[1]
                  << "ordinal: " << row[2] << "\n";
    }

    // =========================================================================
    // Members with Parent Info
    // =========================================================================

    std::cout << "\n=== Members (showing parent.member) ===\n\n";

    auto members = session.query(
        "SELECT name, parent_name, full_name "
        "FROM jump_entities('e', 'prefix') "
        "WHERE kind IN ('member', 'enum_member') "
        "LIMIT 10"
    );

    for (const auto& row : members) {
        std::cout << std::setw(25) << row[0]
                  << " in " << std::setw(25) << row[1]
                  << " (" << row[2] << ")\n";
    }

    // =========================================================================
    // JOIN with funcs Table - Get Function Sizes
    // =========================================================================

    std::cout << "\n=== JOIN with funcs Table (function sizes) ===\n\n";

    auto with_size = session.query(
        "SELECT j.name, f.size, f.address "
        "FROM jump_entities('" + prefix + "', 'prefix') j "
        "LEFT JOIN funcs f ON j.address = f.address "
        "WHERE j.kind = 'function' "
        "ORDER BY f.size DESC "
        "LIMIT 10"
    );

    std::cout << std::setw(30) << "Function"
              << std::setw(10) << "Size"
              << "Address\n";
    std::cout << std::string(55, '-') << "\n";

    for (const auto& row : with_size) {
        std::cout << std::setw(30) << row[0]
                  << std::setw(10) << row[1]
                  << row[2] << "\n";
    }

    // =========================================================================
    // Aggregation - Count by Kind
    // =========================================================================

    std::cout << "\n=== Entity Count by Kind (prefix '" << prefix << "') ===\n\n";

    auto by_kind = session.query(
        "SELECT kind, COUNT(*) as count "
        "FROM jump_entities('" + prefix + "', 'prefix') "
        "GROUP BY kind "
        "ORDER BY count DESC"
    );

    for (const auto& row : by_kind) {
        std::cout << std::setw(15) << row[0] << ": " << row[1] << "\n";
    }

    // =========================================================================
    // Pagination Demo
    // =========================================================================

    std::cout << "\n=== Pagination Demo ===\n\n";

    // Count total
    auto total = session.query(
        "SELECT COUNT(*) FROM jump_entities('" + prefix + "', 'prefix')"
    );
    std::cout << "Total matches: " << total.scalar() << "\n\n";

    // Page 1
    std::cout << "Page 1 (items 1-3):\n";
    auto page1 = session.query(
        "SELECT name, kind FROM jump_entities('" + prefix + "', 'prefix') LIMIT 3 OFFSET 0"
    );
    for (const auto& row : page1) {
        std::cout << "  " << row[0] << " (" << row[1] << ")\n";
    }

    // Page 2
    std::cout << "\nPage 2 (items 4-6):\n";
    auto page2 = session.query(
        "SELECT name, kind FROM jump_entities('" + prefix + "', 'prefix') LIMIT 3 OFFSET 3"
    );
    for (const auto& row : page2) {
        std::cout << "  " << row[0] << " (" << row[1] << ")\n";
    }

    // =========================================================================
    // Case-Insensitive Search Demo
    // =========================================================================

    std::cout << "\n=== Case-Insensitive Search ===\n\n";

    auto upper = session.query(
        "SELECT COUNT(*) FROM jump_entities('SUB', 'prefix')"
    );
    auto lower = session.query(
        "SELECT COUNT(*) FROM jump_entities('sub', 'prefix')"
    );

    std::cout << "Search 'SUB': " << upper.scalar() << " results\n";
    std::cout << "Search 'sub': " << lower.scalar() << " results\n";
    std::cout << "(Both should match the same entities)\n";

    // =========================================================================
    // Complex Query - Subquery
    // =========================================================================

    std::cout << "\n=== Complex Query - Find Types with Many Members ===\n\n";

    auto complex = session.query(
        "SELECT parent_name, COUNT(*) as member_count "
        "FROM jump_entities('', 'contains') "
        "WHERE kind = 'member' AND parent_name IS NOT NULL "
        "GROUP BY parent_name "
        "HAVING COUNT(*) > 2 "
        "ORDER BY member_count DESC "
        "LIMIT 5"
    );

    // Note: empty pattern returns no results, this is just to show the syntax
    // In practice you'd use a real pattern
    if (complex.row_count() > 0) {
        for (const auto& row : complex) {
            std::cout << std::setw(30) << row[0] << ": " << row[1] << " members\n";
        }
    } else {
        std::cout << "(No results - empty pattern returns no results)\n";
        std::cout << "Try with a real pattern like: SELECT parent_name, COUNT(*) ...\n";
        std::cout << "  FROM jump_entities('e', 'prefix') WHERE kind = 'member' ...\n";
    }

    std::cout << "\nDone.\n";
    return 0;
}
