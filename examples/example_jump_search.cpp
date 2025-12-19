/**
 * example_jump_search.cpp - "Jump to Anything" unified entity search
 *
 * Demonstrates:
 *   - Using jump_search() for unified entity search
 *   - Using jump_query() to get the generated SQL
 *   - Prefix search vs Contains search modes
 *   - Pagination for virtual scrolling
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

    std::string prefix = (argc >= 3) ? argv[2] : "main";

    // =========================================================================
    // Basic jump_search usage (returns JSON)
    // =========================================================================

    std::cout << "=== Jump Search: '" << prefix << "' (prefix mode) ===\n\n";

    auto result = session.query(
        "SELECT jump_search('" + prefix + "', 'prefix', 10, 0)"
    );

    if (result.row_count() > 0) {
        std::cout << "JSON result:\n" << result.scalar() << "\n\n";
    }

    // =========================================================================
    // Execute the generated SQL directly for structured results
    // =========================================================================

    std::cout << "=== Structured Results (first 10) ===\n\n";

    // Get the generated query
    auto query_result = session.query(
        "SELECT jump_query('" + prefix + "', 'prefix', 10, 0)"
    );
    std::string sql = query_result.scalar();

    // Execute it directly
    auto entities = session.query(sql);

    std::cout << std::left
              << std::setw(12) << "Kind"
              << std::setw(35) << "Name"
              << std::setw(18) << "Address"
              << "Full Name\n";
    std::cout << std::string(80, '-') << "\n";

    for (const auto& row : entities) {
        std::string addr = row[2].empty() ? "-" : ("0x" + row[2]);
        std::cout << std::setw(12) << row[1]      // kind
                  << std::setw(35) << row[0]      // name
                  << std::setw(18) << addr        // address
                  << row[5] << "\n";              // full_name
    }

    // =========================================================================
    // Pagination demo
    // =========================================================================

    std::cout << "\n=== Pagination: Page 1 vs Page 2 ===\n";

    // Count total matches
    auto count_sql =
        "SELECT COUNT(*) FROM (" +
        session.query("SELECT jump_query('" + prefix + "', 'prefix', 99999, 0)").scalar() +
        ")";
    auto count_result = session.query(count_sql);
    std::cout << "Total matches: " << count_result.scalar() << "\n\n";

    // Page 1
    auto page1 = session.query(
        "SELECT jump_search('" + prefix + "', 'prefix', 5, 0)"
    );
    std::cout << "Page 1 (offset 0, limit 5):\n" << page1.scalar() << "\n\n";

    // Page 2
    auto page2 = session.query(
        "SELECT jump_search('" + prefix + "', 'prefix', 5, 5)"
    );
    std::cout << "Page 2 (offset 5, limit 5):\n" << page2.scalar() << "\n\n";

    // =========================================================================
    // Contains mode (searches anywhere in name)
    // =========================================================================

    std::cout << "=== Contains Mode vs Prefix Mode ===\n\n";

    // Prefix mode - only matches at start
    auto prefix_results = session.query(
        "SELECT jump_search('" + prefix + "', 'prefix', 50, 0)"
    );

    // Contains mode - matches anywhere
    auto contains_results = session.query(
        "SELECT jump_search('" + prefix + "', 'contains', 50, 0)"
    );

    // Count occurrences in each result
    auto count_json = [](const std::string& json) {
        if (json == "[]") return 0;
        int count = 0;
        for (char c : json) if (c == '{') count++;
        return count;
    };

    std::cout << "Prefix mode matches: " << count_json(prefix_results.scalar()) << "\n";
    std::cout << "Contains mode matches: " << count_json(contains_results.scalar()) << "\n";

    // =========================================================================
    // Search different entity types
    // =========================================================================

    std::cout << "\n=== Search by Entity Type ===\n\n";

    // Find some struct names
    auto structs = session.query(
        "SELECT name FROM types WHERE is_struct = 1 LIMIT 1"
    );
    if (structs.row_count() > 0) {
        std::string struct_prefix = structs.scalar().substr(0, 4);
        auto struct_search = session.query(
            "SELECT jump_search('" + struct_prefix + "', 'prefix', 10, 0)"
        );
        std::cout << "Struct search ('" << struct_prefix << "'): "
                  << count_json(struct_search.scalar()) << " results\n";
    }

    // Find some enum names
    auto enums = session.query(
        "SELECT name FROM types WHERE is_enum = 1 LIMIT 1"
    );
    if (enums.row_count() > 0) {
        std::string enum_prefix = enums.scalar().substr(0, 4);
        auto enum_search = session.query(
            "SELECT jump_search('" + enum_prefix + "', 'prefix', 10, 0)"
        );
        std::cout << "Enum search ('" << enum_prefix << "'): "
                  << count_json(enum_search.scalar()) << " results\n";
    }

    // =========================================================================
    // Show the generated SQL
    // =========================================================================

    std::cout << "\n=== Generated SQL Query ===\n\n";
    std::cout << sql << "\n";

    std::cout << "\nDone.\n";
    return 0;
}
