/**
 * example_grep_search.cpp - Grep-style unified entity search
 *
 * Demonstrates:
 *   - grep() SQL function (JSON output)
 *   - grep virtual table (structured rows)
 *   - Pattern semantics and pagination
 */

#include <iostream>
#include <iomanip>
#include <idasql/database.hpp>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <database.i64> [pattern]\n";
        return 1;
    }

    idasql::Session session;
    if (!session.open(argv[1])) {
        std::cerr << "Error: " << session.error() << "\n";
        return 1;
    }

    std::string pattern = (argc >= 3) ? argv[2] : "main";
    std::string escaped_pattern = pattern;
    for (size_t pos = 0; (pos = escaped_pattern.find('\'', pos)) != std::string::npos; pos += 2) {
        escaped_pattern.insert(pos, 1, '\'');
    }

    std::cout << "=== grep() JSON Search ===\n\n";
    auto json_result = session.query(
        "SELECT grep('" + escaped_pattern + "', 10, 0)"
    );
    if (json_result.row_count() > 0) {
        std::cout << json_result.scalar() << "\n\n";
    }

    std::cout << "=== grep Table Search ===\n\n";

    auto rows = session.query(
        "SELECT name, kind, address, full_name "
        "FROM grep "
        "WHERE pattern = '" + escaped_pattern + "' "
        "ORDER BY kind, name "
        "LIMIT 10"
    );

    std::cout << std::left
              << std::setw(28) << "Name"
              << std::setw(14) << "Kind"
              << std::setw(14) << "Address"
              << "Full Name\n";
    std::cout << std::string(90, '-') << "\n";

    for (const auto& row : rows) {
        std::string addr = row[2].empty() ? "-" : ("0x" + row[2]);
        std::cout << std::setw(28) << row[0]
                  << std::setw(14) << row[1]
                  << std::setw(14) << addr
                  << row[3] << "\n";
    }

    std::cout << "\n=== Prefix Pattern Example ===\n\n";
    auto prefix_rows = session.query(
        "SELECT name, kind "
        "FROM grep "
        "WHERE pattern = 'sub%' "
        "ORDER BY name "
        "LIMIT 5 OFFSET 0"
    );
    auto prefix_rows_page2 = session.query(
        "SELECT name, kind "
        "FROM grep "
        "WHERE pattern = 'sub%' "
        "ORDER BY name "
        "LIMIT 5 OFFSET 5"
    );

    std::cout << "Page 1:\n";
    for (const auto& row : prefix_rows) {
        std::cout << "  " << row[0] << " (" << row[1] << ")\n";
    }
    std::cout << "\nPage 2:\n";
    for (const auto& row : prefix_rows_page2) {
        std::cout << "  " << row[0] << " (" << row[1] << ")\n";
    }

    std::cout << "\nDone.\n";
    return 0;
}
