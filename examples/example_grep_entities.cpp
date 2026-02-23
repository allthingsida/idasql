/**
 * example_grep_entities.cpp - Grep table composability examples
 *
 * Demonstrates:
 *   - Structured search directly from the grep virtual table
 *   - Filtering by entity kind
 *   - JOINs with funcs
 *   - Aggregations and pagination
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

    std::string pattern = (argc >= 3) ? argv[2] : "sub%";
    std::string escaped_pattern = pattern;
    for (size_t pos = 0; (pos = escaped_pattern.find('\'', pos)) != std::string::npos; pos += 2) {
        escaped_pattern.insert(pos, 1, '\'');
    }

    std::cout << "=== Basic Search ===\n\n";
    auto result = session.query(
        "SELECT name, kind, address, parent_name, full_name "
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
    for (const auto& row : result) {
        std::string addr = row[2].empty() ? "-" : ("0x" + row[2]);
        std::cout << std::setw(28) << row[0]
                  << std::setw(14) << row[1]
                  << std::setw(14) << addr
                  << row[4] << "\n";
    }

    std::cout << "\n=== Functions Only + JOIN funcs ===\n\n";
    auto funcs_only = session.query(
        "SELECT g.name, f.size, printf('0x%X', f.address) as addr "
        "FROM grep g "
        "JOIN funcs f ON g.address = f.address "
        "WHERE g.pattern = '" + escaped_pattern + "' AND g.kind = 'function' "
        "ORDER BY f.size DESC "
        "LIMIT 10"
    );
    for (const auto& row : funcs_only) {
        std::cout << std::setw(35) << row[0]
                  << std::setw(10) << row[1]
                  << row[2] << "\n";
    }

    std::cout << "\n=== Kind Distribution ===\n\n";
    auto by_kind = session.query(
        "SELECT kind, COUNT(*) as cnt "
        "FROM grep "
        "WHERE pattern = '" + escaped_pattern + "' "
        "GROUP BY kind "
        "ORDER BY cnt DESC"
    );
    for (const auto& row : by_kind) {
        std::cout << std::setw(16) << row[0] << row[1] << "\n";
    }

    std::cout << "\n=== Pagination Demo (sub%) ===\n\n";
    auto page1 = session.query(
        "SELECT name, kind FROM grep "
        "WHERE pattern = 'sub%' "
        "ORDER BY name LIMIT 3 OFFSET 0"
    );
    auto page2 = session.query(
        "SELECT name, kind FROM grep "
        "WHERE pattern = 'sub%' "
        "ORDER BY name LIMIT 3 OFFSET 3"
    );
    std::cout << "Page 1:\n";
    for (const auto& row : page1) {
        std::cout << "  " << row[0] << " (" << row[1] << ")\n";
    }
    std::cout << "\nPage 2:\n";
    for (const auto& row : page2) {
        std::cout << "  " << row[0] << " (" << row[1] << ")\n";
    }

    std::cout << "\nDone.\n";
    return 0;
}
