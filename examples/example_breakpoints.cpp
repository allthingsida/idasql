/**
 * example_breakpoints.cpp - Breakpoint management with IDASQL
 *
 * Demonstrates:
 *   - Querying the breakpoints table
 *   - Adding software and hardware breakpoints via INSERT
 *   - Disabling breakpoints via UPDATE
 *   - Deleting breakpoints via DELETE
 *   - Joining breakpoints with funcs
 *
 * Breakpoints persist in the IDB even without an active debugger session.
 *
 * Build & Run:
 *   cmake -B build && cmake --build build --config Release
 *   set PATH=%IDASDK%\bin;%PATH%
 *   build\Release\example_breakpoints.exe database.i64
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

    std::cout << "Opening: " << argv[1] << "...\n";
    if (!session.open(argv[1])) {
        std::cerr << "Error: " << session.error() << "\n";
        return 1;
    }

    // =========================================================================
    // 1. List existing breakpoints
    // =========================================================================

    std::cout << "=== Existing Breakpoints ===\n";

    auto existing = session.query(
        "SELECT printf('0x%08X', address) as addr, type_name, enabled, "
        "       loc_type_name, condition, \"group\" "
        "FROM breakpoints"
    );

    if (existing.empty()) {
        std::cout << "(none)\n";
    } else {
        for (const auto& row : existing) {
            std::cout << row[0] << "  " << std::setw(16) << row[1]
                      << "  enabled=" << row[2]
                      << "  loc=" << row[3] << "\n";
        }
    }

    // =========================================================================
    // 2. Add two breakpoints at the first two function addresses
    // =========================================================================

    std::cout << "\n=== Adding Breakpoints ===\n";

    // Get two function addresses to use
    auto funcs = session.query(
        "SELECT address, name FROM funcs ORDER BY address LIMIT 2"
    );

    if (funcs.row_count() < 2) {
        std::cerr << "Need at least 2 functions in database\n";
        return 1;
    }

    std::string addr1 = funcs.rows[0][0];
    std::string name1 = funcs.rows[0][1];
    std::string addr2 = funcs.rows[1][0];
    std::string name2 = funcs.rows[1][1];

    // Insert a software breakpoint at the first function
    auto r1 = session.query(
        "INSERT INTO breakpoints (address) VALUES (" + addr1 + ")"
    );
    std::cout << "Added software breakpoint at " << name1 << "\n";

    // Insert a hardware write watchpoint at the second function
    auto r2 = session.query(
        "INSERT INTO breakpoints (address, type, size) VALUES (" + addr2 + ", 1, 4)"
    );
    std::cout << "Added hardware watchpoint at " << name2 << "\n";

    // Show what we have
    auto after_add = session.query(
        "SELECT printf('0x%08X', address) as addr, type_name, enabled, size "
        "FROM breakpoints"
    );

    std::cout << "\nBreakpoints after adding:\n";
    std::cout << std::left
              << std::setw(14) << "Address"
              << std::setw(18) << "Type"
              << std::setw(10) << "Enabled"
              << std::setw(6)  << "Size" << "\n";
    std::cout << std::string(48, '-') << "\n";

    for (const auto& row : after_add) {
        std::cout << std::setw(14) << row[0]
                  << std::setw(18) << row[1]
                  << std::setw(10) << row[2]
                  << std::setw(6)  << row[3] << "\n";
    }

    // =========================================================================
    // 3. Disable the second breakpoint
    // =========================================================================

    std::cout << "\n=== Disabling Second Breakpoint ===\n";

    session.query(
        "UPDATE breakpoints SET enabled = 0 WHERE address = " + addr2
    );

    auto after_disable = session.query(
        "SELECT printf('0x%08X', address) as addr, enabled, type_name "
        "FROM breakpoints"
    );

    for (const auto& row : after_disable) {
        std::cout << row[0] << "  enabled=" << row[1]
                  << "  " << row[2] << "\n";
    }

    // =========================================================================
    // 4. Delete the first breakpoint
    // =========================================================================

    std::cout << "\n=== Deleting First Breakpoint ===\n";

    session.query(
        "DELETE FROM breakpoints WHERE address = " + addr1
    );

    auto after_delete = session.query(
        "SELECT printf('0x%08X', address) as addr, enabled, type_name, size "
        "FROM breakpoints"
    );

    std::cout << "Remaining breakpoints: " << after_delete.row_count() << "\n";
    for (const auto& row : after_delete) {
        std::cout << row[0] << "  enabled=" << row[1]
                  << "  " << row[2] << "  size=" << row[3] << "\n";
    }

    // =========================================================================
    // 5. Clean up
    // =========================================================================

    session.query("DELETE FROM breakpoints WHERE address = " + addr2);
    std::cout << "\nCleaned up. Final count: "
              << session.scalar("SELECT COUNT(*) FROM breakpoints")
              << " breakpoints.\n";

    std::cout << "\nDone.\n";
    return 0;
}
