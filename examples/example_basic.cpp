/**
 * example_basic.cpp - Basic IDASQL usage with Session
 *
 * Demonstrates:
 *   - Opening an IDA database with Session
 *   - Running queries with query() and getting results
 *   - Using scalar() for single values
 *   - Iterating over result rows
 *
 * This is the pattern for standalone CLI tools that manage the IDA lifecycle.
 *
 * Build & Run:
 *   cmake -B build && cmake --build build --config Release
 *   set PATH=%IDASDK%\bin;%PATH%
 *   build\Release\example_basic.exe database.i64
 */

#include <iostream>
#include <idasql/database.hpp>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <database.i64>\n";
        return 1;
    }

    // ==========================================================================
    // Open the IDA database using Session
    // ==========================================================================

    idasql::Session session;

    std::cout << "Opening: " << argv[1] << "...\n";
    if (!session.open(argv[1])) {
        std::cerr << "Error: " << session.error() << "\n";
        return 1;
    }

    std::cout << "\n" << session.info() << "\n";

    // ==========================================================================
    // Example 1: Get a single value with scalar()
    // ==========================================================================

    std::cout << "=== Scalar Queries ===\n";

    std::string func_count = session.scalar("SELECT COUNT(*) FROM funcs");
    std::cout << "Total functions: " << func_count << "\n";

    std::string segment_count = session.scalar("SELECT COUNT(*) FROM segments");
    std::cout << "Total segments: " << segment_count << "\n";

    // ==========================================================================
    // Example 2: Query with result set
    // ==========================================================================

    std::cout << "\n=== Top 5 Largest Functions ===\n";

    auto result = session.query(
        "SELECT printf('0x%08X', address) as addr, name, size "
        "FROM funcs ORDER BY size DESC LIMIT 5"
    );

    if (result.success) {
        // Print column headers
        for (const auto& col : result.columns) {
            std::cout << col << "\t";
        }
        std::cout << "\n" << std::string(50, '-') << "\n";

        // Print rows
        for (const auto& row : result) {
            std::cout << row[0] << "\t" << row[1] << "\t" << row[2] << "\n";
        }
        std::cout << "\n(" << result.row_count() << " rows)\n";
    } else {
        std::cerr << "Query failed: " << result.error << "\n";
    }

    // ==========================================================================
    // Example 3: Segments listing
    // ==========================================================================

    std::cout << "\n=== Segments ===\n";

    auto segments = session.query(
        "SELECT name, printf('0x%X', start_ea) as start, "
        "       printf('0x%X', end_ea) as end, perm "
        "FROM segments"
    );

    for (const auto& row : segments) {
        std::cout << row[0] << ": " << row[1] << " - " << row[2]
                  << " (perm: " << row[3] << ")\n";
    }

    // ==========================================================================
    // Example 4: Using SQL functions
    // ==========================================================================

    std::cout << "\n=== SQL Functions ===\n";

    // Get function at specific index
    auto first_func = session.query(
        "SELECT printf('0x%X', func_at_index(0)) as addr, "
        "       func_at(func_at_index(0)) as name"
    );
    if (!first_func.empty()) {
        std::cout << "First function: " << first_func.rows[0][1]
                  << " at " << first_func.rows[0][0] << "\n";
    }

    // Cleanup (optional - destructor handles it)
    session.close();

    std::cout << "\nDone.\n";
    return 0;
}
