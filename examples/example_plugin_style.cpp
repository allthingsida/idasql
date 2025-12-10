/**
 * example_plugin_style.cpp - IDASQL usage when IDA is already running
 *
 * Demonstrates the recommended patterns for:
 *   - IDA plugins
 *   - IDAPython scripts (via C++ extension)
 *   - Any code where IDA is already initialized
 *
 * Key insight: IDA is singleton, so you don't "open" a database - it's already open.
 * Just create a QueryEngine or use the free functions.
 *
 * NOTE: This example uses Session to simulate IDA being open for standalone testing.
 *       In a real plugin, you'd skip that and just use QueryEngine/free functions.
 */

#include <iostream>
#include <idasql/database.hpp>

// Simulates what your plugin code would look like
void plugin_main() {
    // =========================================================================
    // OPTION 1: Free functions (simplest - recommended for one-off queries)
    // =========================================================================

    std::cout << "=== Using Free Functions ===\n";

    // Quick one-liner queries
    auto funcs = idasql::query("SELECT name, size FROM funcs ORDER BY size DESC LIMIT 5");
    std::cout << "Largest functions:\n";
    for (const auto& row : funcs) {
        std::cout << "  " << row[0] << " (" << row[1] << " bytes)\n";
    }

    // Scalar for single values
    std::string count = idasql::scalar("SELECT COUNT(*) FROM funcs");
    std::cout << "\nTotal functions: " << count << "\n";

    // Execute without results (for comments_live UPDATE, etc.)
    // idasql::execute("UPDATE comments_live SET comment = 'test' WHERE address = 0x401000");

    // =========================================================================
    // OPTION 2: QueryEngine instance (for multiple related queries)
    // =========================================================================

    std::cout << "\n=== Using QueryEngine Instance ===\n";

    idasql::QueryEngine qe;

    // Multiple queries sharing same engine
    auto imports = qe.query("SELECT module, COUNT(*) as cnt FROM imports GROUP BY module ORDER BY cnt DESC LIMIT 3");
    std::cout << "Top imported modules:\n";
    for (const auto& row : imports) {
        std::cout << "  " << row[0] << ": " << row[1] << " imports\n";
    }

    auto strings = qe.query("SELECT content FROM strings WHERE content LIKE '%error%' LIMIT 3");
    std::cout << "\nStrings containing 'error':\n";
    for (const auto& row : strings) {
        std::cout << "  \"" << row[0] << "\"\n";
    }

    // =========================================================================
    // OPTION 3: Callback-based streaming (for large result sets)
    // =========================================================================

    std::cout << "\n=== Using Callback for Streaming ===\n";

    struct Counter {
        int count = 0;
        int total_size = 0;
    } counter;

    qe.exec(
        "SELECT size FROM funcs",
        [](void* data, int argc, char** argv, char**) -> int {
            auto* c = static_cast<Counter*>(data);
            c->count++;
            if (argv[0]) c->total_size += std::atoi(argv[0]);
            return 0;  // Continue
        },
        &counter
    );

    std::cout << "Processed " << counter.count << " functions\n";
    std::cout << "Total code size: " << counter.total_size << " bytes\n";

    // =========================================================================
    // Advanced: Raw SQLite handle access
    // =========================================================================

    std::cout << "\n=== Raw SQLite Handle ===\n";

    sqlite3* db = qe.handle();
    std::cout << "SQLite handle: " << (db ? "valid" : "null") << "\n";

    // You can use db with any SQLite C API directly
    // sqlite3_prepare_v2, sqlite3_bind, etc. for prepared statements
}

int main(int argc, char* argv[]) {
    // For standalone testing, we need to open IDA first
    // In a real plugin, IDA would already be open - skip this part

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <database.i64>\n\n";
        std::cerr << "NOTE: In a real IDA plugin, you wouldn't need to open anything.\n";
        std::cerr << "      This example uses Session just to simulate IDA being open.\n";
        return 1;
    }

    // Simulate IDA being open (in a plugin, this is already done)
    idasql::Session session;
    if (!session.open(argv[1])) {
        std::cerr << "Error: " << session.error() << "\n";
        return 1;
    }

    std::cout << "Database loaded. Simulating plugin environment...\n\n";

    // This is what your actual plugin code would look like
    plugin_main();

    return 0;
}
