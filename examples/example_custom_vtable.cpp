/**
 * example_custom_vtable.cpp - Creating custom virtual tables
 *
 * This example shows how to expose your own data as SQL tables.
 * We'll create a simple "user_functions" table that mirrors the built-in
 * funcs table, demonstrating the pattern you'd use for any custom data.
 *
 * Key concepts:
 *   1. Use VTableBuilder fluent API to define columns
 *   2. Register the module, then create the table instance
 *   3. Query with standard SQL
 */

#include <iostream>
#include <iomanip>

#include <idasql/database.hpp>
#include <idasql/vtable.hpp>

// IDA SDK
#include <funcs.hpp>
#include <name.hpp>

// =============================================================================
// Step 1: Define your table using the fluent API
// =============================================================================

idasql::VTableDef make_user_functions_table() {
    return idasql::table("user_functions")
        // How many rows?
        .count([]() -> size_t {
            return get_func_qty();
        })
        // Column definitions - each takes a lambda (row_index) -> value
        .column_int64("address", [](size_t i) -> int64_t {
            func_t* f = getn_func(i);
            return f ? f->start_ea : BADADDR;
        })
        .column_text("name", [](size_t i) -> std::string {
            func_t* f = getn_func(i);
            if (!f) return "";
            qstring name;
            get_func_name(&name, f->start_ea);
            return std::string(name.c_str());
        })
        .column_int64("size", [](size_t i) -> int64_t {
            func_t* f = getn_func(i);
            return f ? f->size() : 0;
        })
        .column_int("flags", [](size_t i) -> int {
            func_t* f = getn_func(i);
            return f ? f->flags : 0;
        })
        .build();
}

// =============================================================================
// Main
// =============================================================================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <database.i64>\n";
        return 1;
    }

    // Open the IDA database
    idasql::Session session;
    if (!session.open(argv[1])) {
        std::cerr << "Error: " << session.error() << "\n";
        return 1;
    }

    // Get SQLite handle for registration
    sqlite3* db = session.handle();

    // =========================================================================
    // Step 2: Register your custom table
    // =========================================================================

    // Create the table definition (must outlive the registration)
    static auto user_funcs_def = make_user_functions_table();

    // Register the vtable module with SQLite
    idasql::register_vtable(db, "user_functions_module", &user_funcs_def);

    // Create the actual table instance
    idasql::create_vtable(db, "user_functions", "user_functions_module");

    std::cout << "Registered custom table: user_functions\n\n";

    // =========================================================================
    // Step 3: Query your custom table with SQL
    // =========================================================================

    std::cout << "=== Query: user_functions (Top 10 by size) ===\n\n";

    auto result = session.query(
        "SELECT printf('0x%X', address) as addr, name, size, flags "
        "FROM user_functions "
        "ORDER BY size DESC "
        "LIMIT 10"
    );

    // Print results
    std::cout << std::left
              << std::setw(14) << "Address"
              << std::setw(35) << "Name"
              << std::setw(10) << "Size"
              << "Flags\n";
    std::cout << std::string(65, '-') << "\n";

    for (const auto& row : result) {
        std::cout << std::setw(14) << row[0]
                  << std::setw(35) << row[1].substr(0, 33)
                  << std::setw(10) << row[2]
                  << row[3] << "\n";
    }

    // =========================================================================
    // Bonus: Join custom table with built-in tables
    // =========================================================================

    std::cout << "\n=== Join: user_functions + xrefs (most called) ===\n\n";

    auto most_called = session.query(
        "SELECT uf.name, COUNT(x.from_ea) as call_count "
        "FROM user_functions uf "
        "JOIN xrefs x ON uf.address = x.to_ea "
        "WHERE x.type = 17 "  // Code call xref
        "GROUP BY uf.address "
        "ORDER BY call_count DESC "
        "LIMIT 10"
    );

    for (const auto& row : most_called) {
        std::cout << std::setw(40) << row[0]
                  << " called " << row[1] << " times\n";
    }

    std::cout << "\nDone.\n";
    return 0;
}
