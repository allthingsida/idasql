/**
 * test3 - SQLite Virtual Tables backed by IDA entities
 *
 * Refactored to use the clean ida_vtable.hpp framework.
 *
 * Virtual Tables (via ida_entities.hpp):
 *   funcs      - All functions
 *   segments   - Memory segments
 *   names      - Named locations
 *   entries    - Entry points
 *   imports    - Imported functions
 *   strings    - String literals
 *   xrefs      - Cross-references
 *   blocks     - Basic blocks
 *
 * Metadata Tables (via ida_metadata.hpp):
 *   db_info    - Database information
 *   ida_info   - IDA analysis settings
 *
 * Decompiler Tables (via ida_decompiler.hpp) - Requires Hex-Rays:
 *   pseudocode - Decompiled function pseudocode
 *   lvars      - Local variables from decompiled functions
 *
 * Build:
 *   cd src/test3
 *   cmake -B build -DCMAKE_BUILD_TYPE=Release
 *   cmake --build build --config Release
 *
 * Run:
 *   set PATH=%IDASDK%\bin;%PATH%
 *   build\Release\test3.exe database.i64
 */

#include <iostream>
#include <string>
#include <iomanip>

// SQLite
#include <sqlite3.h>

// IDA SDK
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <auto.hpp>
#include <idalib.hpp>

// IDASQL Framework
#include "ida_vtable.hpp"
#include "ida_vtable_v2.hpp"
#include "ida_entities.hpp"
#include "ida_entities_live.hpp"
#include "ida_metadata.hpp"
#include "ida_entities_extended.hpp"
#include "ida_sql_functions.hpp"
#include "ida_decompiler.hpp"

// ============================================================================
// Query Execution Helper
// ============================================================================

static int print_callback(void*, int argc, char** argv, char** colNames) {
    for (int i = 0; i < argc; i++) {
        std::cout << colNames[i] << " = " << (argv[i] ? argv[i] : "NULL");
        if (i < argc - 1) std::cout << " | ";
    }
    std::cout << std::endl;
    return 0;
}

static void run_query(sqlite3* db, const char* description, const char* sql) {
    std::cout << "\n--- " << description << " ---" << std::endl;
    std::cout << "SQL: " << sql << std::endl;
    std::cout << std::endl;

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db, sql, print_callback, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << err_msg << std::endl;
        sqlite3_free(err_msg);
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <idb_file>" << std::endl;
        std::cerr << "Example: " << argv[0] << " database.i64" << std::endl;
        return 1;
    }

    const char* idb_path = argv[1];

    // Initialize IDA library
    std::cout << "Initializing IDA library..." << std::endl;
    int ok = init_library();
    if (ok != 0) {
        std::cerr << "Failed to initialize IDA library: " << ok << std::endl;
        return 1;
    }

    // Open the database
    std::cout << "Opening: " << idb_path << std::endl;
    ok = open_database(idb_path, true, nullptr);
    if (ok != 0) {
        std::cerr << "Failed to open database: " << ok << std::endl;
        return 1;
    }

    // Wait for auto-analysis
    auto_wait();

    std::cout << "\n=== IDA Database Info ===" << std::endl;
    std::cout << "Processor: " << inf_get_procname().c_str() << std::endl;
    std::cout << "Functions: " << get_func_qty() << std::endl;
    std::cout << "Segments: " << get_segm_qty() << std::endl;
    std::cout << "Names: " << get_nlist_size() << std::endl;

    // Initialize SQLite
    sqlite3* db = nullptr;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Cannot open SQLite database: " << sqlite3_errmsg(db) << std::endl;
        close_database(false);
        return 1;
    }

    std::cout << "\n=== Registering Virtual Tables ===" << std::endl;

    // Register all entity tables using the clean framework
    idasql::entities::TableRegistry entities;
    entities.register_all(db);
    std::cout << "Entity tables: funcs, segments, names, entries, imports, strings, strings_ascii, strings_unicode, xrefs, blocks" << std::endl;

    // Register live entity tables (with instructions)
    idasql::live::LiveRegistry live_entities;
    live_entities.register_all(db);
    std::cout << "Live tables: names_live, comments_live, funcs_live, bookmarks, heads, instructions" << std::endl;

    // Register metadata tables
    idasql::metadata::MetadataRegistry metadata;
    metadata.register_all(db);
    std::cout << "Metadata tables: db_info, ida_info" << std::endl;

    // Register extended tables
    idasql::extended::ExtendedRegistry extended;
    extended.register_all(db);
    std::cout << "Extended tables: fixups, hidden_ranges, problems, fchunks, signatures, local_types, comments, mappings" << std::endl;

    // Register SQL functions
    idasql::functions::register_sql_functions(db);
    std::cout << "SQL functions: disasm, bytes, itype, decode_insn, etc." << std::endl;

    // Register decompiler tables (requires Hex-Rays license)
    idasql::decompiler::DecompilerRegistry decompiler;
    decompiler.register_all(db);
    std::cout << "Decompiler tables: pseudocode, lvars" << std::endl;

    // Run example queries
    std::cout << "\n========================================" << std::endl;
    std::cout << "          EXAMPLE QUERIES" << std::endl;
    std::cout << "========================================" << std::endl;

    // Metadata queries
    run_query(db, "Database Metadata",
        "SELECT key, value FROM db_info WHERE type = 'hex' OR key LIKE '%ea%' LIMIT 10");

    // Segment listing
    run_query(db, "All Segments",
        "SELECT printf('0x%08X', start_ea) as start, "
        "       printf('0x%08X', end_ea) as end, "
        "       name, class, perm FROM segments");

    // Top functions by size
    run_query(db, "Top 10 Largest Functions",
        "SELECT printf('0x%08X', address) as addr, name, size "
        "FROM funcs ORDER BY size DESC LIMIT 10");

    // Function size distribution
    run_query(db, "Functions by Size Category",
        "SELECT CASE "
        "  WHEN size < 16 THEN 'tiny (<16)' "
        "  WHEN size < 64 THEN 'small (16-64)' "
        "  WHEN size < 256 THEN 'medium (64-256)' "
        "  WHEN size < 1024 THEN 'large (256-1K)' "
        "  ELSE 'huge (>1K)' "
        "END as size_category, COUNT(*) as count "
        "FROM funcs GROUP BY size_category ORDER BY count DESC");

    // Most called functions
    run_query(db, "Top 10 Most Called Functions",
        "SELECT printf('0x%08X', f.address) as addr, f.name, COUNT(*) as caller_count "
        "FROM funcs f "
        "JOIN xrefs x ON f.address = x.to_ea "
        "WHERE x.is_code = 1 "
        "GROUP BY f.address "
        "ORDER BY caller_count DESC LIMIT 10");

    // Least called functions
    run_query(db, "Bottom 10 Least Called Functions",
        "SELECT printf('0x%08X', f.address) as addr, f.name, COUNT(x.from_ea) as caller_count "
        "FROM funcs f "
        "LEFT JOIN xrefs x ON f.address = x.to_ea AND x.is_code = 1 "
        "GROUP BY f.address "
        "ORDER BY caller_count ASC LIMIT 10");

    // Basic blocks per function
    run_query(db, "Functions with Most Basic Blocks (Top 10)",
        "SELECT printf('0x%08X', b.func_ea) as func, "
        "       (SELECT name FROM funcs WHERE address = b.func_ea) as name, "
        "       COUNT(*) as block_count, "
        "       SUM(b.size) as total_size "
        "FROM blocks b GROUP BY b.func_ea ORDER BY block_count DESC LIMIT 10");

    // Entry points
    run_query(db, "Entry Points",
        "SELECT ordinal, printf('0x%08X', address) as addr, name FROM entries LIMIT 10");

    // Imports by module
    run_query(db, "Imports by Module",
        "SELECT module, COUNT(*) as import_count FROM imports GROUP BY module ORDER BY import_count DESC");

    // Strings containing keywords
    run_query(db, "Strings Containing 'error' or 'fail'",
        "SELECT printf('0x%08X', address) as addr, length, content "
        "FROM strings "
        "WHERE content LIKE '%error%' OR content LIKE '%fail%' "
        "LIMIT 10");

    // Complex analysis: function with size, blocks, callers
    run_query(db, "Complex Function Analysis",
        "SELECT "
        "  printf('0x%08X', f.address) as addr, "
        "  f.name, "
        "  f.size, "
        "  COALESCE((SELECT COUNT(*) FROM blocks b WHERE b.func_ea = f.address), 0) as blocks, "
        "  COALESCE((SELECT COUNT(*) FROM xrefs x WHERE x.to_ea = f.address AND x.is_code = 1), 0) as callers "
        "FROM funcs f "
        "ORDER BY f.size DESC "
        "LIMIT 15");

    // Pagination demo
    run_query(db, "Functions Page 2 (items 11-20)",
        "SELECT printf('0x%08X', address) as addr, name, size "
        "FROM funcs ORDER BY address LIMIT 10 OFFSET 10");

    // Instruction analysis queries
    std::cout << "\n========================================" << std::endl;
    std::cout << "       INSTRUCTION ANALYSIS" << std::endl;
    std::cout << "========================================" << std::endl;

    // Largest function
    run_query(db, "Largest Function",
        "SELECT printf('0x%08X', address) as addr, name, size "
        "FROM funcs ORDER BY size DESC LIMIT 1");

    // Unique mnemonics in largest function
    run_query(db, "Unique Mnemonics in Largest Function",
        "SELECT mnemonic, COUNT(*) as count "
        "FROM instructions "
        "WHERE func_addr = (SELECT address FROM funcs ORDER BY size DESC LIMIT 1) "
        "GROUP BY mnemonic "
        "ORDER BY count DESC");

    // Instruction type distribution
    run_query(db, "Instruction Type Distribution (Top 20)",
        "SELECT itype, mnemonic, COUNT(*) as count "
        "FROM instructions "
        "GROUP BY itype, mnemonic "
        "ORDER BY count DESC LIMIT 20");

    // Call targets
    run_query(db, "Most Common Call Targets (Top 10)",
        "SELECT operand0, COUNT(*) as count "
        "FROM instructions "
        "WHERE mnemonic = 'call' "
        "GROUP BY operand0 "
        "ORDER BY count DESC LIMIT 10");

    // Functions with most NOPs
    run_query(db, "Functions with Most NOP Instructions",
        "SELECT printf('0x%08X', func_addr) as address, "
        "       func_at(func_addr) as name, "
        "       COUNT(*) as nop_count "
        "FROM instructions "
        "WHERE mnemonic = 'nop' "
        "GROUP BY func_addr "
        "ORDER BY nop_count DESC LIMIT 10");

    // Functions making most calls (outgoing)
    run_query(db, "Functions Making Most Calls (Outgoing)",
        "SELECT printf('0x%08X', func_addr) as address, "
        "       func_at(func_addr) as name, "
        "       COUNT(*) as call_count "
        "FROM instructions "
        "WHERE itype IN (16, 18) "  // NN_call variants
        "GROUP BY func_addr "
        "ORDER BY call_count DESC LIMIT 10");

    // Extended table queries
    std::cout << "\n========================================" << std::endl;
    std::cout << "        EXTENDED TABLE QUERIES" << std::endl;
    std::cout << "========================================" << std::endl;

    // Fixups
    run_query(db, "Fixup Records (first 10)",
        "SELECT printf('0x%08X', address) as addr, printf('0x%08X', target) as target, type, flags "
        "FROM fixups LIMIT 10");

    // Analysis problems
    run_query(db, "Analysis Problems Summary",
        "SELECT type, COUNT(*) as count FROM problems GROUP BY type ORDER BY count DESC");

    // Function chunks
    run_query(db, "Function Chunks (Tail Chunks)",
        "SELECT printf('0x%08X', start_ea) as start, printf('0x%08X', owner) as owner, size, is_tail "
        "FROM fchunks WHERE is_tail = 1 LIMIT 10");

    // Applied signatures
    run_query(db, "Applied FLIRT Signatures",
        "SELECT name, state FROM signatures");

    // Local types
    run_query(db, "Local Types (Structs)",
        "SELECT ordinal, name FROM local_types WHERE is_struct = 1 LIMIT 10");

    // Comments
    run_query(db, "Addresses with Comments (first 10)",
        "SELECT printf('0x%08X', address) as addr, "
        "       SUBSTR(comment, 1, 50) as comment_preview "
        "FROM comments WHERE has_regular = 1 LIMIT 10");

    // Decompiler queries (requires Hex-Rays)
    std::cout << "\n========================================" << std::endl;
    std::cout << "      DECOMPILER QUERIES (Hex-Rays)" << std::endl;
    std::cout << "========================================" << std::endl;

    // Get pseudocode for largest function
    run_query(db, "Pseudocode for Largest Function (first 20 lines)",
        "SELECT printf('0x%08X', func_addr) as func, line_num, line "
        "FROM pseudocode "
        "WHERE func_addr = (SELECT address FROM funcs ORDER BY size DESC LIMIT 1) "
        "LIMIT 20");

    // Get local variables for main function
    run_query(db, "Local Variables in _main",
        "SELECT printf('0x%08X', func_addr) as func, name, type, size, "
        "       CASE WHEN is_arg = 1 THEN 'arg' ELSE 'local' END as kind "
        "FROM lvars "
        "WHERE func_addr = (SELECT address FROM funcs WHERE name LIKE '%main%' LIMIT 1)");

    // Count lines of pseudocode per function
    run_query(db, "Functions by Pseudocode Line Count (Top 10)",
        "SELECT printf('0x%08X', p.func_addr) as func, "
        "       func_at(p.func_addr) as name, "
        "       COUNT(*) as line_count "
        "FROM pseudocode p "
        "GROUP BY p.func_addr "
        "ORDER BY line_count DESC LIMIT 10");

    // Functions with most local variables
    run_query(db, "Functions with Most Local Variables (Top 10)",
        "SELECT printf('0x%08X', func_addr) as func, "
        "       func_at(func_addr) as name, "
        "       COUNT(*) as var_count, "
        "       SUM(CASE WHEN is_arg = 1 THEN 1 ELSE 0 END) as args "
        "FROM lvars "
        "GROUP BY func_addr "
        "ORDER BY var_count DESC LIMIT 10");

    // Cleanup
    sqlite3_close(db);
    close_database(false);

    std::cout << "\n=== test3 completed successfully ===" << std::endl;
    return 0;
}
