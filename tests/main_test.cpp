/**
 * main_test.cpp - Test driver for IDASQL
 *
 * Usage:
 *   idasql_tests.exe <database.i64> [--gtest_filter=PATTERN]
 *   idasql_tests.exe --config=test_config.json
 */

// Standard headers FIRST (before IDA SDK via test_fixtures.hpp)
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include <gtest/gtest.h>
#include "test_fixtures.hpp"

// Simple JSON parser for config (minimal, no dependencies)
namespace {

std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string extract_json_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";

    pos = json.find('"', pos);
    if (pos == std::string::npos) return "";

    size_t start = pos + 1;
    size_t end = json.find('"', start);
    if (end == std::string::npos) return "";

    return json.substr(start, end - start);
}

void print_usage(const char* prog) {
    std::cout << "IDASQL Test Driver\n\n";
    std::cout << "Usage:\n";
    std::cout << "  " << prog << " <database.i64> [gtest options]\n";
    std::cout << "  " << prog << " --config=<config.json> [gtest options]\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << prog << " sample.i64\n";
    std::cout << "  " << prog << " sample.i64 --gtest_filter=FuncsTable*\n";
    std::cout << "  " << prog << " --config=test_config.json\n";
    std::cout << "\nTest Suites:\n";
    std::cout << "  VTableFramework*  - Virtual table framework tests\n";
    std::cout << "  FuncsTable*       - Functions table tests\n";
    std::cout << "  SegmentsTable*    - Segments table tests\n";
    std::cout << "  NamesTable*       - Names table tests\n";
    std::cout << "  XrefsTable*       - Cross-references tests\n";
    std::cout << "  ComplexQueries*   - Complex SQL query tests\n";
}

} // namespace

int main(int argc, char** argv) {
    // Initialize GTest
    ::testing::InitGoogleTest(&argc, argv);

    // Parse our arguments (before gtest consumes them)
    std::string db_path;
    std::string config_path;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg.find("--config=") == 0) {
            config_path = arg.substr(9);
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg[0] != '-' && db_path.empty()) {
            db_path = arg;
        }
    }

    // Load config if specified
    if (!config_path.empty()) {
        std::string json = read_file(config_path);
        if (json.empty()) {
            std::cerr << "Error: Cannot read config file: " << config_path << std::endl;
            return 1;
        }

        // Extract default database from config
        std::string default_db = extract_json_string(json, "default");
        if (!default_db.empty() && db_path.empty()) {
            // Try relative to config file
            size_t last_slash = config_path.find_last_of("/\\");
            if (last_slash != std::string::npos) {
                db_path = config_path.substr(0, last_slash + 1) + "../" + default_db;
            } else {
                db_path = "../" + default_db;
            }
        }
    }

    // Use default database path if not specified
    if (db_path.empty()) {
#ifdef IDASQL_TEST_DB_PATH
        db_path = IDASQL_TEST_DB_PATH;
#else
        // Fallback: try testdb.i64 in current directory
        db_path = "testdb.i64";
#endif
    }

    // Check database exists
    std::ifstream db_file(db_path);
    if (!db_file.good()) {
        std::cerr << "Error: Database not found: " << db_path << std::endl;
        return 1;
    }
    db_file.close();

    std::cout << "=== IDASQL Test Driver ===" << std::endl;
    std::cout << "Database: " << db_path << std::endl;
    std::cout << std::endl;

    // Set database path for fixtures
    idasql::testing::set_test_database_path(db_path);

    // Run tests
    return RUN_ALL_TESTS();
}
