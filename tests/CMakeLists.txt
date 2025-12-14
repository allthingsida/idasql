# tests/CMakeLists.txt - GTest infrastructure for IDASQL
#
# Build: cmake -B build && cmake --build build --config Release
# Run:   ctest --test-dir build -C Release --output-on-failure

cmake_minimum_required(VERSION 3.27)
project(idasql_tests VERSION 1.0)
set(CMAKE_CXX_STANDARD 17)

# Include IDA SDK bootstrap
include($ENV{IDASDK}/ida-cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# Fetch GoogleTest
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

# ============================================================================
# xsql dependency (provides SQLite)
# ============================================================================

if(TARGET xsql::xsql)
    # Part of monorepo - already available
    message(STATUS "idasql_tests: Using xsql::xsql from parent project")
else()
    # Standalone build - add libxsql as subdirectory
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../libxsql/CMakeLists.txt")
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
        message(STATUS "idasql_tests: Added libxsql from ../../libxsql")
    else()
        message(FATAL_ERROR "libxsql not found. Build as part of xsql monorepo or ensure ../../libxsql exists.")
    endif()
endif()

# Test utility library
add_library(test_utils STATIC
    test_utils.cpp
)
target_include_directories(test_utils PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/lib/include
)
target_link_libraries(test_utils PUBLIC xsql::xsql)

# Main test executable (idalib-based)
ida_add_idalib(idasql_tests
    TYPE EXECUTABLE
    SOURCES
        main_test.cpp
        vtable_framework_test.cpp
        funcs_table_test.cpp
        segments_table_test.cpp
        names_table_test.cpp
        xrefs_table_test.cpp
        complex_queries_test.cpp
        cli_test.cpp
        ctree_table_test.cpp
        disasm_table_test.cpp
)
target_link_libraries(idasql_tests PRIVATE
    GTest::gtest
    xsql::xsql
    test_utils
)
target_include_directories(idasql_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/lib/include
)

# Define paths for tests
target_compile_definitions(idasql_tests PRIVATE
    IDASQL_TEST_DB_PATH="${CMAKE_CURRENT_SOURCE_DIR}/testdb.i64"
    IDASQL_CLI_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../src/cli/build"
    IDASQL_CLI_CONFIG="$<CONFIG>"
)

# Register with CTest
include(GoogleTest)
gtest_discover_tests(idasql_tests)

# Copy SQL test files to build directory
file(GLOB SQL_FILES ${CMAKE_CURRENT_SOURCE_DIR}/sql/*.sql)
foreach(SQL_FILE ${SQL_FILES})
    get_filename_component(SQL_NAME ${SQL_FILE} NAME)
    configure_file(${SQL_FILE} ${CMAKE_BINARY_DIR}/sql/${SQL_NAME} COPYONLY)
endforeach()

# Windows: Set debugger PATH
if(MSVC)
    file(TO_NATIVE_PATH "${IDABIN}" IDABIN_NATIVE)
    set_target_properties(idasql_tests PROPERTIES
        VS_DEBUGGER_ENVIRONMENT "PATH=${IDABIN_NATIVE};%PATH%"
    )
endif()
