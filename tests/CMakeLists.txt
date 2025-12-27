# tests/CMakeLists.txt - GTest infrastructure for IDASQL
#
# Build: cmake -B build && cmake --build build --config Release
# Run:   ctest --test-dir build -C Release --output-on-failure

cmake_minimum_required(VERSION 3.27)
project(idasql_tests VERSION 1.0)
set(CMAKE_CXX_STANDARD 17)

# For Windows: Use static CRT (/MT) to match IDA SDK's runtime library
# Must be set before fetching GoogleTest
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING "" FORCE)
endif()

# Fetch GoogleTest BEFORE IDA SDK bootstrap to avoid include path conflicts
# (IDA SDK has a regex.h that shadows the system one)
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
set(gtest_force_shared_crt OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Include IDA SDK bootstrap
include($ENV{IDASDK}/src/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

enable_testing()

# ============================================================================
# xsql dependency (provides SQLite)
# ============================================================================

if(TARGET xsql::xsql)
    # Part of monorepo - already available
    message(STATUS "idasql_tests: Using xsql::xsql from parent project")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../libxsql/CMakeLists.txt")
    # Standalone build with libxsql submodule
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
    message(STATUS "idasql_tests: Added libxsql from ../libxsql (submodule)")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../libxsql/CMakeLists.txt")
    # Monorepo layout
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
    message(STATUS "idasql_tests: Added libxsql from ../../libxsql (monorepo)")
else()
    message(FATAL_ERROR "libxsql not found. Either:\n"
        "  1. Build as part of xsql monorepo\n"
        "  2. Ensure libxsql submodule is initialized (git submodule update --init)")
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
        types_table_test.cpp
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

# Build a CLI binary as part of the tests so CLI tests don't rely on an in-tree
# `idasql/src/cli/build` directory existing. This avoids including the separate
# CLI CMake project (which would re-bootstrap ida-cmake and collide targets).
ida_add_idalib(idasql_cli_test
    TYPE EXECUTABLE
    SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/cli/main.cpp
)
target_link_libraries(idasql_cli_test PRIVATE xsql::xsql)
target_include_directories(idasql_cli_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/lib/include
)
target_compile_definitions(idasql_cli_test PRIVATE USE_IDA_SDK USE_HEXRAYS)
set_target_properties(idasql_cli_test PROPERTIES OUTPUT_NAME "idasql")

if(WIN32)
    target_link_libraries(idasql_cli_test PRIVATE ws2_32)
endif()

add_dependencies(idasql_tests idasql_cli_test)

# Define paths for tests
target_compile_definitions(idasql_tests PRIVATE
    IDASQL_TEST_DB_PATH="${CMAKE_CURRENT_SOURCE_DIR}/testdb.i64"
    IDASQL_CLI_EXE="$<TARGET_FILE:idasql_cli_test>"
)

# Register with CTest
# Test executable uses IDASQL_TEST_DB_PATH as default when no database is specified
# NOTE: Use gtest_add_tests() to avoid running the executable during build-time
# discovery (idalib-based tests require IDA DLLs on PATH).
include(GoogleTest)

gtest_add_tests(TARGET idasql_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    TEST_LIST IDASQL_GTESTS
)

# Set test properties including IDADIR and PATH for idalib
if(DEFINED ENV{IDASDK})
    set(IDASDK_BIN "$ENV{IDASDK}/bin")
    set_tests_properties(${IDASQL_GTESTS} PROPERTIES
        TIMEOUT 20
        ENVIRONMENT "IDADIR=${IDASDK_BIN}"
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${IDASDK_BIN}"
    )
else()
    set_tests_properties(${IDASQL_GTESTS} PROPERTIES TIMEOUT 20)
endif()

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
