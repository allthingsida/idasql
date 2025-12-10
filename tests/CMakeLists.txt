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

# SQLite library
set(SQLITE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../src/3rd_party/sqlite)
add_library(sqlite3_test STATIC ${SQLITE_DIR}/sqlite3.c)
target_include_directories(sqlite3_test PUBLIC ${SQLITE_DIR})
target_compile_definitions(sqlite3_test PRIVATE
    SQLITE_ENABLE_FTS5
    SQLITE_ENABLE_RTREE
    SQLITE_ENABLE_JSON1
    SQLITE_ENABLE_COLUMN_METADATA
)

# Test utility library
add_library(test_utils STATIC
    test_utils.cpp
)
target_include_directories(test_utils PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/lib/include
    ${SQLITE_DIR}
)
target_link_libraries(test_utils PUBLIC sqlite3_test)

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
)
target_link_libraries(idasql_tests PRIVATE
    GTest::gtest
    sqlite3_test
    test_utils
)
target_include_directories(idasql_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/lib/include
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
