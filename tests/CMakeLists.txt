cmake_minimum_required(VERSION 3.20)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
# For Windows: prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(idasql_unit_tests
    session_handler_test.cpp
)

target_include_directories(idasql_unit_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

target_link_libraries(idasql_unit_tests
    GTest::gtest
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(idasql_unit_tests)
