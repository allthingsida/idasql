# examples/CMakeLists.txt - IDASQL Example Programs
#
# Build:
#   cmake -B build
#   cmake --build build --config Release
#
# Run:
#   Windows: set PATH=%IDASDK%\src\bin;%PATH%
#            build\Release\example_basic.exe database.i64
#   Linux:   LD_LIBRARY_PATH=$IDASDK/src/bin ./build/example_basic database.i64

cmake_minimum_required(VERSION 3.20)
project(idasql_examples VERSION 1.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include IDA SDK bootstrap
include($ENV{IDASDK}/src/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# ============================================================================
# xsql dependency (provides SQLite)
# ============================================================================

set(LIBXSQL_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../libxsql)

if(TARGET xsql::xsql)
    message(STATUS "idasql_examples: Using xsql::xsql from parent project")
elseif(EXISTS "${LIBXSQL_ROOT}/CMakeLists.txt")
    add_subdirectory(${LIBXSQL_ROOT} ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
    message(STATUS "idasql_examples: Added libxsql from ${LIBXSQL_ROOT}")
else()
    message(FATAL_ERROR "libxsql not found at ${LIBXSQL_ROOT}")
endif()

# libidasql interface library (headers only)
add_library(idasql_lib INTERFACE)
target_include_directories(idasql_lib INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/lib/include
)

# Helper function to create examples
function(add_idasql_example name)
    ida_add_idalib(${name}
        TYPE EXECUTABLE
        SOURCES ${name}.cpp
    )
    target_link_libraries(${name} PRIVATE idasql_lib xsql::xsql)
    target_compile_definitions(${name} PRIVATE USE_IDA_SDK USE_HEXRAYS)

    # Platform-specific settings
    if(MSVC)
        file(TO_NATIVE_PATH "${IDABIN}" IDABIN_NATIVE)
        set_target_properties(${name} PROPERTIES
            VS_DEBUGGER_ENVIRONMENT "PATH=${IDABIN_NATIVE};%PATH%"
        )
    elseif(APPLE)
        set_target_properties(${name} PROPERTIES
            BUILD_WITH_INSTALL_RPATH TRUE
            INSTALL_RPATH "@executable_path;$ENV{IDASDK}/src/bin"
        )
    elseif(UNIX)
        set_target_properties(${name} PROPERTIES
            BUILD_WITH_INSTALL_RPATH TRUE
            INSTALL_RPATH "$ORIGIN;$ENV{IDASDK}/src/bin"
        )
    endif()
endfunction()

# Example executables
add_idasql_example(example_basic)
add_idasql_example(example_functions)
add_idasql_example(example_strings)
add_idasql_example(example_instructions)
add_idasql_example(example_decompiler)
add_idasql_example(example_custom_vtable)
add_idasql_example(example_plugin_style)
add_idasql_example(example_jump_search)
add_idasql_example(example_jump_entities)
