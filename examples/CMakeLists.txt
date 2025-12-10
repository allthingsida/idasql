# examples/CMakeLists.txt - IDASQL Example Programs
#
# Build:
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build --config Release
#
# Run:
#   set PATH=%IDASDK%\bin;%PATH%
#   build\Release\example_basic.exe database.i64

cmake_minimum_required(VERSION 3.20)
project(idasql_examples VERSION 1.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include IDA SDK bootstrap
include($ENV{IDASDK}/ida-cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# SQLite library
set(SQLITE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../src/3rd_party/sqlite)
add_library(sqlite3_examples STATIC ${SQLITE_DIR}/sqlite3.c)
target_include_directories(sqlite3_examples PUBLIC ${SQLITE_DIR})
target_compile_definitions(sqlite3_examples PRIVATE
    SQLITE_ENABLE_FTS5
    SQLITE_ENABLE_RTREE
    SQLITE_ENABLE_JSON1
    SQLITE_ENABLE_COLUMN_METADATA
    SQLITE_THREADSAFE=1
)
if(UNIX AND NOT APPLE)
    target_compile_definitions(sqlite3_examples PRIVATE SQLITE_HAVE_ISNAN)
    target_link_libraries(sqlite3_examples PRIVATE pthread dl)
elseif(APPLE)
    target_compile_definitions(sqlite3_examples PRIVATE SQLITE_HAVE_ISNAN)
endif()

# libidasql interface library
add_library(idasql_lib INTERFACE)
target_include_directories(idasql_lib INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/lib/include
    ${SQLITE_DIR}
)

# Helper function to create examples
function(add_idasql_example name)
    ida_add_idalib(${name}
        TYPE EXECUTABLE
        SOURCES ${name}.cpp
    )
    target_link_libraries(${name} PRIVATE idasql_lib sqlite3_examples)
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
            INSTALL_RPATH "@executable_path;$ENV{IDASDK}/bin"
        )
    elseif(UNIX)
        set_target_properties(${name} PROPERTIES
            BUILD_WITH_INSTALL_RPATH TRUE
            INSTALL_RPATH "$ORIGIN;$ENV{IDASDK}/bin"
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
