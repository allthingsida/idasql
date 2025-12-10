# idasql CLI - Command-line SQL interface to IDA databases
#
# Build:
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build --config Release
#
# Run:
#   Windows: set PATH=%IDASDK%\bin;%PATH% && build\Release\idasql.exe -s database.i64 -i
#   Linux:   LD_LIBRARY_PATH=$IDASDK/bin ./build/idasql -s database.i64 -i
#   macOS:   DYLD_LIBRARY_PATH=$IDASDK/bin ./build/idasql -s database.i64 -i

cmake_minimum_required(VERSION 3.20)
project(idasql_cli VERSION 1.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include IDA SDK bootstrap
include($ENV{IDASDK}/ida-cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# SQLite library (compile from source)
set(SQLITE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../3rd_party/sqlite)
add_library(sqlite3 STATIC ${SQLITE_DIR}/sqlite3.c)
target_include_directories(sqlite3 PUBLIC ${SQLITE_DIR})
target_compile_definitions(sqlite3 PRIVATE
    SQLITE_ENABLE_FTS5
    SQLITE_ENABLE_RTREE
    SQLITE_ENABLE_JSON1
    SQLITE_ENABLE_COLUMN_METADATA
    SQLITE_THREADSAFE=1
)

# Platform-specific SQLite settings
if(UNIX AND NOT APPLE)
    target_compile_definitions(sqlite3 PRIVATE SQLITE_HAVE_ISNAN)
    target_link_libraries(sqlite3 PRIVATE pthread dl)
elseif(APPLE)
    target_compile_definitions(sqlite3 PRIVATE SQLITE_HAVE_ISNAN)
endif()

# libidasql (header-only interface library)
add_library(idasql INTERFACE)
target_include_directories(idasql INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/include
    ${SQLITE_DIR}
)

# idasql CLI executable
ida_add_idalib(idasql_cli
    TYPE EXECUTABLE
    SOURCES main.cpp
)
target_link_libraries(idasql_cli PRIVATE idasql sqlite3)
target_compile_definitions(idasql_cli PRIVATE USE_IDA_SDK)

# Output name: idasql (not idasql_cli)
set_target_properties(idasql_cli PROPERTIES OUTPUT_NAME "idasql")

# Platform-specific settings
if(MSVC)
    # Windows: Set debugger PATH for Visual Studio
    file(TO_NATIVE_PATH "${IDABIN}" IDABIN_NATIVE)
    set_target_properties(idasql_cli PROPERTIES
        VS_DEBUGGER_ENVIRONMENT "PATH=${IDABIN_NATIVE};%PATH%"
    )
elseif(APPLE)
    # macOS: Set RPATH for dylib loading
    set_target_properties(idasql_cli PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "@executable_path;$ENV{IDASDK}/bin"
    )
elseif(UNIX)
    # Linux: Set RPATH for so loading
    set_target_properties(idasql_cli PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "$ORIGIN;$ENV{IDASDK}/bin"
    )
endif()

# Optional: Enable Hex-Rays decompiler support
option(USE_HEXRAYS "Enable Hex-Rays decompiler support" ON)
if(USE_HEXRAYS)
    target_compile_definitions(idasql_cli PRIVATE USE_HEXRAYS)
endif()
