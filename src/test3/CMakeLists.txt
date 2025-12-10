# test3 - IDA Virtual Tables with SQLite
#
# Cross-platform build:
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build --config Release
#
# Run:
#   Windows: set PATH=%IDASDK%\bin;%PATH% && build\Release\test3.exe database.i64
#   Linux:   LD_LIBRARY_PATH=$IDASDK/bin ./build/test3 database.i64
#   macOS:   DYLD_LIBRARY_PATH=$IDASDK/bin ./build/test3 database.i64

cmake_minimum_required(VERSION 3.20)
project(test3 VERSION 1.0 LANGUAGES C CXX)
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

# test3 idalib executable
ida_add_idalib(test3
    TYPE EXECUTABLE
    SOURCES main.cpp
)
target_link_libraries(test3 PRIVATE sqlite3)
target_include_directories(test3 PRIVATE
    ${SQLITE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# Precompiled headers for faster builds
target_precompile_headers(test3 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/pch.hpp
)
target_compile_definitions(test3 PRIVATE USE_IDA_SDK)

# Platform-specific settings
if(MSVC)
    # Windows: Set debugger PATH for Visual Studio
    file(TO_NATIVE_PATH "${IDABIN}" IDABIN_NATIVE)
    set_target_properties(test3 PROPERTIES
        VS_DEBUGGER_ENVIRONMENT "PATH=${IDABIN_NATIVE};%PATH%"
    )
elseif(APPLE)
    # macOS: Set RPATH for dylib loading
    set_target_properties(test3 PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "@executable_path;$ENV{IDASDK}/bin"
    )
elseif(UNIX)
    # Linux: Set RPATH for so loading
    set_target_properties(test3 PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "$ORIGIN;$ENV{IDASDK}/bin"
    )
endif()
