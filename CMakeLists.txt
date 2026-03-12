cmake_minimum_required(VERSION 3.20)
project(idasql LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Silence CMake policy warnings from dependencies
cmake_policy(SET CMP0135 NEW)                     # Use extraction time for DOWNLOAD_EXTRACT_TIMESTAMP
set(CMAKE_POLICY_DEFAULT_CMP0169 OLD CACHE STRING "" FORCE) # Allow FetchContent_Populate() in dependencies

include(FetchContent)

# Output directories (only set if building standalone)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
endif()

# ============================================================================
# IDA SDK (required for CLI and plugin)
# ============================================================================

# Fetch ida-cmake directly — decoupled from ida-sdk's submodule pin.
FetchContent_Declare(ida_cmake
    GIT_REPOSITORY https://github.com/allthingsida/ida-cmake.git
    GIT_TAG        main
    GIT_SHALLOW    TRUE
)
FetchContent_Populate(ida_cmake)

# Bootstrap from fetched ida-cmake (not from ida-sdk's bundled copy)
include(${ida_cmake_SOURCE_DIR}/bootstrap.cmake)
find_package(idasdk REQUIRED)

# Make imported IDA SDK targets globally visible so sibling directories
# (e.g. additional test or example targets) can link against them.
foreach(_idasdk_imported_target idasdk::plugin idasdk::loader idasdk::procmod idasdk::idalib)
    if(TARGET ${_idasdk_imported_target})
        set_property(TARGET ${_idasdk_imported_target} PROPERTY IMPORTED_GLOBAL TRUE)
    endif()
endforeach()

# ============================================================================
# HTTP Server Support - must be set BEFORE libxsql
# ============================================================================

set(XSQL_WITH_THINCLIENT ON CACHE BOOL "" FORCE)

# idasql uses only plain HTTP (localhost); prevent cpp-httplib from opportunistically linking OpenSSL
set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)

# ============================================================================
# libxsql dependency
# ============================================================================

if(TARGET xsql::xsql)
    # Parent project: already available from parent
    message(STATUS "idasql: Using xsql::xsql from parent project")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../libxsql/CMakeLists.txt")
    # Parent project: sibling directory
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
    message(STATUS "idasql: Added libxsql from sibling directory")
else()
    # Standalone: FetchContent from GitHub
    message(STATUS "idasql: Fetching libxsql from GitHub...")
    FetchContent_Declare(libxsql
        GIT_REPOSITORY https://github.com/0xeb/libxsql.git
        GIT_TAG        main
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(libxsql)
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include)

# ============================================================================
# MCP Support (optional)
# ============================================================================

option(IDASQL_WITH_MCP "Build with MCP server support (fastmcpp)" OFF)

if(IDASQL_WITH_MCP)
    message(STATUS "idasql: Building with MCP support via fastmcpp")

    # Reuse an existing fastmcpp target when available in a parent build.
    if(NOT TARGET fastmcpp_core)
        # Keep the dependency surface minimal for idasql.
        set(FASTMCPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_ENABLE_POST_STREAMING OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_ENABLE_SAMPLING_HTTP_HANDLERS OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_FETCH_CURL OFF CACHE BOOL "" FORCE)

        message(STATUS "idasql: Fetching fastmcpp from GitHub...")
        FetchContent_Declare(fastmcpp
            GIT_REPOSITORY https://github.com/0xeb/fastmcpp.git
            GIT_TAG        4837e8e0a27d0011b73643fe02b3553cd3935c34
        )
        FetchContent_MakeAvailable(fastmcpp)
    endif()

    if(MSVC AND TARGET fastmcpp_core)
        target_compile_options(fastmcpp_core PRIVATE /MP)
    endif()
endif()

# Add subdirectories
add_subdirectory(src)

# Examples (optional)
option(IDASQL_BUILD_EXAMPLES "Build IDASQL example programs" ON)
if(IDASQL_BUILD_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples")
    add_subdirectory(examples)
endif()
