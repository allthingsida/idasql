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
        GIT_TAG        v1.0.10
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

option(IDASQL_WITH_MCP "Build with MCP server support (fastmcpp)" ON)

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

    # fastmcpp_core is a static library that gets linked into the idasql plugin
    # (a shared library on Linux). Enable PIC so the link succeeds.
    if(TARGET fastmcpp_core)
        set_property(TARGET fastmcpp_core PROPERTY POSITION_INDEPENDENT_CODE ON)
    endif()
endif()

# ============================================================================
# Windows VERSIONINFO resource (parses idasql_version.hpp as source of truth)
# ============================================================================

set(_idasql_version_hpp "${CMAKE_CURRENT_SOURCE_DIR}/src/common/idasql_version.hpp")
file(READ "${_idasql_version_hpp}" _idasql_version_contents)
string(REGEX MATCH "IDASQL_VERSION_MAJOR[ \t]+([0-9]+)" _ "${_idasql_version_contents}")
set(TOOL_VERSION_MAJOR "${CMAKE_MATCH_1}")
string(REGEX MATCH "IDASQL_VERSION_MINOR[ \t]+([0-9]+)" _ "${_idasql_version_contents}")
set(TOOL_VERSION_MINOR "${CMAKE_MATCH_1}")
string(REGEX MATCH "IDASQL_VERSION_PATCH[ \t]+([0-9]+)" _ "${_idasql_version_contents}")
set(TOOL_VERSION_PATCH "${CMAKE_MATCH_1}")
if(TOOL_VERSION_MAJOR STREQUAL "" OR TOOL_VERSION_MINOR STREQUAL "" OR TOOL_VERSION_PATCH STREQUAL "")
    message(FATAL_ERROR "idasql: failed to parse version from ${_idasql_version_hpp}")
endif()
message(STATUS "idasql: version ${TOOL_VERSION_MAJOR}.${TOOL_VERSION_MINOR}.${TOOL_VERSION_PATCH}")
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/versioninfo.cmake)

# Generate ida-plugin.json from the version header so the IDA-native plugin
# manifest can never drift from idasql_version.hpp. The generated file is the
# packaged manifest (see src/plugin POST_BUILD copy + CI artifact upload).
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/ida-plugin.json.in"
    "${CMAKE_BINARY_DIR}/ida-plugin.json"
    @ONLY)

# Add subdirectories
add_subdirectory(src)

# Examples (optional)
option(IDASQL_BUILD_EXAMPLES "Build IDASQL example programs" ON)
if(IDASQL_BUILD_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples")
    add_subdirectory(examples)
endif()
