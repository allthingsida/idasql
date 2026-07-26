#
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
#

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

# Refuse to proceed if package resolution escaped the standalone ida-cmake
# fetched above (IDA SDK 9.4 also carries a bundled CMake implementation).
file(REAL_PATH "${ida_cmake_SOURCE_DIR}" _idasql_fetched_idacmake_dir)
file(REAL_PATH "${IDA_CMAKE_DIR}" _idasql_active_idacmake_dir)
if(NOT _idasql_active_idacmake_dir STREQUAL _idasql_fetched_idacmake_dir)
    message(FATAL_ERROR
        "idasql: expected standalone ida-cmake at "
        "${_idasql_fetched_idacmake_dir}, but idasdk resolved "
        "${_idasql_active_idacmake_dir}")
endif()
message(STATUS "idasql: using standalone ida-cmake from ${_idasql_active_idacmake_dir}")

if(TARGET ida_compiler_settings)
    target_compile_options(ida_compiler_settings INTERFACE
        "$<$<COMPILE_LANG_AND_ID:CXX,GNU>:-Wno-class-memaccess>"
        "$<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:-Wno-format>"
        "$<$<COMPILE_LANG_AND_ID:CXX,Clang,AppleClang>:-Wno-dynamic-class-memaccess>"
    )
endif()

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
        GIT_TAG        d5a210dad0333dc8dbdbfbbb295968cfe1a0950c
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
            GIT_TAG        9a3ee7125b1db9dc85a71f60661beb40ea1e7993
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
string(REGEX MATCH "IDASQL_VERSION_REVISION[ \t]+([0-9]+)" _ "${_idasql_version_contents}")
set(TOOL_VERSION_REVISION "${CMAKE_MATCH_1}")
if(TOOL_VERSION_MAJOR STREQUAL ""
        OR TOOL_VERSION_MINOR STREQUAL ""
        OR TOOL_VERSION_PATCH STREQUAL ""
        OR TOOL_VERSION_REVISION STREQUAL "")
    message(FATAL_ERROR "idasql: failed to parse version from ${_idasql_version_hpp}")
endif()
message(STATUS
    "idasql: version "
    "${TOOL_VERSION_MAJOR}.${TOOL_VERSION_MINOR}.${TOOL_VERSION_PATCH}.${TOOL_VERSION_REVISION}")
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/versioninfo.cmake)

# Release CI sets this to one exact ABI version (9.2, 9.3, or 9.4). Keep the
# historical range for ordinary local builds that do not opt into packaging.
set(IDASQL_TARGET_IDA_VERSION ">=9.0" CACHE STRING
    "IDA version or range advertised by the generated plugin manifest")
if(IDASQL_TARGET_IDA_VERSION STREQUAL "")
    message(FATAL_ERROR "idasql: IDASQL_TARGET_IDA_VERSION must not be empty")
endif()
message(STATUS "idasql: manifest target IDA version ${IDASQL_TARGET_IDA_VERSION}")

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
