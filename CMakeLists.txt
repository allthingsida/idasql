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
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)                  # Allow FetchContent_Populate() for ida-cmake bootstrap
endif()

include(FetchContent)

# Default dependency revisions: the reviewed lock, the same one release CI builds,
# so a source checkout builds what was tested. Pass -DIDASQL_<DEP>_GIT_TAG=main to
# track upstream instead.
set(_idasql_lock "${CMAKE_CURRENT_SOURCE_DIR}/.github/release-revisions.json")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_idasql_lock}")
file(READ "${_idasql_lock}" _idasql_lock_json)
string(JSON _idasql_lock_ida_cmake GET "${_idasql_lock_json}" dependencies ida_cmake sha)
string(JSON _idasql_lock_libxsql   GET "${_idasql_lock_json}" dependencies libxsql sha)
string(JSON _idasql_lock_fastmcpp  GET "${_idasql_lock_json}" dependencies fastmcpp sha)

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
set(IDASQL_IDA_CMAKE_GIT_TAG "${_idasql_lock_ida_cmake}" CACHE STRING
    "ida-cmake revision (default: the reviewed lock)")
set(_idasql_ida_cmake_shallow TRUE)
if(IDASQL_IDA_CMAKE_GIT_TAG MATCHES "^[0-9a-fA-F]{40}$")
    set(_idasql_ida_cmake_shallow FALSE)
endif()
FetchContent_Declare(ida_cmake
    GIT_REPOSITORY https://github.com/allthingsida/ida-cmake.git
    GIT_TAG        "${IDASQL_IDA_CMAKE_GIT_TAG}"
    GIT_SHALLOW    "${_idasql_ida_cmake_shallow}"
)
FetchContent_Populate(ida_cmake)

# Bootstrap from fetched ida-cmake (not from ida-sdk's bundled copy)
include(${ida_cmake_SOURCE_DIR}/bootstrap.cmake)
find_package(idasdk REQUIRED)

# IDA SDK 9.4 also contains a bundled CMake implementation. Refuse to proceed
# if package resolution escaped the standalone ida-cmake fetched above.
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
    # Standalone: the reviewed lock unless overridden.
    message(STATUS "idasql: Fetching libxsql from GitHub...")
    set(IDASQL_LIBXSQL_GIT_TAG "${_idasql_lock_libxsql}" CACHE STRING
        "libxsql revision (default: the reviewed lock)")
    set(_idasql_libxsql_shallow TRUE)
    if(IDASQL_LIBXSQL_GIT_TAG MATCHES "^[0-9a-fA-F]{40}$")
        set(_idasql_libxsql_shallow FALSE)
    endif()
    FetchContent_Declare(libxsql
        GIT_REPOSITORY https://github.com/0xeb/libxsql.git
        GIT_TAG        "${IDASQL_LIBXSQL_GIT_TAG}"
        GIT_SHALLOW    "${_idasql_libxsql_shallow}"
    )
    FetchContent_MakeAvailable(libxsql)
endif()

# The libxsql API idasql is written against (QueryParam, vtab_write_count,
# counts_as_write): an older revision fails here instead of mid-compile.
set(IDASQL_MIN_LIBXSQL_VERSION 1.0.24)
get_target_property(_idasql_xsql_real xsql::xsql ALIASED_TARGET)
if(NOT _idasql_xsql_real)
    set(_idasql_xsql_real xsql::xsql)
endif()
get_target_property(_idasql_xsql_defs ${_idasql_xsql_real} INTERFACE_COMPILE_DEFINITIONS)
string(REGEX MATCH "XSQL_VERSION_STRING=\"?([0-9]+\\.[0-9]+\\.[0-9]+)" _idasql_xsql_match
       "${_idasql_xsql_defs}")
if(NOT CMAKE_MATCH_1)
    message(FATAL_ERROR "idasql: cannot read libxsql's XSQL_VERSION_STRING")
endif()
if(CMAKE_MATCH_1 VERSION_LESS IDASQL_MIN_LIBXSQL_VERSION)
    message(FATAL_ERROR
        "idasql needs libxsql >= ${IDASQL_MIN_LIBXSQL_VERSION}, got ${CMAKE_MATCH_1}")
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
        set(FASTMCPP_BUILD_CLI OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_ENABLE_POST_STREAMING OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_ENABLE_SAMPLING_HTTP_HANDLERS OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_FETCH_CURL OFF CACHE BOOL "" FORCE)
        # idasql serves MCP; it never uses fastmcpp's client transports.
        set(FASTMCPP_ENABLE_WINHTTP OFF CACHE BOOL "" FORCE)

        message(STATUS "idasql: Fetching fastmcpp from GitHub...")
        set(IDASQL_FASTMCPP_GIT_TAG "${_idasql_lock_fastmcpp}" CACHE STRING
            "fastmcpp revision (default: the reviewed lock)")
        set(_idasql_fastmcpp_shallow TRUE)
        if(IDASQL_FASTMCPP_GIT_TAG MATCHES "^[0-9a-fA-F]{40}$")
            set(_idasql_fastmcpp_shallow FALSE)
        endif()
        FetchContent_Declare(fastmcpp
            GIT_REPOSITORY https://github.com/0xeb/fastmcpp.git
            GIT_TAG        "${IDASQL_FASTMCPP_GIT_TAG}"
            GIT_SHALLOW    "${_idasql_fastmcpp_shallow}"
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
string(REGEX MATCH "IDASQL_VERSION_STRING[ \t]+\"([0-9]+\\.[0-9]+\\.[0-9]+)\"" _ "${_idasql_version_contents}")
set(TOOL_VERSION_STRING "${CMAKE_MATCH_1}")
if(TOOL_VERSION_MAJOR STREQUAL ""
        OR TOOL_VERSION_MINOR STREQUAL ""
        OR TOOL_VERSION_PATCH STREQUAL ""
        OR TOOL_VERSION_REVISION STREQUAL ""
        OR TOOL_VERSION_STRING STREQUAL "")
    message(FATAL_ERROR "idasql: failed to parse version from ${_idasql_version_hpp}")
endif()
set(_idasql_component_version
    "${TOOL_VERSION_MAJOR}.${TOOL_VERSION_MINOR}.${TOOL_VERSION_PATCH}")
if(NOT TOOL_VERSION_STRING STREQUAL _idasql_component_version)
    message(FATAL_ERROR
        "idasql: IDASQL_VERSION_STRING (${TOOL_VERSION_STRING}) does not match "
        "the numeric components (${_idasql_component_version})")
endif()
message(STATUS
    "idasql: version ${TOOL_VERSION_STRING} "
    "(Windows revision ${TOOL_VERSION_REVISION})")
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/versioninfo.cmake)

# Release builds set one exact ABI version (9.2, 9.3, or 9.4). Ordinary local
# builds keep the historical range unless packaging opts into an exact value.
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
