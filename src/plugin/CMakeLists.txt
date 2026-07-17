#
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
#

# idasql Plugin - IDA Pro plugin for SQL queries
# Built as part of the main idasql project

# Plugin sources
ida_add_plugin(idasql_plugin
    SOURCES
        main.cpp
)

# Output as idasql.dll (not idasql_plugin.dll)
set_target_properties(idasql_plugin PROPERTIES OUTPUT_NAME "idasql")

# Co-locate the generated ida-plugin.json (produced by the parent CMakeLists via
# configure_file from idasql_version.hpp) next to the plugin binary so it ships
# with the plugin and CI can package it from the same directory.
add_custom_command(TARGET idasql_plugin POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_BINARY_DIR}/ida-plugin.json"
        "$<TARGET_FILE_DIR:idasql_plugin>/ida-plugin.json")

# Windows VS_VERSION_INFO resource
xsql_add_versioninfo(idasql_plugin
    FILETYPE          VFT_DLL
    DESCRIPTION       "idasql plugin for IDA Pro"
    ORIGINAL_FILENAME "idasql.dll")

# Include directories and link dependencies
target_include_directories(idasql_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/include
)
target_link_libraries(idasql_plugin PRIVATE idasql xsql::xsql)

# USE_DANGEROUS_FUNCTIONS: Disable IDA's safe function macros (pro.h: strcpy, sprintf, getenv, etc.)
# USE_STANDARD_FILE_FUNCTIONS: Disable IDA's file function macros (fpro.h: fgetc, fputc, etc.)
#   Required for std::lib/file APIs used by plugin and shared libraries.
target_compile_definitions(idasql_plugin PRIVATE
    USE_DANGEROUS_FUNCTIONS
    USE_STANDARD_FILE_FUNCTIONS
)

# Windows-specific settings
if(WIN32)
    target_compile_options(idasql_plugin PRIVATE /bigobj)
    target_link_libraries(idasql_plugin PRIVATE ws2_32)
    # WIN32_LEAN_AND_MEAN: Exclude rarely-used Windows headers
    # NOMINMAX: Prevent Windows.h from defining min/max macros
    target_compile_definitions(idasql_plugin PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()

# Hex-Rays support
target_compile_definitions(idasql_plugin PRIVATE USE_HEXRAYS)

# ============================================================================
# MCP support (from parent project)
# ============================================================================

if(IDASQL_WITH_MCP)
    # Add MCP server source files
    target_sources(idasql_plugin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/mcp_server.cpp
    )
    target_include_directories(idasql_plugin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )

    # Link against fastmcpp
    target_link_libraries(idasql_plugin PRIVATE fastmcpp_core)

    # Define the feature flag
    target_compile_definitions(idasql_plugin PRIVATE IDASQL_HAS_MCP)

    message(STATUS "idasql_plugin: MCP support enabled")
endif()

# ============================================================================
# HTTP Server support
# ============================================================================

target_sources(idasql_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/http_server.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/binary_query.cpp
)
target_include_directories(idasql_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)
target_compile_definitions(idasql_plugin PRIVATE XSQL_HAS_THINCLIENT)

# cpp-httplib: provided transitively by xsql::xsql when XSQL_WITH_THINCLIENT=ON.
# Only fetch standalone if the target doesn't already exist.
if(NOT TARGET httplib)
    include(FetchContent)
    FetchContent_Declare(
        cpp_httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG v0.15.3
    )
    FetchContent_MakeAvailable(cpp_httplib)
    target_include_directories(idasql_plugin PRIVATE ${cpp_httplib_SOURCE_DIR})
endif()
