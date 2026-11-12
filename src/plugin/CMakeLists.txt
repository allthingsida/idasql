#
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.

ida_add_plugin(idasql_plugin
    SOURCES
        main.cpp
)

set_target_properties(idasql_plugin PROPERTIES OUTPUT_NAME "idasql")

add_custom_command(TARGET idasql_plugin POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_BINARY_DIR}/ida-plugin.json"
        "$<TARGET_FILE_DIR:idasql_plugin>/ida-plugin.json")

xsql_add_versioninfo(idasql_plugin
    FILETYPE          VFT_DLL
    DESCRIPTION       "idasql plugin for IDA Pro"
    ORIGINAL_FILENAME "idasql.dll")

target_include_directories(idasql_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/include
)
target_link_libraries(idasql_plugin PRIVATE idasql xsql::xsql)

target_compile_definitions(idasql_plugin PRIVATE
    USE_DANGEROUS_FUNCTIONS
    USE_STANDARD_FILE_FUNCTIONS
)

if(WIN32)
    target_compile_options(idasql_plugin PRIVATE /bigobj)
    target_link_libraries(idasql_plugin PRIVATE ws2_32)
    target_compile_definitions(idasql_plugin PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()

target_compile_definitions(idasql_plugin PRIVATE USE_HEXRAYS)

if(IDASQL_WITH_MCP)
    target_sources(idasql_plugin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/mcp_server.cpp
    )
    target_include_directories(idasql_plugin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )

    target_link_libraries(idasql_plugin PRIVATE fastmcpp_core)

    target_compile_definitions(idasql_plugin PRIVATE IDASQL_HAS_MCP)

    message(STATUS "idasql_plugin: MCP support enabled")
endif()

target_sources(idasql_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/http_server.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/binary_query.cpp
)
target_include_directories(idasql_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)
target_compile_definitions(idasql_plugin PRIVATE XSQL_HAS_THINCLIENT)

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
