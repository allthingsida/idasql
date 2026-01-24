cmake_minimum_required(VERSION 3.27)
project(idasql_plugin)
set(CMAKE_CXX_STANDARD 20)

# IDA SDK
include($ENV{IDASDK}/src/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# Find libxsql
if(NOT TARGET xsql::xsql)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../libxsql/CMakeLists.txt")
        # Monorepo: sibling of idasql
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../libxsql libxsql)
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../external/libxsql/CMakeLists.txt")
        # Standalone: submodule in external/
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../external/libxsql libxsql)
    else()
        message(FATAL_ERROR "libxsql not found. Initialize submodule: git submodule update --init external/libxsql")
    endif()
endif()

# Plugin sources
ida_add_plugin(idasql_plugin
    SOURCES main.cpp
)

# Include directories and link dependencies
target_include_directories(idasql_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/include
)
target_link_libraries(idasql_plugin PRIVATE xsql::xsql)

# Windows socket library
if(WIN32)
    target_link_libraries(idasql_plugin PRIVATE ws2_32)
endif()

# Hex-Rays support
target_compile_definitions(idasql_plugin PRIVATE USE_HEXRAYS)

# ============================================================================
# AI Agent support (libagents - optional)
# ============================================================================

if(IDASQL_WITH_AI_AGENT)
    # If libagents target doesn't exist, add the submodule
    if(NOT TARGET libagents)
        set(LIBAGENTS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(LIBAGENTS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(LIBAGENTS_BUILD_CLI OFF CACHE BOOL "" FORCE)
        set(LIBAGENTS_BUILD_COPILOT OFF CACHE BOOL "" FORCE)
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../external/libagents
                         ${CMAKE_CURRENT_BINARY_DIR}/libagents)
    endif()

    # Add ai_agent source files
    target_sources(idasql_plugin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/ai_agent.cpp
    )
    target_include_directories(idasql_plugin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )

    # Link against libagents
    target_link_libraries(idasql_plugin PRIVATE libagents)

    # Define the feature flag
    target_compile_definitions(idasql_plugin PRIVATE IDASQL_HAS_AI_AGENT)

    # Add dependency on prompt generation
    if(TARGET generate_prompt)
        add_dependencies(idasql_plugin generate_prompt)
    endif()

    message(STATUS "idasql_plugin: AI agent support enabled via libagents")
endif()
