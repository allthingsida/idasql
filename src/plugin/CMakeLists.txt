cmake_minimum_required(VERSION 3.27)
project(idasql_plugin)
set(CMAKE_CXX_STANDARD 20)

# IDA SDK
include($ENV{IDASDK}/src/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# Find libxsql (sibling directory)
if(NOT TARGET xsql::xsql)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../libxsql libxsql)
endif()

# Plugin sources
ida_add_plugin(idasql_plugin
    SOURCES main.cpp
)

# Include directories and link dependencies
target_include_directories(idasql_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../libxsql/include
)
target_link_libraries(idasql_plugin PRIVATE xsql::xsql)

# Windows socket library
if(WIN32)
    target_link_libraries(idasql_plugin PRIVATE ws2_32)
endif()

# Hex-Rays support
target_compile_definitions(idasql_plugin PRIVATE USE_HEXRAYS)

# ============================================================================
# Claude Agent support (optional)
# ============================================================================

if(IDASQL_WITH_CLAUDE_AGENT)
    # If claude_sdk target doesn't exist, add the submodule
    if(NOT TARGET claude_sdk)
        set(CLAUDE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(CLAUDE_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../external/claude-agent-sdk-cpp
                         ${CMAKE_CURRENT_BINARY_DIR}/claude-agent-sdk-cpp)
    endif()

    # Add claude_agent source files
    target_sources(idasql_plugin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/claude_agent.cpp
    )
    target_include_directories(idasql_plugin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )

    # Link against claude_sdk
    target_link_libraries(idasql_plugin PRIVATE claude_sdk)

    # Define the feature flag
    target_compile_definitions(idasql_plugin PRIVATE IDASQL_HAS_CLAUDE_AGENT)

    # Add dependency on prompt generation
    if(TARGET generate_prompt)
        add_dependencies(idasql_plugin generate_prompt)
    endif()

    message(STATUS "idasql_plugin: Claude agent support enabled")
endif()
