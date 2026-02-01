cmake_minimum_required(VERSION 3.20)
project(idasql VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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

include($ENV{IDASDK}/src/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# ============================================================================
# HTTP Server Support (optional) - must be set BEFORE libxsql
# ============================================================================

option(IDASQL_WITH_HTTP "Build with HTTP REST server support" OFF)

if(IDASQL_WITH_HTTP)
    message(STATUS "idasql: Building with HTTP server support")
    set(XSQL_WITH_THINCLIENT ON CACHE BOOL "" FORCE)
endif()

# ============================================================================
# libxsql dependency
# ============================================================================

if(TARGET xsql::xsql)
    # Monorepo: already available from parent
    message(STATUS "idasql: Using xsql::xsql from parent project")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../libxsql/CMakeLists.txt")
    # Monorepo: sibling directory (private test infrastructure)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
    message(STATUS "idasql: Added libxsql from sibling directory")
else()
    # Standalone: FetchContent from GitHub
    message(STATUS "idasql: Fetching libxsql from GitHub...")
    FetchContent_Declare(libxsql
        GIT_REPOSITORY https://github.com/0xeb/libxsql.git
        GIT_TAG        main
    )
    FetchContent_MakeAvailable(libxsql)
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include)

# Option to build idalib-based tests (requires IDASDK)
option(BUILD_IDALIB "Build idalib-based tests (test3)" OFF)

# Unit tests (no IDA dependency)
option(IDASQL_BUILD_TESTS "Build IDASQL unit tests" ON)
if(IDASQL_BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    add_subdirectory(tests)
endif()

# ============================================================================
# AI Agent Support (libagents - optional)
# ============================================================================

option(IDASQL_WITH_AI_AGENT "Build with AI agent support (libagents)" ON)

if(IDASQL_WITH_AI_AGENT)
    message(STATUS "idasql: Building with AI agent support via libagents")

    # libagents build options
    set(LIBAGENTS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(LIBAGENTS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(LIBAGENTS_BUILD_CLI OFF CACHE BOOL "" FORCE)
    set(LIBAGENTS_BUILD_COPILOT OFF CACHE BOOL "" FORCE)

    # FetchContent from GitHub (with recursive submodules for fastmcpp, SDKs)
    message(STATUS "idasql: Fetching libagents from GitHub...")
    FetchContent_Declare(libagents
        GIT_REPOSITORY https://github.com/0xeb/libagents.git
        GIT_TAG        main
        GIT_SUBMODULES_RECURSE TRUE
    )
    FetchContent_MakeAvailable(libagents)

    # Generate prompt header if needed (conditional on source file age)
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_FOUND)
        set(PROMPT_MD "${CMAKE_CURRENT_SOURCE_DIR}/prompts/idasql_agent.md")
        set(PROMPT_HPP "${CMAKE_CURRENT_SOURCE_DIR}/src/common/idasql_agent_prompt.hpp")

        add_custom_command(
            OUTPUT ${PROMPT_HPP}
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/scripts/embed_prompt.py
                ${PROMPT_MD} ${PROMPT_HPP}
            DEPENDS ${PROMPT_MD}
            COMMENT "Checking/regenerating idasql_agent_prompt.hpp"
        )
        add_custom_target(generate_prompt DEPENDS ${PROMPT_HPP})
    endif()
endif()

# Add subdirectories
add_subdirectory(src)
