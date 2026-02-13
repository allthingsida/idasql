cmake_minimum_required(VERSION 3.20)
project(idasql VERSION 1.0.0 LANGUAGES C CXX)

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

include($ENV{IDASDK}/src/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# ============================================================================
# HTTP Server Support (optional) - must be set BEFORE libxsql
# ============================================================================

option(IDASQL_WITH_HTTP "Build with HTTP REST server support" ON)

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
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(libxsql)
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include)

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
    set(LIBAGENTS_BUILD_COPILOT ON CACHE BOOL "" FORCE)

    # FetchContent from GitHub (with recursive submodules for fastmcpp, SDKs)
    message(STATUS "idasql: Fetching libagents from GitHub...")
    FetchContent_Declare(libagents
        GIT_REPOSITORY https://github.com/0xeb/libagents.git
        GIT_TAG        ae162192d49126da6328254aab73417d673379cc
        GIT_SHALLOW    TRUE
        GIT_SUBMODULES_RECURSE TRUE
    )
    FetchContent_MakeAvailable(libagents)

    # ========================================================================
    # Build speed: enable MSVC parallel compilation for dependency targets.
    # IDA SDK's /MP only applies to ida_add_plugin/ida_add_idalib targets;
    # FetchContent dependencies compile their files sequentially without this.
    # ========================================================================
    if(MSVC)
        foreach(_dep_target fastmcpp_core copilot_sdk_cpp claude_sdk libagents)
            if(TARGET ${_dep_target})
                target_compile_options(${_dep_target} PRIVATE /MP)
            endif()
        endforeach()
    endif()

    # Build speed: merge translation units to reduce header re-parsing.
    # Note: fastmcpp_core is excluded — its server files use duplicate
    # anonymous-namespace symbols that conflict under unity builds.
    foreach(_dep_target copilot_sdk_cpp claude_sdk libagents)
        if(TARGET ${_dep_target})
            set_target_properties(${_dep_target} PROPERTIES UNITY_BUILD ON)
        endif()
    endforeach()

    # Exclude unused targets from default build (e.g. claude-sdk debug tool)
    foreach(_unused_target debug)
        if(TARGET ${_unused_target})
            set_target_properties(${_unused_target} PROPERTIES EXCLUDE_FROM_ALL TRUE)
        endif()
    endforeach()

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

# Examples (optional)
option(IDASQL_BUILD_EXAMPLES "Build IDASQL example programs" ON)
if(IDASQL_BUILD_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples")
    add_subdirectory(examples)
endif()
