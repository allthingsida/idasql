cmake_minimum_required(VERSION 3.20)
project(idasql VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Output directories (only set if building standalone)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
endif()

# ============================================================================
# libxsql dependency
# ============================================================================

if(TARGET xsql::xsql)
    # Part of monorepo - already available via add_subdirectory
    message(STATUS "idasql: Using xsql::xsql from parent project")
else()
    # Standalone build - try find_package first, then fallback to sibling directory
    find_package(xsql QUIET)
    if(xsql_FOUND)
        message(STATUS "idasql: Using xsql::xsql via find_package")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../libxsql/CMakeLists.txt")
        # Monorepo: sibling directory
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
        message(STATUS "idasql: Added libxsql from sibling directory")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/libxsql/CMakeLists.txt")
        # Standalone: submodule in external/
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
        message(STATUS "idasql: Added libxsql from external/libxsql submodule")
    else()
        message(FATAL_ERROR "libxsql not found. Either:\n"
            "  1. Build as part of xsql monorepo\n"
            "  2. Set xsql_DIR to the libxsql build directory\n"
            "  3. Install libxsql and ensure it's in CMAKE_PREFIX_PATH\n"
            "  4. Initialize submodule: git submodule update --init external/libxsql")
    endif()
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include)

# Option to build idalib-based tests (requires IDASDK)
option(BUILD_IDALIB "Build idalib-based tests (test3)" OFF)

# ============================================================================
# Claude Agent SDK (optional)
# ============================================================================

option(IDASQL_WITH_CLAUDE_AGENT "Build with Claude AI agent support" OFF)

if(IDASQL_WITH_CLAUDE_AGENT)
    message(STATUS "idasql: Building with Claude agent support")

    # Add claude-agent-sdk-cpp as subdirectory
    set(CLAUDE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(CLAUDE_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    add_subdirectory(external/claude-agent-sdk-cpp)

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
