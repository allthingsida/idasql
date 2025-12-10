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
    # Part of monorepo - already available
    message(STATUS "idasql: Using xsql::xsql from parent project")
else()
    # Standalone build - add libxsql as subdirectory
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../libxsql/CMakeLists.txt")
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
        message(STATUS "idasql: Added libxsql from sibling directory")
    else()
        message(FATAL_ERROR "libxsql not found. Build as part of xsql monorepo or ensure ../libxsql exists.")
    endif()
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/lib/include)

# Option to build idalib-based tests (requires IDASDK)
option(BUILD_IDALIB "Build idalib-based tests (test3)" OFF)

# Add subdirectories
add_subdirectory(src)
