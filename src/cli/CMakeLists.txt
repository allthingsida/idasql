# idasql CLI - Command-line SQL interface to IDA databases
#
# Build:
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build --config Release
#
# Run:
#   Windows: set PATH=%IDASDK%\bin;%PATH% && build\Release\idasql.exe -s database.i64 -i
#   Linux:   LD_LIBRARY_PATH=$IDASDK/bin ./build/idasql -s database.i64 -i
#   macOS:   DYLD_LIBRARY_PATH=$IDASDK/bin ./build/idasql -s database.i64 -i

cmake_minimum_required(VERSION 3.20)
project(idasql_cli VERSION 1.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include IDA SDK bootstrap
include($ENV{IDASDK}/src/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# ============================================================================
# xsql dependency (provides SQLite)
# ============================================================================

if(TARGET xsql::xsql)
    message(STATUS "idasql_cli: Using xsql::xsql from parent project")
else()
    # Standalone build - try find_package first, then fallback to sibling directory
    find_package(xsql QUIET)
    if(xsql_FOUND)
        message(STATUS "idasql_cli: Using xsql::xsql via find_package")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../libxsql/CMakeLists.txt")
        # Monorepo: sibling of idasql
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
        message(STATUS "idasql_cli: Added libxsql from monorepo sibling")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../external/libxsql/CMakeLists.txt")
        # Standalone: submodule in external/
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../external/libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
        message(STATUS "idasql_cli: Added libxsql from external/libxsql submodule")
    else()
        message(FATAL_ERROR "libxsql not found. Either:
"
            "  1. Build as part of xsql monorepo
"
            "  2. Set xsql_DIR to the libxsql build directory
"
            "  3. Install libxsql and ensure it's in CMAKE_PREFIX_PATH
"
            "  4. Initialize submodule: git submodule update --init external/libxsql")
    endif()
endif()

# idasql CLI executable
ida_add_idalib(idasql_cli
    TYPE EXECUTABLE
    SOURCES main.cpp
)
target_link_libraries(idasql_cli PRIVATE xsql::xsql)
target_include_directories(idasql_cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../lib/include)
target_compile_definitions(idasql_cli PRIVATE USE_IDA_SDK)

# Output name: idasql (not idasql_cli)
set_target_properties(idasql_cli PROPERTIES OUTPUT_NAME "idasql")

# Platform-specific settings
if(MSVC)
    # Windows: Set debugger PATH for Visual Studio
    file(TO_NATIVE_PATH "${IDABIN}" IDABIN_NATIVE)
    set_target_properties(idasql_cli PROPERTIES
        VS_DEBUGGER_ENVIRONMENT "PATH=${IDABIN_NATIVE};%PATH%"
    )
    # Windows: Link winsock for remote mode
    target_link_libraries(idasql_cli PRIVATE ws2_32)
    # Note: Delayed loading not possible for ida.dll due to data symbol imports (callui)
elseif(APPLE)
    # macOS: Set RPATH for dylib loading
    set_target_properties(idasql_cli PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "@executable_path;$ENV{IDASDK}/bin"
    )
elseif(UNIX)
    # Linux: Set RPATH for so loading
    set_target_properties(idasql_cli PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "$ORIGIN;$ENV{IDASDK}/bin"
    )
endif()

# Optional: Enable Hex-Rays decompiler support
option(USE_HEXRAYS "Enable Hex-Rays decompiler support" ON)
if(USE_HEXRAYS)
    target_compile_definitions(idasql_cli PRIVATE USE_HEXRAYS)
endif()

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
    target_sources(idasql_cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/claude_agent.cpp
    )
    target_include_directories(idasql_cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )

    # Link against claude_sdk
    target_link_libraries(idasql_cli PRIVATE claude_sdk)

    # Define the feature flag
    target_compile_definitions(idasql_cli PRIVATE IDASQL_HAS_CLAUDE_AGENT)

    # Add dependency on prompt generation
    if(TARGET generate_prompt)
        add_dependencies(idasql_cli generate_prompt)
    endif()

    message(STATUS "idasql_cli: Claude agent support enabled")
endif()
