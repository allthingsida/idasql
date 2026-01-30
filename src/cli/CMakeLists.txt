# idasql CLI - Command-line SQL interface to IDA databases
# Built as part of the main idasql project

# idasql CLI executable
ida_add_idalib(idasql_cli
    TYPE EXECUTABLE
    SOURCES
        main.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/sqlite_utils.cpp
)
target_link_libraries(idasql_cli PRIVATE xsql::xsql)
target_include_directories(idasql_cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../lib/include)
target_compile_definitions(idasql_cli PRIVATE USE_IDA_SDK)

# Output name: idasql (not idasql_cli)
set_target_properties(idasql_cli PROPERTIES OUTPUT_NAME "idasql")

# Platform-specific settings
if(MSVC)
    file(TO_NATIVE_PATH "${IDABIN}" IDABIN_NATIVE)
    set_target_properties(idasql_cli PROPERTIES
        VS_DEBUGGER_ENVIRONMENT "PATH=${IDABIN_NATIVE};%PATH%"
    )
    target_link_libraries(idasql_cli PRIVATE ws2_32)
elseif(APPLE)
    set_target_properties(idasql_cli PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "@executable_path;$ENV{IDASDK}/bin"
    )
elseif(UNIX)
    set_target_properties(idasql_cli PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "$ORIGIN;$ENV{IDASDK}/bin"
    )
endif()

# Hex-Rays decompiler support
option(USE_HEXRAYS "Enable Hex-Rays decompiler support" ON)
if(USE_HEXRAYS)
    target_compile_definitions(idasql_cli PRIVATE USE_HEXRAYS)
endif()

# AI Agent support (from parent project)
if(IDASQL_WITH_AI_AGENT)
    target_sources(idasql_cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/ai_agent.cpp
    )
    target_include_directories(idasql_cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )
    target_link_libraries(idasql_cli PRIVATE libagents)
    target_compile_definitions(idasql_cli PRIVATE IDASQL_HAS_AI_AGENT)

    if(TARGET generate_prompt)
        add_dependencies(idasql_cli generate_prompt)
    endif()

    message(STATUS "idasql_cli: AI agent support enabled")
endif()

# HTTP server support
if(IDASQL_WITH_HTTP)
    target_compile_definitions(idasql_cli PRIVATE IDASQL_HAS_HTTP XSQL_HAS_THINCLIENT)

    # Fetch cpp-httplib if not already available
    include(FetchContent)
    FetchContent_Declare(
        cpp_httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG v0.15.3
    )
    FetchContent_MakeAvailable(cpp_httplib)
    target_include_directories(idasql_cli PRIVATE ${cpp_httplib_SOURCE_DIR})

    message(STATUS "idasql_cli: HTTP server support enabled")
endif()
