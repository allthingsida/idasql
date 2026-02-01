# idasql Plugin - IDA Pro plugin for SQL queries
# Built as part of the main idasql project

# Plugin sources
ida_add_plugin(idasql_plugin
    SOURCES main.cpp
)

# Output as idasql.dll (not idasql_plugin.dll)
set_target_properties(idasql_plugin PROPERTIES OUTPUT_NAME "idasql")

# Include directories and link dependencies
target_include_directories(idasql_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/include
)
target_link_libraries(idasql_plugin PRIVATE xsql::xsql)

# USE_DANGEROUS_FUNCTIONS: Disable IDA's safe function macros (pro.h: strcpy, sprintf, getenv, etc.)
# USE_STANDARD_FILE_FUNCTIONS: Disable IDA's file function macros (fpro.h: fgetc, fputc, etc.)
#   Required for std::getenv and file I/O in agent_settings.hpp
target_compile_definitions(idasql_plugin PRIVATE
    USE_DANGEROUS_FUNCTIONS
    USE_STANDARD_FILE_FUNCTIONS
)

# Windows-specific settings
if(WIN32)
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
# AI Agent support (from parent project)
# ============================================================================

if(IDASQL_WITH_AI_AGENT)
    # Add ai_agent and mcp_server source files
    target_sources(idasql_plugin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/ai_agent.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/mcp_server.cpp
    )
    target_include_directories(idasql_plugin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
        ${CMAKE_CURRENT_SOURCE_DIR}/../../external/libagents/external/fastmcpp/include
    )

    # Link against libagents and fastmcpp
    target_link_libraries(idasql_plugin PRIVATE libagents fastmcpp_core)

    # Define the feature flag
    target_compile_definitions(idasql_plugin PRIVATE IDASQL_HAS_AI_AGENT)

    # Add dependency on prompt generation
    if(TARGET generate_prompt)
        add_dependencies(idasql_plugin generate_prompt)
    endif()

    message(STATUS "idasql_plugin: AI agent support enabled")
endif()
