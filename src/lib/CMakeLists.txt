# libidasql - SQL interface to IDA databases

add_library(idasql STATIC
    src/database.cpp
    src/entities.cpp
    src/entities_ext.cpp
    src/entities_dbg.cpp
    src/entities_search.cpp
    src/entities_types.cpp
    src/functions.cpp
    src/decompiler.cpp
    src/disassembly.cpp
    src/search_bytes.cpp
    src/idapython_exec.cpp
    src/metadata.cpp
    src/metadata_welcome.cpp
    src/ui_context_provider.cpp
)

target_include_directories(idasql
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(idasql PUBLIC
    USE_DANGEROUS_FUNCTIONS
    USE_STANDARD_FILE_FUNCTIONS
    USE_IDA_SDK
)

if(WIN32)
    target_compile_options(idasql PRIVATE /bigobj)
    target_compile_definitions(idasql PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()

# Avoid name collision with idasql_plugin's import lib (idasql.lib)
set_target_properties(idasql PROPERTIES OUTPUT_NAME "libidasql")

target_precompile_headers(idasql PRIVATE src/ida_headers.hpp)

target_link_libraries(idasql PUBLIC xsql::xsql idasdk::idalib)

# Export the library target
# install(TARGETS idasql EXPORT idasqlTargets)
# install(DIRECTORY include/idasql DESTINATION include)
