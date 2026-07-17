#
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
#

# libidasql - SQL interface to IDA databases

add_library(idasql STATIC
    src/database.cpp
    src/session.cpp
    src/address_resolution.cpp
    src/dirtree_utils.cpp
    src/autostart_pin.cpp
    src/core_common.cpp
    src/core_registry.cpp
    src/code_funcs.cpp
    src/code_blocks.cpp
    src/code_operand_repr.cpp
    src/code_instructions.cpp
    src/code_calls.cpp
    src/code_loops.cpp
    src/code_graph.cpp
    src/code_cfg.cpp
    src/symbols_names.cpp
    src/symbols_comments.cpp
    src/symbols_bookmarks.cpp
    src/symbols_imports.cpp
    src/memory_segments.cpp
    src/memory_heads.cpp
    src/memory_bytes.cpp
    src/memory_strings.cpp
    src/memory_netnode_kv.cpp
    src/xrefs.cpp
    src/entities_ext.cpp
    src/entities_dbg.cpp
    src/entities_search.cpp
    src/types_common.cpp
    src/types_base.cpp
    src/types_applied.cpp
    src/types_bookmarks.cpp
    src/types_members.cpp
    src/types_member_xrefs.cpp
    src/types_gaps.cpp
    src/types_enums.cpp
    src/types_func_args.cpp
    src/types_registry.cpp
    src/functions.cpp
    src/decompiler.cpp
    src/search_bytes.cpp
    src/idapython_exec.cpp
    src/metadata.cpp
    src/metadata_binary.cpp
    src/metadata_runtime_settings.cpp
    src/true_believers.cpp
    src/ui_context_provider.cpp
    src/ida_compat.cpp
)

target_include_directories(idasql
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
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

# The vendored true_believers decoder is engine-agnostic — keep the IDA SDK PCH
# out of it so it compiles standalone.
set_source_files_properties(src/true_believers.cpp PROPERTIES SKIP_PRECOMPILE_HEADERS ON)

# SDK compilation requirements only — no library linkage.
# Consumers bring their own SDK target (idasdk::plugin or idasdk::idalib).
target_link_libraries(idasql PUBLIC xsql::xsql)
target_link_libraries(idasql PRIVATE ida_platform_settings ida_compiler_settings)
target_include_directories(idasql PUBLIC "${idasdk_INCLUDE_DIRS}")
target_compile_definitions(idasql PRIVATE IDALIB_IMPL)

# Export the library target
# install(TARGETS idasql EXPORT idasqlTargets)
# install(DIRECTORY include/idasql DESTINATION include)
