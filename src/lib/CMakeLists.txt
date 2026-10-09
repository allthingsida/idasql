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
    src/code_switch_tables.cpp
    src/code_function_frames.cpp
    src/code_stack_probe.cpp
    src/code_data_items.cpp
    src/code_graph_tables.cpp
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
    src/decompiler_ctree.cpp
    src/decompiler_mc.cpp
    src/decompiler_splits.cpp
    src/search_bytes.cpp
    src/deep_link.cpp
    src/deep_links_tables.cpp
    src/idapython_exec.cpp
    src/metadata.cpp
    src/metadata_binary.cpp
    src/metadata_notepad.cpp
    src/metadata_config.cpp
    src/cfg_parser.cpp
    src/true_believers.cpp
    src/ui_context_provider.cpp
    src/ida_compat.cpp
    src/checkpoints.cpp
    src/python_bridge.cpp
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

# The deep-link module (link model, IPC client, OS handler registration) uses no
# IDA API: the `idasql link` verbs run before idalib is initialised.
set_source_files_properties(src/deep_link.cpp PROPERTIES SKIP_PRECOMPILE_HEADERS ON)

# SDK compilation requirements only — no library linkage.
# Consumers bring their own SDK target (idasdk::plugin or idasdk::idalib).
target_link_libraries(idasql PUBLIC xsql::xsql)
target_link_libraries(idasql PRIVATE ida_platform_settings ida_compiler_settings)
target_include_directories(idasql PUBLIC "${idasdk_INCLUDE_DIRS}")
target_compile_definitions(idasql PRIVATE IDALIB_IMPL)

# The SDK's own pro.h uses std::is_pod, deprecated in C++20 (every SDK version):
# MSVC's STL has a switch for exactly that one; GCC/Clang ignore deprecations
# inside the SDK headers (ida_headers.hpp), never in idasql code.
if(MSVC)
    target_compile_definitions(idasql PRIVATE _SILENCE_CXX20_IS_POD_DEPRECATION_WARNING)
endif()

# SDK 9.4 deprecates every API that hands out a func_t*, segment_t* or
# hidden_range_t* (and qflow_chart_t / mba_ranges_t). The library reaches them
# only through the ea-based wrappers in src/ida_compat.hpp/.cpp, so on 9.4+ any
# deprecated call is a build error rather than one more warning.
file(STRINGS "${idasdk_INCLUDE_DIRS}/pro.h" _idasql_sdk_version_line
    REGEX "^#define[ \t]+IDA_SDK_VERSION[ \t]+[0-9]+")
string(REGEX REPLACE "^#define[ \t]+IDA_SDK_VERSION[ \t]+([0-9]+).*" "\\1"
    _idasql_sdk_version "${_idasql_sdk_version_line}")
if(NOT _idasql_sdk_version MATCHES "^[0-9]+$")
    message(FATAL_ERROR "idasql: cannot read IDA_SDK_VERSION from ${idasdk_INCLUDE_DIRS}/pro.h")
endif()
# 9.0 SP1 added get_undo_action_label()/get_redo_action_label() to undo.hpp
# without changing IDA_SDK_VERSION (900 for GA and SP1): key on the declaration.
file(STRINGS "${idasdk_INCLUDE_DIRS}/undo.hpp" _idasql_undo_labels REGEX "get_undo_action_label")
if(_idasql_undo_labels)
    target_compile_definitions(idasql PUBLIC IDASQL_SDK_HAS_UNDO_LABELS=1)
else()
    target_compile_definitions(idasql PUBLIC IDASQL_SDK_HAS_UNDO_LABELS=0)
endif()

if(_idasql_sdk_version GREATER_EQUAL 940)
    if(MSVC)
        target_compile_options(idasql PRIVATE /we4996)
    else()
        target_compile_options(idasql PRIVATE -Werror=deprecated-declarations)
    endif()
endif()

# Export the library target
# install(TARGETS idasql EXPORT idasqlTargets)
# install(DIRECTORY include/idasql DESTINATION include)
