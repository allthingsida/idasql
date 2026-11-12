#
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.

set(_XSQL_VI_COMPANY "allthingsida")
set(_XSQL_VI_PRODUCT "idasql")

function(xsql_add_versioninfo target)
  if(NOT WIN32)
    return()
  endif()

  cmake_parse_arguments(VI "" "FILETYPE;DESCRIPTION;ORIGINAL_FILENAME" "" ${ARGN})

  if(NOT VI_FILETYPE OR NOT VI_DESCRIPTION OR NOT VI_ORIGINAL_FILENAME)
    message(FATAL_ERROR
      "xsql_add_versioninfo(${target}): FILETYPE, DESCRIPTION, and ORIGINAL_FILENAME are required")
  endif()

  if(NOT DEFINED TOOL_VERSION_MAJOR
      OR NOT DEFINED TOOL_VERSION_MINOR
      OR NOT DEFINED TOOL_VERSION_PATCH
      OR NOT DEFINED TOOL_VERSION_REVISION
      OR NOT DEFINED TOOL_VERSION_STRING)
    message(FATAL_ERROR
      "xsql_add_versioninfo(${target}): version variables must be set in scope")
  endif()

  set(VERINFO_FILETYPE          "${VI_FILETYPE}")
  set(VERINFO_DESCRIPTION       "${VI_DESCRIPTION}")
  set(VERINFO_ORIGINAL_FILENAME "${VI_ORIGINAL_FILENAME}")
  set(VERINFO_INTERNAL_NAME     "${target}")
  set(VERINFO_COMPANY           "${_XSQL_VI_COMPANY}")
  set(VERINFO_PRODUCT           "${_XSQL_VI_PRODUCT}")

  set(_rc_out "${CMAKE_CURRENT_BINARY_DIR}/${target}_versioninfo.rc")
  configure_file(
    "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/versioninfo.rc.in"
    "${_rc_out}"
    @ONLY)
  target_sources(${target} PRIVATE "${_rc_out}")
endfunction()
