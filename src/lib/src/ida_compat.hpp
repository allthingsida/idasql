// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * ida_compat.hpp - IDA SDK cross-version compatibility shims.
 *
 * Centralizes feature detection and small inline wrappers that paper over
 * API differences between IDA SDK versions. Included via ida_headers.hpp,
 * so every translation unit picks the same definitions.
 *
 * Feature macros are named IDASQL_HAS_<FEATURE> and resolve to 0 or 1.
 * Use `#if IDASQL_HAS_FOO` at call sites; never repeat magic SDK numbers
 * outside this file.
 */

#pragma once

// Cutoffs empirically verified against IDA SDK headers 9.0, 9.1, 9.2, 9.3.
//
//  9.1 added:  tinfo_t::get_edm()/get_edm_by_value() (renamed from find_edm),
//              open_database()'s third `args` parameter, HTI_SEMICOLON.
//  9.2 added:  ctree_parentee_t::parent_item(),
//              is_ida_library() default arguments,
//              callcnv_t typedef, GENDSM_UNHIDE,
//              place_t::equals() (and the idaplace_t__equals runtime export
//              — shimmed locally in ida_compat.cpp).
//  9.3 added:  BWN_TITREE (handled via plain `#ifdef`).
#define IDASQL_HAS_PARENT_ITEM             (IDA_SDK_VERSION >= 920)
#define IDASQL_HAS_GET_EDM                 (IDA_SDK_VERSION >= 910)
#define IDASQL_HAS_OPEN_DATABASE_3ARG      (IDA_SDK_VERSION >= 910)
#define IDASQL_HAS_IS_IDA_LIBRARY_NOARG    (IDA_SDK_VERSION >= 920)

#if IDA_SDK_VERSION < 920
// callcnv_t was introduced in 9.2 as a distinct type for calling-convention
// values extracted from cm_t. On older SDKs, cm_t is the underlying type.
using callcnv_t = cm_t;

// HTI_SEMICOLON: optional-semicolon mode for parse_decls. Added in 9.1.
// The #ifndef guard means this no-op fallback only kicks in on 9.0 where
// the flag genuinely has no SDK constant — on 9.1 the real value from
// typeinf.hpp wins. Falling back to 0 makes the bitmask OR inert: the
// parser will be strict about trailing semicolons on 9.0.
#ifndef HTI_SEMICOLON
#define HTI_SEMICOLON 0
#endif

// GENDSM_UNHIDE: generate_disasm_line flag to render hidden objects.
// Added in 9.2. Falling back to 0 means hidden segments/functions/ranges
// stay hidden in the disasm we produce on older SDKs.
#ifndef GENDSM_UNHIDE
#define GENDSM_UNHIDE 0
#endif
#endif

/**
 * Respect the user's auto-analysis choice when waiting for AA.
 *
 * idasql calls auto_wait() defensively before write operations so that
 * renames/type applies/etc. don't fight in-progress analysis. When the
 * user has explicitly disabled auto-analysis (`idat -a`, the
 * Options→General→Analysis toggle, or a runtime enable_auto(false)),
 * dragging them back into AA defeats their choice. is_auto_enabled()
 * reflects the effective state across all three opt-out paths.
 *
 * See allthingsida/idasql#31.
 */
inline void idasql_auto_wait()
{
    if (!is_auto_enabled())
        return;
    auto_wait();
}

/**
 * is_ida_library() distinguishes the idalib/CLI runtime from a full IDA (GUI
 * plugin) runtime. It gained default arguments in SDK 9.2; older SDKs require
 * all three. Wrap it so call sites never repeat the version guard.
 */
inline bool idasql_is_ida_library()
{
#if IDASQL_HAS_IS_IDA_LIBRARY_NOARG
    return is_ida_library();
#else
    return is_ida_library(nullptr, 0, nullptr);
#endif
}
