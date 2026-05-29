// Copyright (c) 2026 Oxygen1a1
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * ida90_compat.cpp - compatibility shims for plugins built with newer SDKs.
 *
 * IDA SDK 9.2 added place_t::equals() and the idaplace_t__equals export.
 * Binaries built with 9.2+ headers import that symbol even when they only use
 * idaplace_t indirectly. IDA 9.0 does not export it, so loading fails before
 * plugin initialization. Provide the default implementation locally.
 */

struct place_t;
struct idaplace_t;

#if defined(_WIN32)
#define IDASQL_IDAAPI __stdcall
#else
#define IDASQL_IDAAPI
#endif

extern "C" int IDASQL_IDAAPI idaplace_t__compare2(
        const idaplace_t* ths,
        const place_t* t2,
        void* ud);

extern "C" bool IDASQL_IDAAPI idaplace_t__equals(
        const idaplace_t* ths,
        const place_t* t2,
        void* ud) {
    return idaplace_t__compare2(ths, t2, ud) == 0;
}

#undef IDASQL_IDAAPI
