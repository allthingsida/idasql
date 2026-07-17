// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * ida_compat.cpp - link-time compatibility shims for older IDA runtimes.
 *
 * IDA SDK 9.2 added place_t::equals() and the matching idaplace_t__equals
 * runtime export. A plugin built against 9.2/9.3 headers ends up importing
 * idaplace_t__equals even when it only uses idaplace_t indirectly. IDA 9.0
 * does not export the symbol, so the plugin DLL fails to load before
 * initialization. Provide the default implementation locally for the
 * pre-9.2 case (forward to the still-exported idaplace_t__compare2).
 *
 * See allthingsida/idasql#30.
 */

#include "ida_headers.hpp"

#if IDA_SDK_VERSION < 920

// place_t / idaplace_t come from <kernwin.hpp> via ida_headers.hpp.

#if defined(_WIN32)
#define IDASQL_IDAAPI __stdcall
#else
#define IDASQL_IDAAPI
#endif

extern "C" int IDASQL_IDAAPI idaplace_t__compare2(
        const idaplace_t *ths,
        const place_t *t2,
        void *ud);

extern "C" bool IDASQL_IDAAPI idaplace_t__equals(
        const idaplace_t *ths,
        const place_t *t2,
        void *ud)
{
    return idaplace_t__compare2(ths, t2, ud) == 0;
}

#undef IDASQL_IDAAPI

#endif  // IDA_SDK_VERSION < 920
