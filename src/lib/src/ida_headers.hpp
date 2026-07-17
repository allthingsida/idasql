// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * ida_headers.hpp - Precompiled header for the idasql library.
 *
 * Registered as the PCH via target_precompile_headers() in
 * src/lib/CMakeLists.txt. Every .cpp/.hpp in the idasql library should
 * `#include "ida_headers.hpp"` rather than including individual IDA SDK
 * headers (<ida.hpp>, <kernwin.hpp>, ...) directly -- this keeps PCH hits
 * consistent and centralizes platform/MSVC workarounds.
 *
 * Aggregates: <idasql/platform.hpp> fixups, the std headers we need
 * before the SDK, the full IDA SDK superset, the MSVC strtoull undef,
 * and the cross-SDK compat shims in ida_compat.hpp.
 *
 * NOT in this PCH:
 *   - widget_catalog.hpp -- include explicitly when you use BWN_*
 *     classification helpers (only ui_context_provider.cpp today).
 *
 * Note: platform.hpp must still be included BEFORE standard library headers
 * in each TU (it sets up macOS typedef redirects that affect system headers).
 * This file handles the corresponding platform_undef.hpp cleanup.
 */

#pragma once

// Platform fixups (macOS typedef redirects) — must precede system headers
#include <idasql/platform.hpp>

// Standard library headers — include before IDA SDK so that IDA's pro.h
// (which pulls in <stdlib.h> C-style) doesn't prevent <cstdlib> from
// placing _strtoui64 / strtoull into namespace std.
#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iomanip>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Platform fixup cleanup (undoes platform.hpp macOS typedef redirects)
#include <idasql/platform_undef.hpp>

// IDA SDK -- full superset used across the library
#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <dbg.hpp>
#include <entry.hpp>
#include <expr.hpp>
#include <fixup.hpp>
#include <fpro.h>
#include <frame.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <hexrays.hpp>
#include <idalib.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <moves.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <offset.hpp>
#include <problems.hpp>
#include <segment.hpp>
#include <strlist.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

// IDA SDK's pro.h defines: #define strtoull _strtoui64  (VS2010 compat shim).
// Modern MSVC has strtoull natively, and the macro breaks nlohmann/json which
// uses std::strtoull (macro-expanded to std::_strtoui64 which doesn't exist).
// Undo the macro so downstream headers see the real std::strtoull.
#ifdef _MSC_VER
#undef strtoull
#endif

// Cross-SDK feature macros, fallbacks, and inline wrappers (e.g.
// idasql_auto_wait). Must come AFTER the IDA SDK headers so it can probe
// for SDK-defined macros (HTI_SEMICOLON, etc.).
#include "ida_compat.hpp"
