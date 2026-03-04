// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * ida_headers.hpp - Precompiled header for IDA SDK includes
 *
 * Contains the full superset of all IDA SDK headers used across the library.
 * Include this instead of individual IDA headers in private .cpp/.hpp files.
 *
 * Usage: #include "ida_headers.hpp"
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
