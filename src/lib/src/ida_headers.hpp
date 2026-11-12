// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <idasql/platform.hpp>

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

#include <idasql/platform_undef.hpp>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4005 4018 4244 4267)
#endif
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
#include <diskio.hpp>
#if defined(__has_include)
#if __has_include(<libfuncs.hpp>)
#include <libfuncs.hpp>
#endif
#endif
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
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif

#ifdef _MSC_VER
#undef strtoull
#endif

#include "ida_compat.hpp"
