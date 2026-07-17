// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * platform_undef.hpp - Undo platform.hpp redirects before IDA headers
 *
 * Include this after all system/library headers and before any IDA SDK
 * headers. See platform.hpp for details.
 *
 * This file is intentionally NOT guarded with #pragma once so it can
 * be included multiple times (each header pair needs its own cleanup).
 */

#ifdef __APPLE__
#undef processor_t
#undef token_t
#endif
