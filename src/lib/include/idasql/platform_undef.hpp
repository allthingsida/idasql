// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
