// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * idapython.hpp - Public IDAPython runtime API
 *
 * Use runtime_acquire/runtime_release to manage the Python runtime
 * in CLI tools and plugins. The full internal API is private.
 */

#pragma once

#include <string>

namespace idasql {
namespace idapython {

/**
 * Acquire the IDAPython runtime (refcounted).
 * Call before executing Python or enabling Python-backed SQL functions.
 * @param error Optional error message on failure
 * @return true on success
 */
bool runtime_acquire(std::string* error = nullptr);

/**
 * Release the IDAPython runtime (refcounted).
 * Balances a prior runtime_acquire() call.
 */
void runtime_release();

} // namespace idapython
} // namespace idasql
