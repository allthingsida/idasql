// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

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
