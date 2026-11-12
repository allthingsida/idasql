// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <string>

namespace idasql {
namespace idapython {

bool runtime_acquire(std::string* error = nullptr);

void runtime_release();

}
}
