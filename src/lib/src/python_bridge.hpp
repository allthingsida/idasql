// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <string>

namespace idasql {

class QueryEngine;

namespace python_bridge {

constexpr int kMaxDepth = 8;

void attach(QueryEngine* engine);

void detach(QueryEngine* engine);

void retarget(QueryEngine* from, QueryEngine* to);

bool ensure_python_module(std::string* error = nullptr);

bool in_bridge_call();

}
}
