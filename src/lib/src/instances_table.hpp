// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include "instances.hpp"

namespace idasql {
namespace instances {

struct TableRegistry {
    CachedTableDef<Entry> table;

    TableRegistry();
    void register_all(xsql::Database& db);
};

}
}
