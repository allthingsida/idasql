// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace code {

struct DataItemRow {
  ea_t ea = BADADDR;
};

GeneratorTableDef<DataItemRow> define_data_items();

}
}
