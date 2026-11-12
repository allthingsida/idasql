// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace memory {

struct NetnodeKvRow {
  std::string key;
  std::string value;
  nodeidx_t entry_id = 0;
};

CachedTableDef<NetnodeKvRow> define_netnode_kv();

}
}
