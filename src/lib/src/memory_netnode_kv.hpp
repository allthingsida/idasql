// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_netnode_kv.hpp - `netnode_kv` table (netnode-backed key-value store).
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace memory {

struct NetnodeKvRow {
  std::string key;
  std::string value;
  // Stable identity: the entry netnode index for this key. Used as the table's
  // rowid so a full-scan multi-row DELETE/UPDATE resolves each row by its own
  // entry_id (round-tripping through the entry_id-keyed row_lookup) instead of
  // by a cache position that shifts as earlier rows are removed. 0 = unknown.
  nodeidx_t entry_id = 0;
};

CachedTableDef<NetnodeKvRow> define_netnode_kv();

} // namespace memory
} // namespace idasql
