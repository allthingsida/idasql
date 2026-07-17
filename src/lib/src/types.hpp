// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * types.hpp - Umbrella header for the idasql::types SQL tables.
 *
 * Each table (types, applied_types, local_type_bookmarks, types_members,
 * types_enum_values, types_func_args) is declared in its own `types_<table>.hpp`
 * and implemented in the matching `types_<table>.cpp`. This header aggregates
 * them and declares the `TypesRegistry` that owns and registers every table.
 *
 * Views: types_v_structs / _unions / _enums / _typedefs / _funcs / _inheritance.
 */

#pragma once

#include "types_common.hpp"

#include "types_applied.hpp"
#include "types_base.hpp"
#include "types_bookmarks.hpp"
#include "types_enums.hpp"
#include "types_func_args.hpp"
#include "types_gaps.hpp"
#include "types_member_xrefs.hpp"
#include "types_members.hpp"

namespace idasql {
namespace types {

// ============================================================================
// Types Registry
// ============================================================================

struct TypesRegistry {
  CachedTableDef<TypeEntry> types;
  GeneratorTableDef<AppliedTypeEntry> applied_types;
  CachedTableDef<LocalTypeBookmarkRow> local_type_bookmarks;
  CachedTableDef<MemberEntry> types_members;
  CachedTableDef<MemberXrefRow> struct_member_xrefs;
  CachedTableDef<GapRow> type_gaps;
  CachedTableDef<EnumValueEntry> types_enum_values;
  CachedTableDef<FuncArgEntry> types_func_args;

  TypesRegistry();
  void register_all(xsql::Database &db);

private:
  void create_views(xsql::Database &db);
};

} // namespace types
} // namespace idasql
