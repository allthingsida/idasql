// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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

struct TypesRegistry {
  CachedTableDef<TypeEntry> types;
  GeneratorTableDef<AppliedTypeEntry> applied_types;
  CachedTableDef<LocalTypeBookmarkRow> local_type_bookmarks;
  CachedTableDef<MemberEntry> types_members;
  GeneratorTableDef<MemberXrefRow> struct_member_xrefs;
  GeneratorTableDef<GapRow> type_gaps;
  CachedTableDef<EnumValueEntry> types_enum_values;
  CachedTableDef<FuncArgEntry> types_func_args;

  TypesRegistry();
  void register_all(xsql::Database &db);

private:
  void create_views(xsql::Database &db);
};

}
}
