// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "types.hpp"

namespace idasql {
namespace types {

TypesRegistry::TypesRegistry()
    : types(define_types())
    , applied_types(define_applied_types())
    , local_type_bookmarks(define_local_type_bookmarks())
    , types_members(define_types_members())
    , struct_member_xrefs(define_struct_member_xrefs())
    , type_gaps(define_type_gaps())
    , types_enum_values(define_types_enum_values())
    , types_func_args(define_types_func_args())
{}

void TypesRegistry::register_all(xsql::Database& db) {
    db.register_cached_table("ida_types", &types);
    db.create_table("types", "ida_types");

    db.register_generator_table("ida_applied_types", &applied_types);
    db.create_table("applied_types", "ida_applied_types");

    db.register_cached_table("ida_local_type_bookmarks", &local_type_bookmarks);
    db.create_table("local_type_bookmarks", "ida_local_type_bookmarks");

    db.register_cached_table("ida_types_members", &types_members);
    db.create_table("types_members", "ida_types_members");

    db.register_cached_table("ida_struct_member_xrefs", &struct_member_xrefs);
    db.create_table("struct_member_xrefs", "ida_struct_member_xrefs");

    db.register_cached_table("ida_type_gaps", &type_gaps);
    db.create_table("type_gaps", "ida_type_gaps");

    db.register_cached_table("ida_types_enum_values", &types_enum_values);
    db.create_table("types_enum_values", "ida_types_enum_values");

    db.register_cached_table("ida_types_func_args", &types_func_args);
    db.create_table("types_func_args", "ida_types_func_args");

    // Create views
    create_views(db);
}

void TypesRegistry::create_views(xsql::Database& db) {
    // Filtering views
    db.exec("CREATE VIEW IF NOT EXISTS types_v_structs AS SELECT * FROM types WHERE is_struct = 1");
    db.exec("CREATE VIEW IF NOT EXISTS types_v_unions AS SELECT * FROM types WHERE is_union = 1");
    db.exec("CREATE VIEW IF NOT EXISTS types_v_enums AS SELECT * FROM types WHERE is_enum = 1");
    db.exec("CREATE VIEW IF NOT EXISTS types_v_typedefs AS SELECT * FROM types WHERE is_typedef = 1");
    db.exec("CREATE VIEW IF NOT EXISTS types_v_funcs AS SELECT * FROM types WHERE is_func = 1");

    // Inheritance view: struct/class base classes
    db.exec(R"(
        CREATE VIEW IF NOT EXISTS types_v_inheritance AS
        SELECT
            m.type_ordinal as derived_ordinal,
            m.type_name as derived_name,
            m.member_type as base_type_name,
            m.member_type_ordinal as base_ordinal,
            m."offset" as base_offset
        FROM types_members m
        WHERE m.is_baseclass = 1
    )");
}

} // namespace types
} // namespace idasql
