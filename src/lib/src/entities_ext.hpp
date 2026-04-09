// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * entities_ext.hpp - Additional IDA entities as virtual tables
 *
 * Tables: fixups, hidden_ranges, problems, fchunks, signatures, local_types, mappings
 */

#pragma once

#include <idasql/platform.hpp>

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include "ida_headers.hpp"

namespace idasql {
namespace extended {

struct FixupEntry {
    ea_t ea;
    fixup_data_t data;
};

struct ProblemEntry {
    ea_t ea;
    problist_id_t type;
    std::string description;
    std::string type_name;
};

struct SignatureEntry {
    int index;
    std::string name;
    std::string optlibs;
    int32 state;
};

struct LocalTypeEntry {
    uint32_t ordinal;
    std::string name;
    std::string type_str;
    bool is_struct;
    bool is_enum;
    bool is_typedef;
};

void collect_fixups(std::vector<FixupEntry>& rows);
void collect_problems(std::vector<ProblemEntry>& rows);
void collect_signatures(std::vector<SignatureEntry>& rows);
void collect_local_types(std::vector<LocalTypeEntry>& rows);

CachedTableDef<FixupEntry> define_fixups();
VTableDef define_hidden_ranges();
CachedTableDef<ProblemEntry> define_problems();
VTableDef define_fchunks();
CachedTableDef<SignatureEntry> define_signatures();
CachedTableDef<LocalTypeEntry> define_local_types();
VTableDef define_mappings();

struct ExtendedRegistry {
    CachedTableDef<FixupEntry> fixups;
    VTableDef hidden_ranges;
    CachedTableDef<ProblemEntry> problems;
    VTableDef fchunks;
    CachedTableDef<SignatureEntry> signatures;
    CachedTableDef<LocalTypeEntry> local_types;
    VTableDef mappings;

    ExtendedRegistry();
    void register_all(xsql::Database& db);
};

} // namespace extended
} // namespace idasql
