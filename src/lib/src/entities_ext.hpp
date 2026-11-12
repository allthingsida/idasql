// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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
    int index = 0;
    std::string name;
    std::string title;
    int state = 0;
    int32 matches = 0;
    std::string optlibs;
};

struct AvailableSignature {
    std::string name;
    std::string title;
    std::string path;
    std::string source;
    int is_startup = -1;
    int64_t modules = -1;
    bool in_list = false;
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
void collect_available_signatures(std::vector<AvailableSignature>& rows);
void collect_local_types(std::vector<LocalTypeEntry>& rows);

CachedTableDef<FixupEntry> define_fixups();
VTableDef define_hidden_ranges();
CachedTableDef<ProblemEntry> define_problems();
VTableDef define_fchunks();
CachedTableDef<SignatureEntry> define_signatures();
CachedTableDef<AvailableSignature> define_available_signatures();
CachedTableDef<LocalTypeEntry> define_local_types();
VTableDef define_mappings();

struct ExtendedRegistry {
    CachedTableDef<FixupEntry> fixups;
    VTableDef hidden_ranges;
    CachedTableDef<ProblemEntry> problems;
    VTableDef fchunks;
    CachedTableDef<SignatureEntry> signatures;
    CachedTableDef<AvailableSignature> available_signatures;
    CachedTableDef<LocalTypeEntry> local_types;
    VTableDef mappings;

    ExtendedRegistry();
    void register_all(xsql::Database& db);
};

}
}
