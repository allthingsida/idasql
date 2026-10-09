// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_ext.hpp - Additional IDA entities as virtual tables
 *
 * Tables: fixups, hidden_ranges, problems, fchunks, signatures, available_signatures,
 *         local_types, mappings
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

// One entry of the database's FLIRT signature list.
struct SignatureEntry {
    int index = 0;
    std::string name;      // as IDA stores it: a short name or an absolute path
    std::string title;     // the library's name, "" when the file is not found
    int state = 0;         // IDASGN_APPLIED / IDASGN_CURRENT / IDASGN_PLANNED
    int32 matches = 0;     // library modules the signature recognised
    std::string optlibs;
};

// One .sig file IDA would find for the current processor.
struct AvailableSignature {
    std::string name;      // file name without ".sig": what INSERT takes
    std::string title;
    std::string path;
    std::string source;    // "idausr", "idasgn" or "idadir"
    int is_startup = -1;   // -1: unknown (no header reader on this SDK)
    int64_t modules = -1;  // -1: unknown
    bool in_list = false;  // already in the database's signature list
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

} // namespace extended
} // namespace idasql
