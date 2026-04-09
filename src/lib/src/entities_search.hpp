// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * entities_search.hpp - Grep-style entity search table
 *
 * Tables: grep
 */

#pragma once

#include <idasql/platform.hpp>

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <memory>
#include <string>

#include "ida_headers.hpp"

namespace idasql {
namespace search {

struct EntityRow {
    std::string name;
    std::string kind;
    ea_t address = BADADDR;
    uint32 ordinal = 0;
    std::string parent_name;
    std::string full_name;
    bool has_address = false;
    bool has_ordinal = false;
};

class NamePattern {
    std::string pattern_;
    bool valid_ = false;

public:
    explicit NamePattern(const std::string& raw);
    bool valid() const { return valid_; }
    bool matches(const std::string& value) const;

private:
    static std::string to_lower(const std::string& s);
    static bool has_wildcards(const std::string& s);
    static bool like_match(const std::string& text, const std::string& pattern);
};

enum class EntitySource {
    Functions = 0,
    Labels,
    Segments,
    Structs,
    Unions,
    Enums,
    Members,
    EnumMembers,
    Done
};

class EntityGenerator {
    NamePattern pattern_;
    EntitySource current_source_ = EntitySource::Functions;
    size_t current_index_ = 0;
    EntityRow current_row_;
    uint32 type_ordinal_ = 0;
    size_t member_index_ = 0;
    tinfo_t current_type_;

public:
    explicit EntityGenerator(const std::string& pattern);
    bool next();
    const EntityRow& current() const { return current_row_; }

private:
    bool matches(const std::string& name) const;
    bool advance_current_source();
    bool advance_functions();
    bool advance_labels();
    bool advance_segments();
    bool advance_types_of_kind(const char* kind, bool want_struct, bool want_union, bool want_enum);
    bool advance_structs();
    bool advance_unions();
    bool advance_enums();
    bool advance_members();
    bool advance_enum_members();
};

class GrepIterator : public xsql::RowIterator {
    EntityGenerator generator_;
    bool started_ = false;
    bool valid_ = false;
    int64_t rowid_ = -1;

public:
    explicit GrepIterator(const std::string& pattern);
    bool next() override;
    bool eof() const override;
    void column(xsql::FunctionContext& ctx, int col) override;
    int64_t rowid() const override;
};

VTableDef define_grep();
bool register_grep_entities(xsql::Database& db);

} // namespace search
} // namespace idasql
