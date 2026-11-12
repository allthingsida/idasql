// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace idasql {

class QueryEngine;

namespace checkpoints {

struct CheckpointRow {
    int64_t seq = 0;
    std::string label;
    std::string created_at;
    std::string kind;
    std::optional<std::string> statement;
    std::string state;
    int64_t writes_since = 0;
    int64_t mark = 0;
    int64_t segment = 0;
};

struct UndoStateRow {
    std::optional<std::string> next_undo_label;
    std::optional<std::string> next_redo_label;
    int redo_safe = 0;
    int64_t last_rollback_steps = 0;
    int64_t last_rollback_foreign = 0;
};

struct CheckpointsRegistry {
    CachedTableDef<CheckpointRow> checkpoints;
    CachedTableDef<UndoStateRow> undo_state;

    CheckpointsRegistry();
    void register_all(xsql::Database& db);
};

void attach_engine(QueryEngine* engine);
void detach_engine(QueryEngine* engine);
void retarget_engine(QueryEngine* from, QueryEngine* to);

int64_t write_epoch();

class ScopedDerivedWrites {
public:
    ScopedDerivedWrites();
    ~ScopedDerivedWrites();
    ScopedDerivedWrites(const ScopedDerivedWrites&) = delete;
    ScopedDerivedWrites& operator=(const ScopedDerivedWrites&) = delete;
};

class StatementScope {
public:
    StatementScope(const std::string& sql, xsql::Database* db);
    ~StatementScope();
    void finish();
    StatementScope(const StatementScope&) = delete;
    StatementScope& operator=(const StatementScope&) = delete;

private:
    std::string sql_;
    bool finished_ = false;
};

}
}
