// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * checkpoints.hpp - named undo checkpoints over IDA's undo engine (undo.hpp).
 *
 * SQL surface:
 *   checkpoints   writable table (seq, label, created_at, kind, writes_since,
 *                 statement, state)
 *     INSERT INTO checkpoints(label) VALUES ('turn 21')   create one (label optional)
 *     UPDATE checkpoints SET state='undone' WHERE label='turn 21'
 *                                     roll back to it, newer checkpoints included
 *     UPDATE checkpoints SET state='live' WHERE ...   redo the next undone one
 *   undo_state    one read-only row: IDA's next undo/redo labels, whether a redo
 *                 would be accepted, and what the last rollback undid
 *   runtime_settings key auto_checkpoint = 'off' | 'statement'
 *                 'statement': every top-level statement that writes gets its own
 *                 checkpoint (kind 'auto', label 'auto#N')
 *
 * A checkpoint is an IDA undo point (create_undo_point). IDA cannot list its
 * undo history, so idasql keeps the list; it covers one database session (it
 * survives save_database(), not closing the database). IDA's undo is separate
 * from SQLite transactions: a SQL ROLLBACK does not undo IDA writes, and it does
 * not remove a checkpoint either.
 *
 * Write detection ("did anything change since X?") adds libxsql's count of
 * virtual-table row writes (temp and ordinary SQLite tables excluded) on every
 * live engine to a count of IDA database-change notifications (HT_IDB), which
 * also sees scalar-function, IDAPython and GUI writes. IDA's own undo/redo
 * notify nothing. IDB changes Hex-Rays makes while idasql decompiles to read
 * (it stores a guessed prototype the first time) are not counted.
 */

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
    std::string kind;                      // "user" or "auto"
    std::optional<std::string> statement;  // auto: the statement that wrote
    std::string state;                     // "live" or "undone"
    int64_t writes_since = 0;              // filled when the table is read
    int64_t mark = 0;     // write epoch this checkpoint's changes are counted from
    int64_t segment = 0;  // writes undone with this checkpoint (redo bookkeeping)
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

// The engines whose connections count toward the write epoch. The first engine
// starts a session (empty list, IDA change monitor hooked); when the last one
// goes, the session ends.
void attach_engine(QueryEngine* engine);
void detach_engine(QueryEngine* engine);
void retarget_engine(QueryEngine* from, QueryEngine* to);

// Monotonic write epoch: table writes + IDA database-change notifications.
int64_t write_epoch();

// IDB changes made while one of these is alive are side effects of reading and
// are not counted as writes. Main thread only.
class ScopedDerivedWrites {
public:
    ScopedDerivedWrites();
    ~ScopedDerivedWrites();
    ScopedDerivedWrites(const ScopedDerivedWrites&) = delete;
    ScopedDerivedWrites& operator=(const ScopedDerivedWrites&) = delete;
};

// Brackets one statement for auto_checkpoint. Statements nested inside another
// (SQL issued from Python through `import idasql`) belong to the outer one.
class StatementScope {
public:
    // `db` (optional) classifies a WITH statement as a read or a write.
    StatementScope(const std::string& sql, xsql::Database* db);
    ~StatementScope();
    void finish();
    StatementScope(const StatementScope&) = delete;
    StatementScope& operator=(const StatementScope&) = delete;

private:
    std::string sql_;
    bool finished_ = false;
};

} // namespace checkpoints
} // namespace idasql
