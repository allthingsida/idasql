// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "checkpoints.hpp"

#include <idasql/database.hpp>
#include <idasql/runtime_settings.hpp>

#include "decompiler.hpp"
#include "ida_headers.hpp"

#include <undo.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <ctime>
#include <vector>

namespace idasql {
namespace checkpoints {
namespace {

// The undo-point record IDAPython's create_undo_point(action, label) builds, so
// a checkpoint shows in IDA's Undo menu as "idasql checkpoint: <label>".
constexpr const char* kActionName = "idasql";
constexpr const char* kLabelPrefix = "idasql checkpoint: ";
constexpr const char* kAutoPrefix = "auto#";
constexpr size_t kStatementMax = 240;
constexpr const char* kStateLive = "live";
constexpr const char* kStateUndone = "undone";

// > 0 while idasql causes IDB changes as a side effect of reading.
thread_local int t_derived_depth = 0;
// Depth of the statements running on this thread (nested = issued from Python).
thread_local int t_stmt_depth = 0;

struct Store {
    std::vector<CheckpointRow> live;   // oldest first
    std::vector<CheckpointRow> redo;   // back() = the next checkpoint a redo restores
    int64_t next_seq = 1;
    // write_epoch() right after the last rollback/redo; -1 when none is pending.
    // After an undo, IDA does not end its redo branch when the database is changed
    // programmatically, and a later perform_redo() re-applies the undone step AND
    // drops those newer changes. A redo is refused once the epoch moved.
    int64_t changes_mark = -1;
    // auto_checkpoint: an undo point created before a statement that has not
    // written yet. The next statement reuses it instead of stacking empty undo
    // points (IDA keeps empty ones; each would cost an undo step).
    std::optional<CheckpointRow> pending;
    int64_t last_rollback_steps = 0;
    int64_t last_rollback_foreign = 0;
};

Store& store() {
    static Store s;
    return s;
}

// Counts IDA database-change notifications. Measured on IDA 9.2-9.4: renames,
// comments, types, bytes, functions, folders... all notify; perform_undo(),
// perform_redo() and idle auto-analysis with nothing queued do not.
struct WriteMonitor : public event_listener_t {
    std::atomic<int64_t> events{0};
    bool hooked = false;

    ssize_t idaapi on_event(ssize_t code, va_list) override {
        if (code == idb_event::closebase) {
            // IDA's undo history ends with the database.
            store() = Store{};
            return 0;
        }
        if (t_derived_depth > 0)
            return 0;
        switch (code) {
            case idb_event::savebase:
            case idb_event::upgraded:
            case idb_event::auto_empty:
            case idb_event::auto_empty_finally:
            case idb_event::determined_main:
            case idb_event::extlang_changed:
            case idb_event::idasgn_loaded:
            case idb_event::kernel_config_loaded:
            case idb_event::loader_finished:
            case idb_event::flow_chart_created:
                break;  // informational, not a change to the database
            default:
                events.fetch_add(1, std::memory_order_relaxed);
                break;
        }
        return 0;
    }
};

WriteMonitor& monitor() {
    static WriteMonitor m;
    return m;
}

struct Engines {
    std::vector<QueryEngine*> live;
    int64_t retired_writes = 0;  // vtab writes of engines already gone
};

Engines& engines() {
    static Engines e;
    return e;
}

std::string undo_label(const std::string& label) {
    return std::string(kLabelPrefix) + label;
}

bool is_idasql_label(const qstring& raw) {
    const size_t n = std::char_traits<char>::length(kLabelPrefix);
    return raw.length() >= n && strncmp(raw.c_str(), kLabelPrefix, n) == 0;
}

std::string now_iso() {
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    return buf;
}

// After undo/redo the IDB is right but cached decompilations are not: Hex-Rays
// would serve the old pseudocode and lvars, and nothing says which functions
// changed. (Table caches are query-scoped, so they rebuild on their own.)
void refresh_caches() {
    if (decompiler::hexrays_available())
        clear_cached_cfuncs();
}

bool create_point(const std::string& label) {
    // Callers take their write mark AFTER this: creating an undo point can flush
    // pending notifications (the first one of a session reports func_updated).
    bytevec_t rec;
    rec.pack_ds(kActionName);
    rec.pack_ds(undo_label(label).c_str());
    return create_undo_point(rec.begin(), rec.size());
}

bool ida_undo_label(qstring* out) {
#if IDASQL_HAS_UNDO_LABELS
    return get_undo_action_label(out);
#else
    (void)out;
    return false;
#endif
}

bool ida_redo_label(qstring* out) {
#if IDASQL_HAS_UNDO_LABELS
    return get_redo_action_label(out);
#else
    (void)out;
    return false;
#endif
}

bool supported(std::string* error) {
#if IDASQL_HAS_UNDO_LABELS
    (void)error;
    return true;
#else
    if (error != nullptr)
        *error = "checkpoints need IDA 9.0 SP1 or later (IDA 9.0 GA cannot report its undo labels)";
    return false;
#endif
}

bool label_taken(const Store& s, const std::string& label) {
    for (const auto& cp : s.live)
        if (cp.label == label)
            return true;
    return false;
}

// A pending auto point that saw writes (GUI edits between statements, say) is a
// real checkpoint; an unused one is forgotten (its empty IDA step stays behind).
void settle_pending(Store& s, const char* statement) {
    if (!s.pending)
        return;
    if (write_epoch() != s.pending->mark) {
        s.pending->created_at = now_iso();
        s.pending->statement = std::string(statement);
        s.live.push_back(*s.pending);
    }
    s.pending.reset();
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// INSERT / UPDATE / DELETE / REPLACE (after leading whitespace and comments),
// or a WITH that SQLite says writes. Not CREATE TEMP TABLE and friends: a temp
// table is not a change to the database.
bool is_dml_statement(const std::string& sql, xsql::Database* db) {
    size_t i = 0;
    for (;;) {
        while (i < sql.size() && std::isspace(static_cast<unsigned char>(sql[i]))) ++i;
        if (sql.compare(i, 2, "--") == 0) {
            i = sql.find('\n', i);
            if (i == std::string::npos) return false;
        } else if (sql.compare(i, 2, "/*") == 0) {
            i = sql.find("*/", i + 2);
            if (i == std::string::npos) return false;
            i += 2;
        } else {
            break;
        }
    }
    std::string word;
    while (i < sql.size() && std::isalpha(static_cast<unsigned char>(sql[i])))
        word += static_cast<char>(std::tolower(static_cast<unsigned char>(sql[i++])));
    if (word == "with")
        return db != nullptr && !db->is_readonly_statement(sql);
    return word == "insert" || word == "update" || word == "delete" || word == "replace";
}

bool is_ident_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$' ||
           static_cast<unsigned char>(c) >= 0x80;
}

// Statements that name the checkpoints table (an identifier token: bare, "..",
// `..` or [..]) manage undo points themselves. The word inside a string or blob
// literal or a comment is not a reference: such a write still gets its
// auto checkpoint.
bool references_checkpoints(const std::string& sql) {
    const size_t n = sql.size();
    for (size_t i = 0; i < n;) {
        const char c = sql[i];
        if (c == '-' && i + 1 < n && sql[i + 1] == '-') {
            i = sql.find('\n', i);
            if (i == std::string::npos) return false;
            continue;
        }
        if (c == '/' && i + 1 < n && sql[i + 1] == '*') {
            i = sql.find("*/", i + 2);
            if (i == std::string::npos) return false;
            i += 2;
            continue;
        }
        if (c == '\'') {  // '...' with '' escapes (also X'..')
            for (++i; i < n; ++i) {
                if (sql[i] == '\'') {
                    if (i + 1 < n && sql[i + 1] == '\'') ++i;
                    else break;
                }
            }
            ++i;
            continue;
        }
        if (c == '"' || c == '`' || c == '[') {  // quoted identifier
            const char close = c == '[' ? ']' : c;
            std::string ident;
            for (++i; i < n; ++i) {
                if (sql[i] == close) {
                    if (close != ']' && i + 1 < n && sql[i + 1] == close) {
                        ident += close;
                        ++i;
                        continue;
                    }
                    break;
                }
                ident += sql[i];
            }
            ++i;
            if (to_lower(ident) == "checkpoints") return true;
            continue;
        }
        if (is_ident_char(c)) {
            size_t j = i;
            while (j < n && is_ident_char(sql[j])) ++j;
            if (to_lower(sql.substr(i, j - i)) == "checkpoints") return true;
            i = j;
            continue;
        }
        ++i;
    }
    return false;
}

bool auto_checkpoint_enabled() {
    return runtime_settings().auto_checkpoint() == "statement";
}

// --------------------------------------------------------------------------
// The verbs
// --------------------------------------------------------------------------

bool create_checkpoint(const std::optional<std::string>& requested) {
    std::string error;
    if (!supported(&error)) {
        xsql::set_vtab_error("checkpoints: " + error);
        return false;
    }
    auto& s = store();
    settle_pending(s, "(outside idasql statements)");
    std::string label;
    if (requested) {
        label = *requested;
        if (label.empty()) {
            xsql::set_vtab_error("checkpoints: label must not be empty (omit it for an automatic one)");
            return false;
        }
        if (label.rfind(kAutoPrefix, 0) == 0) {
            xsql::set_vtab_error(std::string("checkpoints: labels starting with '") + kAutoPrefix +
                                 "' are reserved for auto_checkpoint");
            return false;
        }
    } else {
        label = "checkpoint " + std::to_string(s.next_seq);
        while (label_taken(s, label))
            label += "'";
    }
    if (label_taken(s, label)) {
        xsql::set_vtab_error("checkpoints: checkpoint '" + label + "' already exists");
        return false;
    }
    if (!create_point(label)) {
        xsql::set_vtab_error("checkpoints: IDA refused to create an undo point "
                             "(undo disabled? see UNDO_MAXSIZE / UNDO_DEPTH in ida.cfg)");
        return false;
    }
    CheckpointRow row;
    row.seq = s.next_seq++;
    row.label = label;
    row.created_at = now_iso();
    row.kind = "user";
    row.state = kStateLive;
    row.mark = write_epoch();
    s.live.push_back(std::move(row));
    s.redo.clear();  // a new undo point ends IDA's redo branch
    s.changes_mark = -1;
    return true;
}

// Undo back through live[idx], newer checkpoints included.
bool rollback_to(size_t idx) {
    std::string error;
    if (!supported(&error)) {
        xsql::set_vtab_error("checkpoints: " + error);
        return false;
    }
    auto& s = store();
    const std::string label = s.live[idx].label;
    const std::string target = undo_label(label);
    int64_t steps = 0;
    int64_t foreign = 0;
    bool reached = false;
    for (;;) {
        qstring lab;
        if (!ida_undo_label(&lab) || !perform_undo())
            break;
        ++steps;
        if (lab == target.c_str()) {
            reached = true;
            break;
        }
        if (!is_idasql_label(lab))
            ++foreign;
    }
    if (!reached) {
        // The label is idasql's, but IDA no longer has the point (history trimmed
        // by UNDO_MAXSIZE / UNDO_DEPTH, or undone outside idasql). IDA cannot list
        // its history, so that is only found by undoing: put everything back.
        for (int64_t i = 0; i < steps; ++i) {
            if (!perform_redo())
                break;
        }
        refresh_caches();
        xsql::set_vtab_error("checkpoints: '" + label +
                             "' is no longer in IDA's undo history (trimmed by UNDO_MAXSIZE / "
                             "UNDO_DEPTH, or undone outside idasql); the database was left as it was");
        return false;
    }

    // writes_since bookkeeping: remember what each rolled-back checkpoint held
    // (for redo), and stop counting the undone writes against older checkpoints.
    const int64_t now = write_epoch();
    for (size_t j = idx; j < s.live.size(); ++j) {
        const int64_t end = (j + 1 < s.live.size()) ? s.live[j + 1].mark : now;
        s.live[j].segment = end - s.live[j].mark;
    }
    const int64_t undone = now - s.live[idx].mark;
    for (size_t k = 0; k < idx; ++k)
        s.live[k].mark += undone;

    // Newest first onto the redo stack, so the target ends on top (redone first).
    for (size_t i = s.live.size(); i-- > idx;) {
        s.live[i].state = kStateUndone;
        s.redo.push_back(s.live[i]);
    }
    s.live.erase(s.live.begin() + static_cast<std::ptrdiff_t>(idx), s.live.end());
    s.pending.reset();  // undone with the rest
    s.last_rollback_steps = steps;
    s.last_rollback_foreign = foreign;
    refresh_caches();
    s.changes_mark = write_epoch();
    return true;
}

bool redo_safe(const Store& s) {
    return !s.redo.empty() && (s.changes_mark < 0 || write_epoch() == s.changes_mark);
}

// Redo the checkpoint on top of the redo stack: IDA's steps up to and including
// its own (foreign steps recorded between two checkpoints come back with it).
bool redo_next() {
    std::string error;
    if (!supported(&error)) {
        xsql::set_vtab_error("checkpoints: " + error);
        return false;
    }
    auto& s = store();
    if (!redo_safe(s)) {
        xsql::set_vtab_error(
            "checkpoints: the database was modified after the rollback; redoing now would "
            "re-apply the rolled-back changes and discard the newer ones (IDA does not end "
            "its redo branch on a programmatic write)");
        return false;
    }
    const std::string label = s.redo.back().label;
    const std::string want = undo_label(label);
    int64_t steps = 0;
    bool reached = false;
    for (;;) {
        qstring lab;
        if (!ida_redo_label(&lab) || !perform_redo())
            break;
        ++steps;
        if (lab == want.c_str()) {
            reached = true;
            break;
        }
    }
    if (!reached) {
        for (int64_t i = 0; i < steps; ++i) {
            if (!perform_undo())
                break;
        }
        refresh_caches();
        xsql::set_vtab_error("checkpoints: '" + label +
                             "' is no longer in IDA's redo history; the database was left as it was");
        return false;
    }
    refresh_caches();
    const int64_t now = write_epoch();
    CheckpointRow cp = s.redo.back();
    s.redo.pop_back();
    for (auto& older : s.live)
        older.mark -= cp.segment;
    cp.mark = now - cp.segment;
    cp.state = kStateLive;
    s.live.push_back(std::move(cp));
    s.changes_mark = s.redo.empty() ? -1 : now;
    return true;
}

// The row as it is now, or nullptr when the checkpoint is gone.
CheckpointRow* find_seq(Store& s, int64_t seq, bool* is_live, size_t* index) {
    for (size_t i = 0; i < s.live.size(); ++i) {
        if (s.live[i].seq == seq) {
            *is_live = true;
            *index = i;
            return &s.live[i];
        }
    }
    for (size_t i = 0; i < s.redo.size(); ++i) {
        if (s.redo[i].seq == seq) {
            *is_live = false;
            *index = i;
            return &s.redo[i];
        }
    }
    return nullptr;
}

void collect_rows(std::vector<CheckpointRow>& rows) {
    const auto& s = store();
    rows.clear();
    const int64_t now = write_epoch();
    for (const auto& cp : s.live) {
        rows.push_back(cp);
        rows.back().writes_since = now - cp.mark;
    }
    for (const auto& cp : s.redo) {
        rows.push_back(cp);
        rows.back().writes_since = 0;
    }
    std::sort(rows.begin(), rows.end(),
              [](const CheckpointRow& a, const CheckpointRow& b) { return a.seq < b.seq; });
}

bool set_state(CheckpointRow& row, xsql::FunctionArg value) {
    if (value.is_nochange())
        return true;
    const std::string wanted = value.is_null() ? std::string() : value.as_text();
    if (wanted != kStateLive && wanted != kStateUndone) {
        xsql::set_vtab_error("checkpoints: state must be 'live' or 'undone'");
        return false;
    }
    auto& s = store();
    settle_pending(s, "(outside idasql statements)");
    bool is_live = false;
    size_t index = 0;
    if (find_seq(s, row.seq, &is_live, &index) == nullptr) {
        xsql::set_vtab_error("checkpoints: checkpoint '" + row.label + "' no longer exists");
        return false;
    }
    if (wanted == kStateUndone) {
        // Already undone (e.g. by an older row of the same UPDATE): nothing to do.
        if (is_live && !rollback_to(index))
            return false;
    } else if (!is_live) {
        if (index + 1 != s.redo.size()) {
            xsql::set_vtab_error("checkpoints: redo one checkpoint at a time, oldest first; the next "
                                 "one to redo is '" + s.redo.back().label + "'");
            return false;
        }
        if (!redo_next())
            return false;
    }
    row.state = wanted;
    return true;
}

bool insert_checkpoint(int argc, xsql::FunctionArg* argv) {
    // Column order: seq, label, created_at, kind, writes_since, statement, state.
    for (int i = 0; i < argc; ++i) {
        if (i == 1 || argv[i].is_null())
            continue;
        if (i == 6 && argv[i].as_text() == kStateLive)
            continue;
        xsql::set_vtab_error("checkpoints: INSERT takes only a label "
                             "(INSERT INTO checkpoints(label) VALUES ('...'))");
        return false;
    }
    std::optional<std::string> label;
    if (argc > 1 && !argv[1].is_null())
        label = argv[1].as_text();
    return create_checkpoint(label);
}

// --------------------------------------------------------------------------
// auto_checkpoint
// --------------------------------------------------------------------------

void before_statement(const std::string& sql, xsql::Database* db) {
    if (++t_stmt_depth != 1)
        return;  // nested (from Python through `import idasql`): the outer statement owns it
    auto& s = store();
    if (!auto_checkpoint_enabled() || !supported(nullptr)) {
        // Turned off: a point left pending by the statement that turned it off
        // holds nothing of this statement's.
        settle_pending(s, "(outside idasql statements)");
        return;
    }
    if (references_checkpoints(sql))
        return;
    // Right after a rollback/redo with nothing written since, a new undo point
    // would end IDA's redo branch: keep it alive for reads. A DML statement ends
    // it anyway (a redo is refused after any write), so that one still gets its
    // checkpoint.
    qstring redo_lab;
    if (ida_redo_label(&redo_lab) && (s.changes_mark < 0 || write_epoch() == s.changes_mark) &&
        !is_dml_statement(sql, db))
        return;
    if (s.pending) {
        if (write_epoch() == s.pending->mark)
            return;  // still unused: reuse it
        settle_pending(s, "(outside idasql statements)");
    }
    CheckpointRow row;
    row.seq = s.next_seq;
    row.label = kAutoPrefix + std::to_string(row.seq);
    while (label_taken(s, row.label))
        row.label += "'";
    row.kind = "auto";
    row.state = kStateLive;
    if (!create_point(row.label))
        return;
    row.mark = write_epoch();
    ++s.next_seq;
    s.redo.clear();
    s.changes_mark = -1;
    s.pending = std::move(row);
}

void after_statement(const std::string& sql) {
    const bool top = t_stmt_depth == 1;
    if (t_stmt_depth > 0)
        --t_stmt_depth;
    auto& s = store();
    if (!top || !s.pending)
        return;
    if (write_epoch() == s.pending->mark) {
        // Unused. Kept for the next statement, unless this one turned auto mode off.
        if (!auto_checkpoint_enabled())
            s.pending.reset();
        return;
    }
    s.pending->created_at = now_iso();
    s.pending->statement = sql.size() > kStatementMax ? sql.substr(0, kStatementMax) + "..." : sql;
    s.live.push_back(*s.pending);
    s.pending.reset();
}

void hook_monitor() {
    auto& m = monitor();
    if (!m.hooked)
        m.hooked = hook_event_listener(HT_IDB, &m, nullptr);
}

void unhook_monitor() {
    auto& m = monitor();
    if (m.hooked) {
        unhook_event_listener(HT_IDB, &m);
        m.hooked = false;
    }
}

}  // namespace

// --------------------------------------------------------------------------
// Public
// --------------------------------------------------------------------------

ScopedDerivedWrites::ScopedDerivedWrites() { ++t_derived_depth; }
ScopedDerivedWrites::~ScopedDerivedWrites() { --t_derived_depth; }

StatementScope::StatementScope(const std::string& sql, xsql::Database* db) : sql_(sql) {
    before_statement(sql_, db);
}

StatementScope::~StatementScope() {
    finish();
}

void StatementScope::finish() {
    if (finished_)
        return;
    finished_ = true;
    after_statement(sql_);
}

int64_t write_epoch() {
    const auto& e = engines();
    int64_t vtab_writes = e.retired_writes;
    for (QueryEngine* engine : e.live)
        vtab_writes += static_cast<int64_t>(engine->database().vtab_write_count());
    return vtab_writes + monitor().events.load(std::memory_order_relaxed);
}

void attach_engine(QueryEngine* engine) {
    auto& e = engines();
    if (e.live.empty()) {
        // A new session: nothing to roll back to yet.
        store() = Store{};
        hook_monitor();
    }
    if (std::find(e.live.begin(), e.live.end(), engine) == e.live.end())
        e.live.push_back(engine);
}

void detach_engine(QueryEngine* engine) {
    auto& e = engines();
    const auto it = std::find(e.live.begin(), e.live.end(), engine);
    if (it == e.live.end())
        return;
    if (engine->database().is_open())
        e.retired_writes += static_cast<int64_t>(engine->database().vtab_write_count());
    e.live.erase(it);
    if (e.live.empty()) {
        unhook_monitor();
        store() = Store{};
    }
}

void retarget_engine(QueryEngine* from, QueryEngine* to) {
    for (auto& engine : engines().live) {
        if (engine == from)
            engine = to;
    }
}

CheckpointsRegistry::CheckpointsRegistry()
    : checkpoints(
          cached_table<CheckpointRow>("checkpoints")
              .no_shared_cache()
              .counts_as_write(false)  // a checkpoint is not a change to the database
              .estimate_rows([]() -> size_t { return store().live.size() + store().redo.size(); })
              .cache_builder([](std::vector<CheckpointRow>& rows) { collect_rows(rows); })
              .column_int64("seq", [](const CheckpointRow& r) -> int64_t { return r.seq; })
              .column_text("label", [](const CheckpointRow& r) -> std::string { return r.label; })
              .column_text("created_at", [](const CheckpointRow& r) -> std::string { return r.created_at; })
              .column_text("kind", [](const CheckpointRow& r) -> std::string { return r.kind; })
              .column_int64("writes_since", [](const CheckpointRow& r) -> int64_t { return r.writes_since; })
              .column_text_nullable("statement",
                                    [](const CheckpointRow& r) -> std::optional<std::string> {
                                        return r.statement;
                                    })
              .column_text_rw("state", [](const CheckpointRow& r) -> std::string { return r.state; },
                              set_state)
              .rowid([](const CheckpointRow& r) -> int64_t { return r.seq; })
              .row_lookup([](CheckpointRow& row, int64_t seq) -> bool {
                  std::vector<CheckpointRow> rows;
                  collect_rows(rows);
                  for (auto& r : rows) {
                      if (r.seq == seq) {
                          row = std::move(r);
                          return true;
                      }
                  }
                  return false;
              })
              .insertable(insert_checkpoint)
              .deletable([](CheckpointRow&) -> bool {
                  xsql::set_vtab_error(
                      "checkpoints: a checkpoint is an IDA undo point and cannot be dropped; "
                      "roll back with UPDATE checkpoints SET state='undone' WHERE label=...");
                  return false;
              })
              .build()),
      undo_state(
          cached_table<UndoStateRow>("undo_state")
              .no_shared_cache()
              .estimate_rows([]() -> size_t { return 1; })
              .cache_builder([](std::vector<UndoStateRow>& rows) {
                  rows.clear();
                  const auto& s = store();
                  UndoStateRow row;
                  qstring lab;
                  if (ida_undo_label(&lab))
                      row.next_undo_label = std::string(lab.c_str());
                  if (ida_redo_label(&lab))
                      row.next_redo_label = std::string(lab.c_str());
                  row.redo_safe = redo_safe(s) && row.next_redo_label ? 1 : 0;
                  row.last_rollback_steps = s.last_rollback_steps;
                  row.last_rollback_foreign = s.last_rollback_foreign;
                  rows.push_back(std::move(row));
              })
              .column_text_nullable("next_undo_label",
                                    [](const UndoStateRow& r) { return r.next_undo_label; })
              .column_text_nullable("next_redo_label",
                                    [](const UndoStateRow& r) { return r.next_redo_label; })
              .column_int("redo_safe", [](const UndoStateRow& r) { return r.redo_safe; })
              .column_int64("last_rollback_steps",
                            [](const UndoStateRow& r) -> int64_t { return r.last_rollback_steps; })
              .column_int64("last_rollback_foreign",
                            [](const UndoStateRow& r) -> int64_t { return r.last_rollback_foreign; })
              .build()) {}

void CheckpointsRegistry::register_all(xsql::Database& db) {
    db.register_cached_table("checkpoints", &checkpoints);
    db.create_table("checkpoints", "checkpoints");
    db.register_cached_table("undo_state", &undo_state);
    db.create_table("undo_state", "undo_state");
}

} // namespace checkpoints
} // namespace idasql
