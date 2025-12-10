/**
 * ida_vtable_v2.hpp - Live data virtual tables with UPDATE/DELETE support
 *
 * Key changes from v1:
 *   - No caching - all data fetched live from IDA
 *   - xUpdate support for DELETE/UPDATE operations
 *   - Undo point integration for safe modifications
 *
 * Design philosophy:
 *   - Tables return fresh data on every query
 *   - Modifications create undo points automatically
 *   - Policy-based caching can be added as an optional layer
 */

#pragma once

#include <sqlite3.h>
#include <string>
#include <vector>
#include <functional>
#include <cstring>
#include <sstream>

// IDA SDK for undo
#include <ida.hpp>
#include <undo.hpp>

namespace idasql {
namespace v2 {

// ============================================================================
// Column Types
// ============================================================================

enum class ColumnType {
    Integer,
    Text,
    Real,
    Blob
};

inline const char* column_type_sql(ColumnType t) {
    switch (t) {
        case ColumnType::Integer: return "INTEGER";
        case ColumnType::Text:    return "TEXT";
        case ColumnType::Real:    return "REAL";
        case ColumnType::Blob:    return "BLOB";
    }
    return "TEXT";
}

// ============================================================================
// Column Definition (Live)
// ============================================================================

struct LiveColumnDef {
    std::string name;
    ColumnType type;
    bool writable;  // Can this column be updated?

    // Getter: Fetch value at row index (called on every query)
    std::function<void(sqlite3_context*, size_t)> get;

    // Setter: Update value at row index (for UPDATE support)
    std::function<bool(size_t, sqlite3_value*)> set;

    LiveColumnDef(const char* n, ColumnType t, bool w,
                  std::function<void(sqlite3_context*, size_t)> getter,
                  std::function<bool(size_t, sqlite3_value*)> setter = nullptr)
        : name(n), type(t), writable(w), get(std::move(getter)), set(std::move(setter)) {}
};

// ============================================================================
// Virtual Table Definition (Live)
// ============================================================================

struct LiveVTableDef {
    std::string name;

    // Count function: Returns current row count (called fresh each time)
    std::function<size_t()> row_count;

    // Columns
    std::vector<LiveColumnDef> columns;

    // DELETE handler: Delete row at index, returns success
    std::function<bool(size_t)> delete_row;

    // Can rows be deleted?
    bool supports_delete = false;

    std::string schema() const {
        std::ostringstream ss;
        ss << "CREATE TABLE " << name << "(";
        for (size_t i = 0; i < columns.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << columns[i].name << " " << column_type_sql(columns[i].type);
        }
        ss << ")";
        return ss.str();
    }
};

// ============================================================================
// SQLite Virtual Table Implementation (Live)
// ============================================================================

struct LiveVtab {
    sqlite3_vtab base;
    const LiveVTableDef* def;
};

struct LiveCursor {
    sqlite3_vtab_cursor base;
    size_t idx;
    size_t total;  // Cached at filter time for iteration
    const LiveVTableDef* def;
};

// xConnect/xCreate
inline int live_vtab_connect(sqlite3* db, void* pAux, int, const char* const*,
                              sqlite3_vtab** ppVtab, char**) {
    const LiveVTableDef* def = static_cast<const LiveVTableDef*>(pAux);

    int rc = sqlite3_declare_vtab(db, def->schema().c_str());
    if (rc != SQLITE_OK) return rc;

    auto* vtab = new LiveVtab();
    memset(&vtab->base, 0, sizeof(vtab->base));
    vtab->def = def;
    *ppVtab = &vtab->base;
    return SQLITE_OK;
}

// xDisconnect/xDestroy
inline int live_vtab_disconnect(sqlite3_vtab* pVtab) {
    delete reinterpret_cast<LiveVtab*>(pVtab);
    return SQLITE_OK;
}

// xOpen
inline int live_vtab_open(sqlite3_vtab* pVtab, sqlite3_vtab_cursor** ppCursor) {
    auto* vtab = reinterpret_cast<LiveVtab*>(pVtab);
    auto* cursor = new LiveCursor();
    memset(&cursor->base, 0, sizeof(cursor->base));
    cursor->idx = 0;
    cursor->total = 0;  // Will be set in xFilter
    cursor->def = vtab->def;
    *ppCursor = &cursor->base;
    return SQLITE_OK;
}

// xClose
inline int live_vtab_close(sqlite3_vtab_cursor* pCursor) {
    delete reinterpret_cast<LiveCursor*>(pCursor);
    return SQLITE_OK;
}

// xNext
inline int live_vtab_next(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<LiveCursor*>(pCursor);
    cursor->idx++;
    return SQLITE_OK;
}

// xEof
inline int live_vtab_eof(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<LiveCursor*>(pCursor);
    return cursor->idx >= cursor->total;
}

// xColumn - fetches LIVE data each time
inline int live_vtab_column(sqlite3_vtab_cursor* pCursor, sqlite3_context* ctx, int col) {
    auto* cursor = reinterpret_cast<LiveCursor*>(pCursor);
    if (col < 0 || static_cast<size_t>(col) >= cursor->def->columns.size()) {
        sqlite3_result_null(ctx);
        return SQLITE_OK;
    }
    // LIVE: Fetch fresh data from IDA
    cursor->def->columns[col].get(ctx, cursor->idx);
    return SQLITE_OK;
}

// xRowid
inline int live_vtab_rowid(sqlite3_vtab_cursor* pCursor, sqlite3_int64* pRowid) {
    auto* cursor = reinterpret_cast<LiveCursor*>(pCursor);
    *pRowid = static_cast<sqlite3_int64>(cursor->idx);
    return SQLITE_OK;
}

// xFilter - get fresh count for iteration
inline int live_vtab_filter(sqlite3_vtab_cursor* pCursor, int, const char*, int, sqlite3_value**) {
    auto* cursor = reinterpret_cast<LiveCursor*>(pCursor);
    cursor->idx = 0;
    // LIVE: Get fresh count from IDA
    cursor->total = cursor->def->row_count();
    return SQLITE_OK;
}

// xBestIndex
inline int live_vtab_best_index(sqlite3_vtab* pVtab, sqlite3_index_info* pInfo) {
    auto* vtab = reinterpret_cast<LiveVtab*>(pVtab);
    // LIVE: Get fresh count for cost estimation
    size_t count = vtab->def->row_count();
    pInfo->estimatedCost = static_cast<double>(count);
    pInfo->estimatedRows = count;
    return SQLITE_OK;
}

// xUpdate - handles INSERT, UPDATE, DELETE
inline int live_vtab_update(sqlite3_vtab* pVtab, int argc, sqlite3_value** argv, sqlite3_int64* pRowid) {
    auto* vtab = reinterpret_cast<LiveVtab*>(pVtab);
    const LiveVTableDef* def = vtab->def;

    // argc == 1: DELETE
    if (argc == 1 && sqlite3_value_type(argv[0]) != SQLITE_NULL) {
        if (!def->supports_delete || !def->delete_row) {
            return SQLITE_READONLY;
        }

        size_t rowid = static_cast<size_t>(sqlite3_value_int64(argv[0]));

        // Create undo point before deletion
        std::string undo_desc = "IDASQL DELETE FROM " + def->name;
        create_undo_point((const uchar*)undo_desc.c_str(), undo_desc.size());

        if (!def->delete_row(rowid)) {
            return SQLITE_ERROR;
        }
        return SQLITE_OK;
    }

    // argc > 1, argv[0] != NULL: UPDATE
    if (argc > 1 && sqlite3_value_type(argv[0]) != SQLITE_NULL) {
        size_t old_rowid = static_cast<size_t>(sqlite3_value_int64(argv[0]));

        // Create undo point before update
        std::string undo_desc = "IDASQL UPDATE " + def->name;
        create_undo_point((const uchar*)undo_desc.c_str(), undo_desc.size());

        // argv[2..n] are the new column values
        for (size_t i = 2; i < static_cast<size_t>(argc) && (i - 2) < def->columns.size(); ++i) {
            size_t col_idx = i - 2;
            const auto& col = def->columns[col_idx];
            if (col.writable && col.set) {
                if (!col.set(old_rowid, argv[i])) {
                    return SQLITE_ERROR;
                }
            }
        }
        return SQLITE_OK;
    }

    // argc > 1, argv[0] == NULL: INSERT (not supported for IDA entities)
    return SQLITE_READONLY;
}

// Create module with xUpdate support
inline sqlite3_module create_live_module() {
    sqlite3_module mod = {};
    mod.iVersion = 0;
    mod.xCreate = live_vtab_connect;
    mod.xConnect = live_vtab_connect;
    mod.xBestIndex = live_vtab_best_index;
    mod.xDisconnect = live_vtab_disconnect;
    mod.xDestroy = live_vtab_disconnect;
    mod.xOpen = live_vtab_open;
    mod.xClose = live_vtab_close;
    mod.xFilter = live_vtab_filter;
    mod.xNext = live_vtab_next;
    mod.xEof = live_vtab_eof;
    mod.xColumn = live_vtab_column;
    mod.xRowid = live_vtab_rowid;
    mod.xUpdate = live_vtab_update;  // Enable UPDATE/DELETE
    return mod;
}

inline sqlite3_module& get_live_module() {
    static sqlite3_module mod = create_live_module();
    return mod;
}

// ============================================================================
// Registration
// ============================================================================

inline bool register_live_vtable(sqlite3* db, const char* module_name, const LiveVTableDef* def) {
    int rc = sqlite3_create_module_v2(db, module_name, &get_live_module(),
                                       const_cast<LiveVTableDef*>(def), nullptr);
    return rc == SQLITE_OK;
}

inline bool create_live_vtable(sqlite3* db, const char* table_name, const char* module_name) {
    std::string sql = "CREATE VIRTUAL TABLE " + std::string(table_name) +
                      " USING " + std::string(module_name) + ";";
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

// ============================================================================
// Builder Pattern (Live)
// ============================================================================

class LiveVTableBuilder {
    LiveVTableDef def_;
public:
    explicit LiveVTableBuilder(const char* name) {
        def_.name = name;
        def_.supports_delete = false;
    }

    LiveVTableBuilder& count(std::function<size_t()> fn) {
        def_.row_count = std::move(fn);
        return *this;
    }

    // Read-only integer column
    LiveVTableBuilder& column_int64(const char* name, std::function<int64_t(size_t)> getter) {
        def_.columns.emplace_back(name, ColumnType::Integer, false,
            [getter = std::move(getter)](sqlite3_context* ctx, size_t idx) {
                sqlite3_result_int64(ctx, getter(idx));
            },
            nullptr);
        return *this;
    }

    // Writable integer column
    LiveVTableBuilder& column_int64_rw(const char* name,
                                        std::function<int64_t(size_t)> getter,
                                        std::function<bool(size_t, int64_t)> setter) {
        def_.columns.emplace_back(name, ColumnType::Integer, true,
            [getter = std::move(getter)](sqlite3_context* ctx, size_t idx) {
                sqlite3_result_int64(ctx, getter(idx));
            },
            [setter = std::move(setter)](size_t idx, sqlite3_value* val) -> bool {
                return setter(idx, sqlite3_value_int64(val));
            });
        return *this;
    }

    // Read-only text column
    LiveVTableBuilder& column_text(const char* name, std::function<std::string(size_t)> getter) {
        def_.columns.emplace_back(name, ColumnType::Text, false,
            [getter = std::move(getter)](sqlite3_context* ctx, size_t idx) {
                std::string val = getter(idx);
                sqlite3_result_text(ctx, val.c_str(), -1, SQLITE_TRANSIENT);
            },
            nullptr);
        return *this;
    }

    // Writable text column
    LiveVTableBuilder& column_text_rw(const char* name,
                                       std::function<std::string(size_t)> getter,
                                       std::function<bool(size_t, const char*)> setter) {
        def_.columns.emplace_back(name, ColumnType::Text, true,
            [getter = std::move(getter)](sqlite3_context* ctx, size_t idx) {
                std::string val = getter(idx);
                sqlite3_result_text(ctx, val.c_str(), -1, SQLITE_TRANSIENT);
            },
            [setter = std::move(setter)](size_t idx, sqlite3_value* val) -> bool {
                const char* text = (const char*)sqlite3_value_text(val);
                return setter(idx, text ? text : "");
            });
        return *this;
    }

    // Read-only int column
    LiveVTableBuilder& column_int(const char* name, std::function<int(size_t)> getter) {
        def_.columns.emplace_back(name, ColumnType::Integer, false,
            [getter = std::move(getter)](sqlite3_context* ctx, size_t idx) {
                sqlite3_result_int(ctx, getter(idx));
            },
            nullptr);
        return *this;
    }

    // Enable DELETE support
    LiveVTableBuilder& deletable(std::function<bool(size_t)> delete_fn) {
        def_.supports_delete = true;
        def_.delete_row = std::move(delete_fn);
        return *this;
    }

    LiveVTableDef build() { return std::move(def_); }
};

inline LiveVTableBuilder live_table(const char* name) {
    return LiveVTableBuilder(name);
}

} // namespace v2
} // namespace idasql
