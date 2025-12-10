/**
 * ida_vtable_policy.hpp - Policy and configuration system for IDASQL
 *
 * This allows passing options to virtual tables via:
 *   1. Module arguments: CREATE VIRTUAL TABLE funcs USING ida_funcs(cache=off)
 *   2. Global configuration via SQL function: SELECT idasql_config('cache', 'off')
 *   3. Per-session settings stored in a config table
 *
 * Supported policies:
 *   - cache: 'on'|'off' - Enable/disable result caching
 *   - undo: 'on'|'off' - Create undo points for modifications
 *   - batch: 'on'|'off' - Batch multiple operations into one undo point
 */

#pragma once

#include <sqlite3.h>
#include <string>
#include <unordered_map>
#include <mutex>

namespace idasql {
namespace policy {

// ============================================================================
// Policy Values
// ============================================================================

enum class CachePolicy {
    Off,        // No caching, always fetch live data
    Session,    // Cache for the duration of SQL statement
    Persistent  // Cache until invalidated
};

enum class UndoPolicy {
    Off,        // No undo points
    PerRow,     // Undo point per row modification
    PerStatement // One undo point per SQL statement (recommended)
};

// ============================================================================
// Global Configuration
// ============================================================================

struct IdasqlConfig {
    CachePolicy cache = CachePolicy::Off;          // Default: live data
    UndoPolicy undo = UndoPolicy::PerStatement;    // Default: one undo per statement
    bool batch_operations = true;                   // Batch ops under one undo
    bool verbose = false;                           // Debug output

    static IdasqlConfig& instance() {
        static IdasqlConfig config;
        return config;
    }

private:
    IdasqlConfig() = default;
};

// ============================================================================
// Configuration Parsing from Module Arguments
// ============================================================================

struct ModuleOptions {
    CachePolicy cache = CachePolicy::Off;
    UndoPolicy undo = UndoPolicy::PerStatement;

    // Parse from CREATE VIRTUAL TABLE ... USING module(key=value, ...)
    static ModuleOptions parse(int argc, const char* const* argv) {
        ModuleOptions opts;

        // argv[0] = module name, argv[1] = database name, argv[2] = table name
        // argv[3..] = additional arguments
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            size_t eq = arg.find('=');
            if (eq == std::string::npos) continue;

            std::string key = arg.substr(0, eq);
            std::string val = arg.substr(eq + 1);

            // Trim quotes if present
            if (val.size() >= 2 && val.front() == '\'' && val.back() == '\'') {
                val = val.substr(1, val.size() - 2);
            }

            if (key == "cache") {
                if (val == "off" || val == "0" || val == "false") {
                    opts.cache = CachePolicy::Off;
                } else if (val == "session") {
                    opts.cache = CachePolicy::Session;
                } else if (val == "on" || val == "1" || val == "true" || val == "persistent") {
                    opts.cache = CachePolicy::Persistent;
                }
            } else if (key == "undo") {
                if (val == "off" || val == "0" || val == "false") {
                    opts.undo = UndoPolicy::Off;
                } else if (val == "row" || val == "perrow") {
                    opts.undo = UndoPolicy::PerRow;
                } else if (val == "on" || val == "1" || val == "true" || val == "statement") {
                    opts.undo = UndoPolicy::PerStatement;
                }
            }
        }

        return opts;
    }
};

// ============================================================================
// SQL Configuration Function
// ============================================================================

// Register: SELECT idasql_config('key', 'value') to set
// Register: SELECT idasql_config('key') to get
inline void idasql_config_func(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "idasql_config requires at least 1 argument", -1);
        return;
    }

    const char* key = (const char*)sqlite3_value_text(argv[0]);
    if (!key) {
        sqlite3_result_null(ctx);
        return;
    }

    auto& config = IdasqlConfig::instance();

    // Setter mode
    if (argc >= 2) {
        const char* val = (const char*)sqlite3_value_text(argv[1]);
        if (!val) val = "";

        if (strcmp(key, "cache") == 0) {
            if (strcmp(val, "off") == 0 || strcmp(val, "0") == 0) {
                config.cache = CachePolicy::Off;
            } else if (strcmp(val, "session") == 0) {
                config.cache = CachePolicy::Session;
            } else {
                config.cache = CachePolicy::Persistent;
            }
            sqlite3_result_text(ctx, val, -1, SQLITE_TRANSIENT);
        } else if (strcmp(key, "undo") == 0) {
            if (strcmp(val, "off") == 0 || strcmp(val, "0") == 0) {
                config.undo = UndoPolicy::Off;
            } else if (strcmp(val, "row") == 0) {
                config.undo = UndoPolicy::PerRow;
            } else {
                config.undo = UndoPolicy::PerStatement;
            }
            sqlite3_result_text(ctx, val, -1, SQLITE_TRANSIENT);
        } else if (strcmp(key, "verbose") == 0) {
            config.verbose = (strcmp(val, "on") == 0 || strcmp(val, "1") == 0);
            sqlite3_result_int(ctx, config.verbose ? 1 : 0);
        } else {
            sqlite3_result_error(ctx, "Unknown config key", -1);
        }
        return;
    }

    // Getter mode
    if (strcmp(key, "cache") == 0) {
        const char* val = "off";
        if (config.cache == CachePolicy::Session) val = "session";
        else if (config.cache == CachePolicy::Persistent) val = "persistent";
        sqlite3_result_text(ctx, val, -1, SQLITE_STATIC);
    } else if (strcmp(key, "undo") == 0) {
        const char* val = "statement";
        if (config.undo == UndoPolicy::Off) val = "off";
        else if (config.undo == UndoPolicy::PerRow) val = "row";
        sqlite3_result_text(ctx, val, -1, SQLITE_STATIC);
    } else if (strcmp(key, "verbose") == 0) {
        sqlite3_result_int(ctx, config.verbose ? 1 : 0);
    } else {
        sqlite3_result_null(ctx);
    }
}

// Register the config function with SQLite
inline bool register_config_function(sqlite3* db) {
    return sqlite3_create_function(db, "idasql_config", -1,
                                    SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                    nullptr, idasql_config_func,
                                    nullptr, nullptr) == SQLITE_OK;
}

// ============================================================================
// Configuration Table (Alternative approach)
// ============================================================================

inline bool create_config_table(sqlite3* db) {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS idasql_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            description TEXT
        );

        INSERT OR IGNORE INTO idasql_settings VALUES
            ('cache', 'off', 'Cache policy: off, session, persistent'),
            ('undo', 'statement', 'Undo policy: off, row, statement'),
            ('verbose', '0', 'Debug output: 0 or 1');
    )";

    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (err) {
        sqlite3_free(err);
        return false;
    }
    return rc == SQLITE_OK;
}

// Sync config from table to memory
inline bool load_config_from_table(sqlite3* db) {
    auto& config = IdasqlConfig::instance();

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, "SELECT key, value FROM idasql_settings", -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* key = (const char*)sqlite3_column_text(stmt, 0);
        const char* val = (const char*)sqlite3_column_text(stmt, 1);
        if (!key || !val) continue;

        if (strcmp(key, "cache") == 0) {
            if (strcmp(val, "off") == 0) config.cache = CachePolicy::Off;
            else if (strcmp(val, "session") == 0) config.cache = CachePolicy::Session;
            else config.cache = CachePolicy::Persistent;
        } else if (strcmp(key, "undo") == 0) {
            if (strcmp(val, "off") == 0) config.undo = UndoPolicy::Off;
            else if (strcmp(val, "row") == 0) config.undo = UndoPolicy::PerRow;
            else config.undo = UndoPolicy::PerStatement;
        } else if (strcmp(key, "verbose") == 0) {
            config.verbose = (strcmp(val, "1") == 0);
        }
    }

    sqlite3_finalize(stmt);
    return true;
}

// ============================================================================
// Initialization Helper
// ============================================================================

inline bool init_policy_system(sqlite3* db) {
    bool ok = true;
    ok = ok && register_config_function(db);
    ok = ok && create_config_table(db);
    ok = ok && load_config_from_table(db);
    return ok;
}

} // namespace policy
} // namespace idasql
