// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include <idasql/database.hpp>

#include <idasql/platform.hpp>

#include "ida_headers.hpp"

// Private headers for registry implementations
#include "core.hpp"
#include "entities_ext.hpp"
#include "entities_dbg.hpp"
#include "entities_search.hpp"
#include "functions.hpp"
#include "decompiler.hpp"
#include "types.hpp"
#include "search_bytes.hpp"
#include "metadata.hpp"
#include <idasql/ui_context_provider.hpp>

namespace idasql {

// ============================================================================
// QueryEngine
// ============================================================================

QueryEngine::QueryEngine() {
    init();
}

QueryEngine::~QueryEngine() = default;

// Defined here (not inline in the header) so the registry member types are
// complete for the move of their std::unique_ptr members.
QueryEngine::QueryEngine(QueryEngine&&) noexcept = default;
QueryEngine& QueryEngine::operator=(QueryEngine&&) noexcept = default;

QueryResult QueryEngine::query(const char* sql) {
    QueryResult result;

    if (!db_.is_open()) {
        result.error = "QueryEngine not initialized";
        return result;
    }

    if (handle_runtime_pragma(sql, result)) {
        error_ = result.success ? "" : result.error;
        return result;
    }

    xsql::QueryOptions options;
    options.timeout_ms = runtime_settings().query_timeout_ms();
    xsql::Result raw = db_.query(sql, options);
    result.columns = std::move(raw.columns);
    result.rows.reserve(raw.rows.size());
    for (auto& raw_row : raw.rows) {
        Row row;
        row.values = std::move(raw_row.values);
        row.nulls = std::move(raw_row.nulls);  // carry the SQL-NULL mask through
        result.rows.push_back(std::move(row));
    }
    result.error = std::move(raw.error);
    result.warnings = std::move(raw.warnings);
    result.timed_out = raw.timed_out;
    result.partial = raw.partial;
    result.elapsed_ms = raw.elapsed_ms;
    append_query_hints(sql ? std::string(sql) : std::string(), result);
    result.success = result.error.empty();
    error_ = result.success ? "" : result.error;

    return result;
}

xsql::Status QueryEngine::exec(const char* sql) {
    if (!db_.is_open()) {
        error_ = "QueryEngine not initialized";
        return xsql::Status::error;
    }

    QueryResult pragma_result;
    if (handle_runtime_pragma(sql, pragma_result)) {
        error_ = pragma_result.success ? "" : pragma_result.error;
        return pragma_result.success ? xsql::Status::ok : xsql::Status::error;
    }

    xsql::Status rc = db_.exec(sql);
    error_ = db_.last_error();
    return rc;
}

bool QueryEngine::execute(const char* sql) {
    return xsql::is_ok(exec(sql));
}

bool QueryEngine::execute_script(const std::string& script,
                                  std::vector<xsql::StatementResult>& results,
                                  std::string& error) {
    if (!db_.is_open()) {
        error_ = "QueryEngine not initialized";
        error = error_;
        return false;
    }

    // Route each statement through the runtime-PRAGMA handler so scripts run via
    // `idasql -f setup.sql` honor `PRAGMA idasql.* = ...;` control statements the
    // same way single-statement query()/exec() do. Non-PRAGMA statements are
    // executed by the shared db_ script executor, preserving interleaving order.
    std::vector<std::string> statements;
    if (!xsql::collect_statements(script, statements, error)) {
        error_ = error;
        return false;
    }

    for (const auto& sql : statements) {
        QueryResult pragma_result;
        if (handle_runtime_pragma(sql.c_str(), pragma_result)) {
            if (!pragma_result.success) {
                error = pragma_result.error;
                error_ = error;
                return false;
            }
            continue;
        }

        if (!db_.execute_script(sql, results, error)) {
            error_ = error;
            return false;
        }
    }

    error.clear();
    error_.clear();
    return true;
}

bool QueryEngine::export_tables(const std::vector<std::string>& tables,
                                 const std::string& output_path,
                                 std::string& error) {
    if (!db_.is_open()) {
        error_ = "QueryEngine not initialized";
        error = error_;
        return false;
    }

    bool ok = db_.export_tables(tables, output_path, error);
    error_ = ok ? "" : error;
    return ok;
}

std::string QueryEngine::scalar(const char* sql) {
    auto result = query(sql);
    if (result.success && !result.empty()) {
        return result.rows[0].values[0];
    }
    return "";
}

QueryResult QueryEngine::make_pragma_result(const std::string& key, const std::string& value) {
    QueryResult result;
    result.columns = {"name", "value"};
    Row row;
    row.values = {key, value};
    result.rows.push_back(std::move(row));
    result.success = true;
    return result;
}

QueryResult QueryEngine::make_pragma_error(const std::string& error) {
    QueryResult result;
    result.success = false;
    result.error = error;
    return result;
}

bool QueryEngine::handle_runtime_pragma(const char* sql, QueryResult& out) {
    const auto request = xsql::runtime::parse_runtime_pragma(sql, "idasql");
    if (!request.matched) {
        return false;
    }

    auto& settings = runtime_settings();

    const auto common = xsql::runtime::handle_common_runtime_pragma(
        request, "idasql", settings.common_settings());
    if (common.handled) {
        out = common.success
            ? make_pragma_result(common.name, common.value)
            : make_pragma_error(common.error);
        return true;
    }

    if (request.key == "enable_idapython") {
        if (request.value.empty()) {
            out = make_pragma_result("enable_idapython", settings.enable_idapython() ? "1" : "0");
            return true;
        }
        bool enabled = false;
        if (!xsql::runtime::parse_bool_value(request.value, enabled)) {
            out = make_pragma_error("Invalid idasql.enable_idapython value");
            return true;
        }
        settings.set_enable_idapython(enabled);
        out = make_pragma_result("enable_idapython", settings.enable_idapython() ? "1" : "0");
        return true;
    }

    if (request.key == "idapython_output_max") {
        if (request.value.empty()) {
            out = make_pragma_result("idapython_output_max",
                                     std::to_string(settings.idapython_output_max()));
            return true;
        }
        int value = 0;
        if (!xsql::runtime::parse_int_value(request.value, value) || value < 0) {
            out = make_pragma_error(
                "Invalid idasql.idapython_output_max value (bytes; 0 = unbounded)");
            return true;
        }
        settings.set_idapython_output_max(static_cast<size_t>(value));
        out = make_pragma_result("idapython_output_max",
                                 std::to_string(settings.idapython_output_max()));
        return true;
    }

    out = make_pragma_error(xsql::runtime::unknown_runtime_pragma_error("idasql"));
    return true;
}

void QueryEngine::append_query_hints(const std::string& sql, QueryResult& result) const {
    if (!runtime_settings().hints_enabled()) {
        return;
    }

    const std::string lower = xsql::runtime::to_lower_copy(sql);
    const bool touches_decompiler_table =
        lower.find("ctree_lvars") != std::string::npos ||
        lower.find("ctree_call_args") != std::string::npos ||
        lower.find("ctree ") != std::string::npos ||
        lower.find("ctree\n") != std::string::npos ||
        lower.find("pseudocode") != std::string::npos;
    const bool has_func_filter = lower.find("func_addr") != std::string::npos;

    auto add_warning_once = [&result](const std::string& warning) {
        for (const auto& existing : result.warnings) {
            if (existing == warning) {
                return;
            }
        }
        result.warnings.push_back(warning);
    };

    if (touches_decompiler_table && !has_func_filter) {
        add_warning_once(
            "Decompiler tables are expensive without func_addr filtering; add WHERE func_addr = <addr> and LIMIT.");
    }
    if (result.timed_out && touches_decompiler_table) {
        add_warning_once(
            "Decompiler query timed out; resolve candidate functions first, then query ctree_* per function.");
    }
}

void QueryEngine::init() {
    // db_ auto-opens :memory: via xsql::Database constructor

    // Register all virtual tables
    core_ = std::make_unique<core::CoreRegistry>();
    core_->register_all(db_);

    metadata_ = std::make_unique<metadata::MetadataRegistry>();
    metadata_->register_all(db_);

    extended_ = std::make_unique<extended::ExtendedRegistry>();
    extended_->register_all(db_);

    types_ = std::make_unique<types::TypesRegistry>();
    types_->register_all(db_);

    debugger_ = std::make_unique<debugger::DebuggerRegistry>();
    debugger_->register_all(db_);

    // Decompiler registry - register_all() handles runtime Hex-Rays detection
    // Must be registered before SQL functions so hexrays_available() is set
    decompiler_ = std::make_unique<decompiler::DecompilerRegistry>();
    decompiler_->register_all(db_);

    functions::register_sql_functions(db_);
    search::register_byte_search(db_);

    // get_ui_context_json(): registered for every runtime. Returns live UI
    // state in the GUI plugin; a "not applicable" stub under idalib/CLI.
    ui_context::register_ui_context_sql_functions(db_);
}

// ============================================================================
// TIER 3: Free Functions - Quick one-liners
// ============================================================================

namespace detail {
    QueryEngine& global_engine() {
        static QueryEngine engine;
        return engine;
    }
}

QueryResult query(const char* sql) {
    return detail::global_engine().query(sql);
}

xsql::Status exec(const char* sql) {
    return detail::global_engine().exec(sql);
}

bool execute(const char* sql) {
    return detail::global_engine().execute(sql);
}

std::string scalar(const char* sql) {
    return detail::global_engine().scalar(sql);
}

} // namespace idasql
