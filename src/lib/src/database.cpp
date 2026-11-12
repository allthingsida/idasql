// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include <idasql/database.hpp>

#include <idasql/platform.hpp>

#include "ida_headers.hpp"
#include "checkpoints.hpp"
#include "idapython_runs.hpp"
#include "instances_table.hpp"
#include "ui_actions.hpp"
#include "python_bridge.hpp"

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

#include <algorithm>
#include <string>
#include <vector>

namespace idasql {

QueryEngine::QueryEngine() {
    init();
}

QueryEngine::~QueryEngine() {
    python_bridge::detach(this);
    checkpoints::detach_engine(this);
}

QueryEngine::QueryEngine(QueryEngine&& other) noexcept
    : db_(std::move(other.db_)),
      error_(std::move(other.error_)),
      core_(std::move(other.core_)),
      metadata_(std::move(other.metadata_)),
      extended_(std::move(other.extended_)),
      types_(std::move(other.types_)),
      debugger_(std::move(other.debugger_)),
      decompiler_(std::move(other.decompiler_)),
      checkpoints_(std::move(other.checkpoints_)),
      idapython_runs_(std::move(other.idapython_runs_)),
      instances_(std::move(other.instances_)),
      ui_actions_(std::move(other.ui_actions_)) {
    python_bridge::retarget(&other, this);
    checkpoints::retarget_engine(&other, this);
}

QueryEngine& QueryEngine::operator=(QueryEngine&& other) noexcept {
    if (this != &other) {
        python_bridge::detach(this);
        checkpoints::detach_engine(this);
        db_ = std::move(other.db_);
        error_ = std::move(other.error_);
        core_ = std::move(other.core_);
        metadata_ = std::move(other.metadata_);
        extended_ = std::move(other.extended_);
        types_ = std::move(other.types_);
        debugger_ = std::move(other.debugger_);
        decompiler_ = std::move(other.decompiler_);
        checkpoints_ = std::move(other.checkpoints_);
        idapython_runs_ = std::move(other.idapython_runs_);
        instances_ = std::move(other.instances_);
        ui_actions_ = std::move(other.ui_actions_);
        python_bridge::retarget(&other, this);
        checkpoints::retarget_engine(&other, this);
    }
    return *this;
}

QueryResult QueryEngine::query(const char* sql) {
    xsql::QueryOptions options;
    options.timeout_ms = runtime_settings().query_timeout_ms();
    return run_query(sql, nullptr, options);
}

QueryResult QueryEngine::query(const char* sql, const xsql::QueryOptions& options) {
    return run_query(sql, nullptr, options);
}

QueryResult QueryEngine::query(const char* sql, const std::vector<xsql::QueryParam>& params) {
    xsql::QueryOptions options;
    options.timeout_ms = runtime_settings().query_timeout_ms();
    return run_query(sql, &params, options);
}

QueryResult QueryEngine::query(const char* sql, const std::vector<xsql::QueryParam>& params,
                               const xsql::QueryOptions& options) {
    return run_query(sql, &params, options);
}

QueryResult QueryEngine::run_query(const char* sql, const std::vector<xsql::QueryParam>* params,
                                   const xsql::QueryOptions& options) {
    QueryResult result;

    if (!db_.is_open()) {
        result.error = "QueryEngine not initialized";
        return result;
    }

    if (handle_runtime_pragma(sql, result)) {
        if (params != nullptr && !params->empty() && result.success) {
            result = make_pragma_error("runtime PRAGMAs take no bound parameters");
        }
        error_ = result.success ? "" : result.error;
        return result;
    }

    const xsql::QueryOptions& effective_options = options;

    xsql::clear_vtab_error();
    checkpoints::StatementScope statement_scope(sql ? sql : "", &db_);
    xsql::Result raw = params != nullptr
        ? db_.query(sql, *params, effective_options)
        : db_.query(sql, effective_options);
    statement_scope.finish();
    std::string generator_error = xsql::get_vtab_error();
    xsql::clear_vtab_error();
    if (!generator_error.empty()) {
        raw.rows.clear();
        const bool cancelled =
            effective_options.should_cancel && effective_options.should_cancel();
        if (cancelled) {
            if (!raw.columns.empty()) {
                raw.error.clear();
                raw.partial = true;
                raw.warnings.push_back(
                    "query cancelled; returning no rows from the interrupted scan");
            } else {
                raw.error = "Query cancelled";
            }
        } else if (effective_options.timeout_ms > 0
                   && raw.elapsed_ms >= effective_options.timeout_ms) {
            raw.timed_out = true;
            if (!raw.columns.empty()) {
                raw.error.clear();
                raw.partial = true;
                raw.warnings.push_back(
                    "query timed out; returning no rows from the interrupted scan");
            } else {
                raw.error = "Query timed out";
            }
        } else if (raw.error.empty()) {
            raw.error = std::move(generator_error);
        }
    }
    if (!raw.error.empty()) {
        raw.partial = false;
    }
    result.columns = std::move(raw.columns);
    result.rows.reserve(raw.rows.size());
    for (auto& raw_row : raw.rows) {
        Row row;
        row.values = std::move(raw_row.values);
        row.nulls = std::move(raw_row.nulls);
        row.types = std::move(raw_row.types);
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

    checkpoints::StatementScope statement_scope(sql ? sql : "", &db_);
    xsql::Status rc = db_.exec(sql);
    statement_scope.finish();
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

        checkpoints::StatementScope statement_scope(sql, &db_);
        const bool ok = db_.execute_script(sql, results, error);
        statement_scope.finish();
        if (!ok) {
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

    if (request.key == "timeout_push" || request.key == "timeout_pop") {
        auto& settings = runtime_settings();
        const auto reply = xsql::runtime::handle_common_runtime_pragma(
            request, "idasql", settings.common_settings());
        out = reply.success
            ? make_pragma_result(reply.name, reply.value)
            : make_pragma_error(reply.error);
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
    std::vector<std::string> words;
    {
        std::string word;
        auto flush = [&] {
            if (!word.empty()) words.push_back(word);
            word.clear();
        };
        for (size_t i = 0; i < lower.size(); ++i) {
            const char c = lower[i];
            if (c == '\'') {
                flush();
                for (++i; i < lower.size(); ++i) {
                    if (lower[i] == '\'' && (i + 1 >= lower.size() || lower[i + 1] != '\'')) break;
                    if (lower[i] == '\'') ++i;
                }
            } else if (c == '-' && i + 1 < lower.size() && lower[i + 1] == '-') {
                flush();
                while (i < lower.size() && lower[i] != '\n') ++i;
            } else if (c == '/' && i + 1 < lower.size() && lower[i + 1] == '*') {
                flush();
                const size_t end = lower.find("*/", i + 2);
                i = end == std::string::npos ? lower.size() : end + 1;
            } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
                word.push_back(c);
            } else {
                flush();
            }
        }
        flush();
    }
    auto any_word = [&words](auto pred) { return std::any_of(words.begin(), words.end(), pred); };
    const bool touches_decompiler_table = any_word([](const std::string& w) {
        return w.rfind("ctree", 0) == 0 || w.rfind("pseudocode", 0) == 0;
    });
    const bool has_func_filter = any_word([](const std::string& w) { return w == "func_addr"; });

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

    decompiler_ = std::make_unique<decompiler::DecompilerRegistry>();
    decompiler_->register_all(db_);

    functions::register_sql_functions(db_);

    checkpoints_ = std::make_unique<checkpoints::CheckpointsRegistry>();
    checkpoints_->register_all(db_);
    checkpoints::attach_engine(this);

    idapython_runs_ = std::make_unique<idapython_runs::Registry>();
    idapython_runs_->register_all(db_);

    instances_ = std::make_unique<instances::TableRegistry>();
    instances_->register_all(db_);

    ui_actions_ = std::make_unique<ui_actions::Registry>();
    ui_actions_->register_all(db_);

    python_bridge::attach(this);

    search::register_byte_search(db_);
    deep_links::register_deep_links(db_);

    ui_context::register_ui_context_sql_functions(db_);
}

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

}
