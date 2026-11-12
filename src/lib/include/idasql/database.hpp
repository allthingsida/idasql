// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <idasql/platform.hpp>
#include <idasql/string_utils.hpp>

#include <xsql/database.hpp>
#include <xsql/json.hpp>
#include <xsql/script.hpp>
#include <idasql/runtime_settings.hpp>
#include <idasql/fwd.hpp>
#include <string>
#include <vector>
#include <memory>

#include <idasql/platform_undef.hpp>

namespace idasql {

struct Row {
    std::vector<std::string> values;
    std::vector<char> nulls;
    std::vector<char> types;

    const std::string& operator[](size_t i) const { return values[i]; }
    size_t size() const { return values.size(); }
    bool is_null(size_t i) const { return i < nulls.size() && nulls[i] != 0; }
    int type(size_t i) const { return i < types.size() ? types[i] : 0; }
};

struct QueryResult {
    std::vector<std::string> columns;
    std::vector<Row> rows;
    std::string error;
    std::vector<std::string> warnings;
    bool success = false;
    bool timed_out = false;
    bool partial = false;
    int elapsed_ms = 0;

    size_t row_count() const { return rows.size(); }
    size_t column_count() const { return columns.size(); }
    bool empty() const { return rows.empty(); }

    std::string scalar() const {
        return (!empty() && rows[0].size() > 0) ? rows[0][0] : "";
    }

    auto begin() { return rows.begin(); }
    auto end() { return rows.end(); }
    auto begin() const { return rows.begin(); }
    auto end() const { return rows.end(); }

    std::string to_string() const {
        if (!success) return error;
        if (empty()) return "(0 rows)";

        std::string result;
        for (size_t i = 0; i < columns.size(); ++i) {
            if (i > 0) result += " | ";
            result += columns[i];
        }
        result += "\n";
        for (size_t i = 0; i < columns.size(); ++i) {
            if (i > 0) result += "-+-";
            result += std::string(columns[i].size(), '-');
        }
        result += "\n";
        for (const auto& row : rows) {
            for (size_t i = 0; i < row.size(); ++i) {
                if (i > 0) result += " | ";
                result += row[i];
            }
            result += "\n";
        }
        result += "(" + std::to_string(row_count()) + " rows)";
        if (!warnings.empty()) {
            result += "\nWarnings:";
            for (const auto& warning : warnings) {
                result += "\n  - " + warning;
            }
        }
        if (timed_out) {
            result += "\n(timed out after " + std::to_string(elapsed_ms) + " ms)";
        }
        return result;
    }
};

class QueryEngine {
public:
    QueryEngine();
    ~QueryEngine();

    QueryEngine(QueryEngine&&) noexcept;
    QueryEngine& operator=(QueryEngine&&) noexcept;

    QueryEngine(const QueryEngine&) = delete;
    QueryEngine& operator=(const QueryEngine&) = delete;

    QueryResult query(const std::string& sql) { return query(sql.c_str()); }
    QueryResult query(const std::string& sql, const xsql::QueryOptions& options) {
        return query(sql.c_str(), options);
    }
    QueryResult query(const char* sql);
    QueryResult query(const char* sql, const xsql::QueryOptions& options);

    QueryResult query(const char* sql, const std::vector<xsql::QueryParam>& params);
    QueryResult query(const char* sql, const std::vector<xsql::QueryParam>& params,
                      const xsql::QueryOptions& options);

    xsql::Status exec(const char* sql);

    bool execute(const char* sql);

    bool execute_script(const std::string& script,
                        std::vector<xsql::StatementResult>& results,
                        std::string& error);

    bool export_tables(const std::vector<std::string>& tables,
                       const std::string& output_path,
                       std::string& error);

    std::string scalar(const std::string& sql) { return scalar(sql.c_str()); }
    std::string scalar(const char* sql);

    const std::string& error() const { return error_; }

    bool is_valid() const { return db_.is_open(); }

    xsql::Database& database() { return db_; }
    const xsql::Database& database() const { return db_; }

private:
    static QueryResult make_pragma_result(const std::string& key, const std::string& value);
    static QueryResult make_pragma_error(const std::string& error);
    QueryResult run_query(const char* sql, const std::vector<xsql::QueryParam>* params,
                          const xsql::QueryOptions& options);
    bool handle_runtime_pragma(const char* sql, QueryResult& out);
    void append_query_hints(const std::string& sql, QueryResult& result) const;

    xsql::Database db_;
    std::string error_;

    std::unique_ptr<core::CoreRegistry> core_;
    std::unique_ptr<metadata::MetadataRegistry> metadata_;
    std::unique_ptr<extended::ExtendedRegistry> extended_;
    std::unique_ptr<types::TypesRegistry> types_;
    std::unique_ptr<debugger::DebuggerRegistry> debugger_;
    std::unique_ptr<decompiler::DecompilerRegistry> decompiler_;
    std::unique_ptr<checkpoints::CheckpointsRegistry> checkpoints_;
    std::unique_ptr<idapython_runs::Registry> idapython_runs_;
    std::unique_ptr<instances::TableRegistry> instances_;
    std::unique_ptr<ui_actions::Registry> ui_actions_;

    void init();
};

enum class OpenOutcome {
    Ok,
    Failed,
    UpgradedReopenRequired
};

namespace rescue { class Guard; }

class Session {
public:
    Session();
    ~Session();

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&) = delete;
    Session& operator=(Session&&) = delete;

    bool open(const char* idb_path);

    OpenOutcome open_outcome() const { return open_outcome_; }

    const std::string& upgraded_i64_path() const { return upgraded_i64_path_; }

    const std::string& upgrade_log_path() const { return upgrade_log_path_; }

    const std::string& open_notice() const { return open_notice_; }

    void close();

    bool is_open() const { return engine_ && engine_->is_valid() && ida_opened_; }

    const std::string& error() const {
        return engine_ ? engine_->error() : error_;
    }

    QueryResult query(const std::string& sql) { return query(sql.c_str()); }
    QueryResult query(const std::string& sql, const xsql::QueryOptions& options) {
        return query(sql.c_str(), options);
    }
    QueryResult query(const char* sql);
    QueryResult query(const char* sql, const xsql::QueryOptions& options);

    xsql::Status exec(const char* sql);

    bool execute(const std::string& sql) { return execute(sql.c_str()); }
    bool execute(const char* sql);

    bool execute_script(const std::string& script,
                        std::vector<xsql::StatementResult>& results,
                        std::string& error);

    bool export_tables(const std::vector<std::string>& tables,
                       const std::string& output_path,
                       std::string& error);

    std::string scalar(const std::string& sql) { return scalar(sql.c_str()); }
    std::string scalar(const char* sql);

    QueryEngine* engine() { return engine_.get(); }

    std::string info() const;

private:
    std::unique_ptr<QueryEngine> engine_;
    bool ida_opened_ = false;
    std::unique_ptr<rescue::Guard> rescue_guard_;
    std::string error_;
    OpenOutcome open_outcome_ = OpenOutcome::Failed;
    std::string upgraded_i64_path_;
    std::string upgrade_log_path_;
    std::string open_notice_;
};

namespace detail {
    QueryEngine& global_engine();
}

QueryResult query(const char* sql);

xsql::Status exec(const char* sql);

bool execute(const char* sql);

std::string scalar(const char* sql);

using Database = Session;

}
