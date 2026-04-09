// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <idasql/database.hpp>

#include <algorithm>

#include "ida_headers.hpp"

namespace idasql {

// ============================================================================
// Session
// ============================================================================

Session::~Session() { close(); }

bool Session::open(const char* idb_path) {
    if (engine_) close();
    error_.clear();

    // Open the database
    int rc = open_database(idb_path, true, nullptr);
    if (rc != 0) {
        error_ = "Failed to open database: " + std::string(idb_path);
        return false;
    }
    ida_opened_ = true;

    // Wait for auto-analysis
    auto_wait();

    // For new analysis (exe/dll/etc), build strings after auto-analysis completes
    // For existing databases (i64/idb), strings are already saved
    std::string path_lower = idb_path;
    std::transform(path_lower.begin(), path_lower.end(), path_lower.begin(), ::tolower);
    auto ends_with = [](const std::string& s, const std::string& suffix) {
        return s.size() >= suffix.size() &&
               s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
    };
    bool is_new_analysis = !(
        ends_with(path_lower, ".i64") ||
        ends_with(path_lower, ".idb")
    );
    if (is_new_analysis) {
        // Configure and build string list with sensible defaults
        strwinsetup_t* opts = const_cast<strwinsetup_t*>(get_strlist_options());
        opts->strtypes.clear();
        opts->strtypes.push_back(STRTYPE_C);      // ASCII
        opts->strtypes.push_back(STRTYPE_C_16);   // UTF-16
        opts->minlen = 5;
        opts->only_7bit = 0;
        clear_strlist();  // Clear before building (like rebuild_strings)
        build_strlist();
    }

    // Create query engine
    engine_ = std::make_unique<QueryEngine>();
    if (!engine_->is_valid()) {
        error_ = engine_->error();
        close();
        return false;
    }

    error_.clear();
    return true;
}

void Session::close() {
    engine_.reset();
    if (ida_opened_) {
        close_database(false);
        ida_opened_ = false;
    }
}

QueryResult Session::query(const char* sql) {
    if (!engine_) {
        QueryResult r;
        r.error = "Session not open";
        return r;
    }
    return engine_->query(sql);
}

xsql::Status Session::exec(const char* sql) {
    return engine_ ? engine_->exec(sql) : xsql::Status::error;
}

bool Session::execute(const char* sql) {
    return engine_ ? engine_->execute(sql) : false;
}

bool Session::execute_script(const std::string& script,
                              std::vector<xsql::StatementResult>& results,
                              std::string& error) {
    if (!engine_) {
        error = "Session not open";
        return false;
    }
    return engine_->execute_script(script, results, error);
}

bool Session::export_tables(const std::vector<std::string>& tables,
                             const std::string& output_path,
                             std::string& error) {
    if (!engine_) {
        error = "Session not open";
        return false;
    }
    return engine_->export_tables(tables, output_path, error);
}

std::string Session::scalar(const char* sql) {
    return engine_ ? engine_->scalar(sql) : "";
}

std::string Session::info() const {
    if (!ida_opened_) return "Not opened";

    std::string s;
    s += "Processor: " + std::string(inf_get_procname().c_str()) + "\n";
    s += "Functions: " + std::to_string(get_func_qty()) + "\n";
    s += "Segments:  " + std::to_string(get_segm_qty()) + "\n";
    s += "Names:     " + std::to_string(get_nlist_size()) + "\n";
    return s;
}

} // namespace idasql
