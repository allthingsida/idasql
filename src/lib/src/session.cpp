// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include <idasql/database.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <system_error>

#include "ida_headers.hpp"
#include "types_bookmarks.hpp"

namespace idasql {

namespace {

int idasql_open_database(const char* path) {
#if IDASQL_HAS_OPEN_DATABASE_3ARG
    return open_database(path, true, nullptr);
#else
    return open_database(path, true);
#endif
}

std::string to_lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool extension_equals(const std::filesystem::path& path, const char* ext) {
    return to_lower_copy(path.extension().string()) == ext;
}

std::filesystem::path i64_sibling_for_idb(const std::filesystem::path& idb_path) {
    namespace fs = std::filesystem;

    fs::path candidate = idb_path;
    candidate.replace_extension(".i64");

    std::error_code ec;
    fs::path parent = candidate.parent_path();
    if (parent.empty()) {
        parent = ".";
    }

    const std::string target_name = to_lower_copy(candidate.filename().string());
    if (!fs::exists(parent, ec) || ec) {
        return candidate;
    }

    for (const auto& entry : fs::directory_iterator(parent, ec)) {
        if (ec) {
            break;
        }
        if (to_lower_copy(entry.path().filename().string()) == target_name) {
            return entry.path();
        }
    }

    return candidate;
}

[[maybe_unused]] std::filesystem::path upgrade_log_for_idb(const std::filesystem::path& idb_path) {
    std::filesystem::path log_path = idb_path;
    log_path.replace_extension(".id0.upgrade.log");
    return log_path;
}

bool legacy_idb_upgrade_allowed_in_process() {
#ifdef _WIN32
    return true;
#else
    qstring value;
    return qgetenv("IDASQL_ALLOW_LEGACY_IDB_UPGRADE_IN_PROCESS", &value) &&
        value == "1";
#endif
}

void close_ida_database_for_session() {
    types::reset_local_type_bookmark_place_cache();
    close_database(false);
}

} // namespace

// ============================================================================
// Session
// ============================================================================

Session::~Session() { close(); }

bool Session::open(const char* idb_path) {
    if (engine_ || ida_opened_) close();
    error_.clear();
    upgraded_i64_path_.clear();
    upgrade_log_path_.clear();
    open_notice_.clear();
    open_outcome_ = OpenOutcome::Failed;

    namespace fs = std::filesystem;
    fs::path requested_path(idb_path ? idb_path : "");
    fs::path open_path = requested_path;
    bool already_opened = false;

    if (extension_equals(requested_path, ".idb")) {
        fs::path i64_path = i64_sibling_for_idb(requested_path);
        std::error_code ec;
        bool i64_existed_before = fs::exists(i64_path, ec);
        if (!ec && i64_existed_before) {
            // Freshness guard: only prefer the sibling .i64 when it is at least as
            // new as the requested .idb. A .i64 older than its .idb is stale (the
            // .idb was touched after the last upgrade) or unrelated, and silently
            // making it the database of record would return the wrong analysis.
            // Refuse and require an explicit choice instead of guessing. (mtime is
            // a pragmatic freshness signal; it does not prove input-file identity.)
            std::error_code idb_ec, i64_ec;
            auto idb_mtime = fs::last_write_time(requested_path, idb_ec);
            auto i64_mtime = fs::last_write_time(i64_path, i64_ec);
            if (!idb_ec && !i64_ec && i64_mtime < idb_mtime) {
                open_outcome_ = OpenOutcome::Failed;
                error_ = "Sibling 64-bit database is older than the requested .idb and "
                    "may be stale: " + i64_path.string() + " predates " +
                    requested_path.string() + ". Reopen the .i64 explicitly to use it, "
                    "or remove it to re-run analysis from the .idb.";
                return false;
            }
            open_path = i64_path;
            open_notice_ = "Opened " + i64_path.string() +
                " (existing 64-bit database) instead of " + requested_path.string() + ".";
        } else {
            if (!legacy_idb_upgrade_allowed_in_process()) {
                open_outcome_ = OpenOutcome::Failed;
                error_ = "Legacy .idb upgrade is not supported in-process from this executable; "
                    "use the idasql CLI to upgrade the .idb, then reopen the generated .i64.";
                return false;
            }

            int rc = idasql_open_database(requested_path.string().c_str());
            ec.clear();
            bool i64_exists_after = fs::exists(i64_path, ec);
            if (i64_exists_after && !i64_existed_before) {
                if (rc == 0) {
                    ida_opened_ = true;
                    close_ida_database_for_session();
                    ida_opened_ = false;
                }
                open_outcome_ = OpenOutcome::UpgradedReopenRequired;
                upgraded_i64_path_ = i64_path.string();
                upgrade_log_path_ = upgrade_log_for_idb(requested_path).string();
                error_ = "Database upgraded from 32-bit .idb to 64-bit .i64; reopen with: " +
                    upgraded_i64_path_;
                return false;
            }

            if (rc != 0) {
                error_ = "Failed to open or upgrade database: " + requested_path.string() +
                    " (legacy .idb upgrades require a writable directory)";
                return false;
            }

            ida_opened_ = true;
            open_path = requested_path;
            already_opened = true;
        }
    }

    if (!already_opened) {
        int rc = idasql_open_database(open_path.string().c_str());
        if (rc != 0) {
            error_ = "Failed to open database: " + open_path.string();
            return false;
        }
        ida_opened_ = true;
    }

    // Wait for auto-analysis (no-op if the user disabled AA — see ida_compat.hpp)
    idasql_auto_wait();

    // For new analysis (exe/dll/etc), build strings after auto-analysis completes
    // For existing databases (i64/idb), strings are already saved
    std::string path_lower = to_lower_copy(open_path.string());
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
        open_outcome_ = OpenOutcome::Failed;
        return false;
    }

    error_.clear();
    open_outcome_ = OpenOutcome::Ok;
    return true;
}

void Session::close() {
    engine_.reset();
    if (ida_opened_) {
        close_ida_database_for_session();
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
