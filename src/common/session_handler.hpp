// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

/**
 * session_handler.hpp - Interactive session orchestration core
 *
 * SessionHandler - Core query processing logic for IDASQL
 *
 * This class handles:
 * - SQL query execution
 * - Meta commands (.tables, .schema, .help)
 *
 * NO IDA DEPENDENCIES - can be tested standalone.
 */

#include <algorithm>
#include <cctype>
#include <functional>
#include <string>

#include "idasql_commands.hpp"

namespace idasql {

class SessionHandler {
public:
    using SqlExecutor = std::function<std::string(const std::string&)>;

    // Simple allowlist for table identifiers (alnum + underscore)
    static bool is_safe_table_name(const std::string& name) {
        if (name.empty() || name.size() > 128) {
            return false;
        }
        return std::all_of(name.begin(), name.end(), [](unsigned char c) {
            return std::isalnum(c) || c == '_';
        });
    }

    explicit SessionHandler(SqlExecutor executor)
        : executor_(std::move(executor)) {
        callbacks_.get_tables = [this]() {
            return executor_("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
        };
        callbacks_.get_schema = [this](const std::string& table) {
            if (!is_safe_table_name(table)) {
                return std::string("Invalid table name");
            }
            std::string sql = "SELECT sql FROM sqlite_master WHERE name='" + table + "'";
            return executor_(sql);
        };
        callbacks_.get_info = [this]() {
            return executor_("PRAGMA database_list");
        };
    }

    ~SessionHandler() {
        end_session();
    }

    // Non-copyable, movable
    SessionHandler(const SessionHandler&) = delete;
    SessionHandler& operator=(const SessionHandler&) = delete;
    SessionHandler(SessionHandler&&) = default;
    SessionHandler& operator=(SessionHandler&&) = default;

    std::string process_line(const std::string& line) {
        if (line.empty()) {
            return "";
        }

        std::string output;
        auto cmd_result = handle_command(line, callbacks_, output);

        switch (cmd_result) {
            case CommandResult::QUIT:
                quit_requested_ = true;
                return "";

            case CommandResult::HANDLED:
                return output;

            case CommandResult::NOT_HANDLED:
                break;
        }

        return executor_(line);
    }

    std::string query(const std::string& prompt) {
        return executor_(prompt);
    }

    void end_session() {
        // No stateful session resources to clean up in slim mode.
    }

    bool is_quit_requested() const { return quit_requested_; }

    CommandCallbacks& callbacks() { return callbacks_; }
    const CommandCallbacks& callbacks() const { return callbacks_; }

private:
    SqlExecutor executor_;
    CommandCallbacks callbacks_;
    bool quit_requested_ = false;
};

} // namespace idasql
