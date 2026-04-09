// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

/**
 * idasql_cli.hpp - IDA plugin CLI integration wrapper
 *
 * IdasqlCLI - IDA plugin command line interface.
 *
 * Wraps SessionHandler and provides cli_t integration for IDA.
 */

#include <functional>
#include <memory>
#include <string>

#include <kernwin.hpp>

#include "session_handler.hpp"

namespace idasql {

class IdasqlCLI {
public:
    using SqlExecutor = std::function<std::string(const std::string&)>;

    explicit IdasqlCLI(SqlExecutor executor)
        : session_(std::move(executor)) {}

    ~IdasqlCLI() {
        uninstall();
    }

    // Non-copyable
    IdasqlCLI(const IdasqlCLI&) = delete;
    IdasqlCLI& operator=(const IdasqlCLI&) = delete;

    bool install() {
        if (installed_) {
            return true;
        }

        s_instance_ = this;

        cli_.size = sizeof(cli_t);
        cli_.flags = 0;
        cli_.sname = "idasql";
        cli_.lname = "idasql - SQL interface to IDA database";
        cli_.hint = "Enter SQL query or .command";
        cli_.execute_line = &IdasqlCLI::execute_line_cb;
        cli_.keydown = nullptr;
        cli_.find_completions = nullptr;

        install_command_interpreter(&cli_);
        installed_ = true;
        msg("IDASQL CLI: Installed\n");
        return true;
    }

    void uninstall() {
        if (!installed_) {
            return;
        }

        session_.end_session();
        remove_command_interpreter(&cli_);
        installed_ = false;
        s_instance_ = nullptr;

        msg("IDASQL CLI: Uninstalled\n");
    }

    bool is_installed() const { return installed_; }

    std::string process_line(const std::string& line) {
        return session_.process_line(line);
    }

    SessionHandler& session() { return session_; }
    const SessionHandler& session() const { return session_; }

private:
    SessionHandler session_;
    cli_t cli_{};
    bool installed_ = false;

    static IdasqlCLI* s_instance_;

    static bool idaapi execute_line_cb(const char* line) {
        if (!s_instance_ || !line) {
            return true;
        }

        std::string result = s_instance_->process_line(line);
        if (!result.empty()) {
            msg("%s\n", result.c_str());
        }

        return true;
    }
};

inline IdasqlCLI* IdasqlCLI::s_instance_ = nullptr;

} // namespace idasql
