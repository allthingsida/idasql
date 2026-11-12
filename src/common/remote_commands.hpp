// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <string>

#include <idasql/remote_setting.hpp>

#include "../lib/src/instances.hpp"
#include "idasql_commands.hpp"

namespace idasql {

inline void wire_remote_callbacks(CommandCallbacks& cb, bool honoured) {
    cb.remote_status = [honoured]() -> std::string {
        const bool on = remote::enabled();
        std::string out = on ? "remote control: on   (other processes may start and stop this database's "
                               "servers: idasql http start <database|pid>)"
                             : "remote control: off  (other processes cannot start or stop this database's "
                               "servers; .remote on allows it)";
        if (!honoured)
            out += "\nThis idasql -s session cannot be started from outside; an IDA window with this "
                   "database can.";
        return out;
    };
    cb.remote_set = [honoured](bool on) -> std::string {
        remote::set_enabled(on);
        if (honoured) instances::self().set_remote(on);
        std::string out = std::string("remote control: ") + (on ? "on" : "off") +
                          "  (saved in this database; save the database to keep it)";
        if (!honoured && on)
            out += "\nThis idasql -s session cannot be started from outside; an IDA window with this "
                   "database can.";
        return out;
    };
}

}
