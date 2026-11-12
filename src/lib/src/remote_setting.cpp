// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "ida_headers.hpp"

#include <idasql/idasql_config.hpp>
#include <idasql/remote_setting.hpp>

namespace idasql {
namespace remote {

bool enabled() {
    netnode node(config::NODE_NAME, 0, false);
    if (node == BADNODE) return false;
    return node.altval(config::alt::REMOTE_ENABLED) == 1;
}

void set_enabled(bool on) {
    netnode node(config::NODE_NAME, 0, on);
    if (node == BADNODE) return;
    node.altset(config::alt::SCHEMA_VERSION, config::SCHEMA_VERSION);
    if (on)
        node.altset(config::alt::REMOTE_ENABLED, 1);
    else
        node.altdel(config::alt::REMOTE_ENABLED);
}

}
}
