// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace idasql {
namespace ui_actions {

struct ActionRow {
    std::string name;
    std::string kind;
    std::optional<std::string> ida_action;
    std::string description;
    std::string arg_spec;
    std::string where;
    int available = 0;
    std::optional<int> checked;
    int64_t id = 0;
};

using QuitHandler = std::function<bool(bool save, std::string& error)>;

void set_quit_handler(QuitHandler handler);

bool request_quit(bool save, std::string& error);

std::vector<std::string> catalog_problems();

struct Registry {
    CachedTableDef<ActionRow> table;

    Registry();
    void register_all(xsql::Database& db);
};

}
}
