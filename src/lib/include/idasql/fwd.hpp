// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <idasql/vtable.hpp>

#include <string>

namespace idasql {

namespace core {
    struct CoreRegistry;
}

namespace metadata {
    struct MetadataItem;
    struct MetadataRegistry;
}

namespace extended {
    struct ExtendedRegistry;
}

namespace types {
    struct TypesRegistry;
}

namespace debugger {
    struct DebuggerRegistry;
}

namespace decompiler {
    struct DecompilerRegistry;
}

namespace instances {
    struct TableRegistry;
}
namespace ui_actions {
    struct Registry;
}
namespace idapython_runs {
    struct Registry;
}
namespace checkpoints {
    struct CheckpointsRegistry;
}

namespace functions {
    void register_sql_functions(xsql::Database& db);
}

namespace search {
    bool register_byte_search(xsql::Database& db);
}

namespace deep_links {
    bool register_deep_links(xsql::Database& db);
    void enable_navigation_default_for_gui();
    bool open_link(const std::string& uri, std::string& error);
}

}
