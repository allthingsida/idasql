// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * fwd.hpp - Forward declarations for IDASQL registry types
 *
 * Allows database.hpp to hold unique_ptr<T> without including full definitions.
 */

#pragma once

#include <idasql/vtable.hpp>

namespace idasql {

namespace entities {
    struct TableRegistry;
}

namespace metadata {
    struct MetadataItem;
    struct WelcomeRow;
    struct MetadataRegistry;
}

namespace extended {
    struct ExtendedRegistry;
}

namespace disassembly {
    struct DisassemblyRegistry;
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

namespace functions {
    void register_sql_functions(xsql::Database& db);
}

namespace search {
    bool register_search_bytes(xsql::Database& db);
}

} // namespace idasql
