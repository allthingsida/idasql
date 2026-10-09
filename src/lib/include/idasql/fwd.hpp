// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * fwd.hpp - Forward declarations for IDASQL registry types
 *
 * Allows database.hpp to hold unique_ptr<T> without including full definitions.
 */

#pragma once

#include <idasql/vtable.hpp>

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
    // IDA 9.4+ deep links; a no-op on older SDKs.
    bool register_deep_links(xsql::Database& db);
    // The GUI plugin opens links in-process, so navigation defaults ON there.
    void enable_navigation_default_for_gui();
}

} // namespace idasql
