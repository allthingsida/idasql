// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// widget_catalog.hpp
//
// Single source of truth for IDA widget-type classification across IDA SDK
// versions 9.0, 9.1, 9.2, 9.3. Header-only;
//

#pragma once

#include <cstddef>
#include <string>
#include <sstream>

// This header must be included AFTER the IDA SDK headers (kernwin.hpp) and
// ida_compat.hpp; ida_headers.hpp arranges that ordering.

namespace idasql {
namespace ui_context {

enum class WidgetCategory
{
    Unknown = 0,
    Disassembly,
    Decompiler,
    HexView,
    TypeView,
    Chooser,
    Debugger,
    Navigation,
    Output,
    Script,
    Auxiliary,
};

struct WidgetCatalogEntry
{
    int            id;
    const char    *name;
    WidgetCategory category;
    bool           is_address;
    bool           is_custom_view;
    bool           is_chooser_like;
};

inline constexpr WidgetCatalogEntry kWidgetCatalog[] = {
    // --- Choosers / list widgets present in all 9.0-9.3 ---
    { BWN_EXPORTS,         "BWN_EXPORTS",         WidgetCategory::Chooser,     false, false, true  },
    { BWN_IMPORTS,         "BWN_IMPORTS",         WidgetCategory::Chooser,     false, false, true  },
    { BWN_NAMES,           "BWN_NAMES",           WidgetCategory::Chooser,     false, false, true  },
    { BWN_FUNCS,           "BWN_FUNCS",           WidgetCategory::Chooser,     false, false, true  },
    { BWN_STRINGS,         "BWN_STRINGS",         WidgetCategory::Chooser,     false, false, true  },
    { BWN_SEGS,            "BWN_SEGS",            WidgetCategory::Chooser,     false, false, true  },
    { BWN_SEGREGS,         "BWN_SEGREGS",         WidgetCategory::Chooser,     false, false, true  },
    { BWN_SELS,            "BWN_SELS",            WidgetCategory::Chooser,     false, false, true  },
    { BWN_SIGNS,           "BWN_SIGNS",           WidgetCategory::Chooser,     false, false, true  },
    { BWN_TILS,            "BWN_TILS",            WidgetCategory::TypeView,    false, false, true  },

    // --- Slot id 10: Local Types widget. Exactly one row per SDK. ---
#if defined(BWN_TITREE)
    { BWN_TITREE,          "BWN_TITREE",          WidgetCategory::TypeView,    false, false, true  },
#elif defined(BWN_TICSR)
    { BWN_TICSR,           "BWN_TICSR",           WidgetCategory::TypeView,    false, false, true  },
#elif defined(BWN_TILVIEW)
    { BWN_TILVIEW,         "BWN_TILVIEW",         WidgetCategory::TypeView,    false, false, true  },
#endif

    // --- Slot id 11: BWN_CALLS in 9.0-9.2; reserved in 9.3 ---
#ifdef BWN_CALLS
    { BWN_CALLS,           "BWN_CALLS",           WidgetCategory::Chooser,     false, false, true  },
#endif
#ifdef BWN_RESERVED_1
    { BWN_RESERVED_1,      "BWN_RESERVED_1",      WidgetCategory::Auxiliary,   false, false, false },
#endif

    { BWN_PROBS,           "BWN_PROBS",           WidgetCategory::Chooser,     false, false, true  },
    { BWN_BPTS,            "BWN_BPTS",            WidgetCategory::Debugger,    false, false, true  },
    { BWN_THREADS,         "BWN_THREADS",         WidgetCategory::Debugger,    false, false, true  },
    { BWN_MODULES,         "BWN_MODULES",         WidgetCategory::Debugger,    false, false, true  },
    { BWN_TRACE,           "BWN_TRACE",           WidgetCategory::Debugger,    false, false, true  },
    { BWN_CALL_STACK,      "BWN_CALL_STACK",      WidgetCategory::Debugger,    false, false, true  },
    { BWN_XREFS,           "BWN_XREFS",           WidgetCategory::Chooser,     false, false, true  },
    { BWN_SEARCH,          "BWN_SEARCH",          WidgetCategory::Chooser,     false, false, true  },

    { BWN_FRAME,           "BWN_FRAME",           WidgetCategory::Navigation,  false, false, false },
    { BWN_NAVBAND,         "BWN_NAVBAND",         WidgetCategory::Navigation,  false, false, false },
    { BWN_DISASM,          "BWN_DISASM",          WidgetCategory::Disassembly, true,  true,  false },
    { BWN_HEXVIEW,         "BWN_HEXVIEW",         WidgetCategory::HexView,     true,  true,  false },
    { BWN_NOTEPAD,         "BWN_NOTEPAD",         WidgetCategory::Script,      false, false, false },
    { BWN_OUTPUT,          "BWN_OUTPUT",          WidgetCategory::Output,      false, false, false },
    { BWN_CLI,             "BWN_CLI",             WidgetCategory::Script,      false, false, false },
    { BWN_WATCH,           "BWN_WATCH",           WidgetCategory::Debugger,    false, false, true  },
    { BWN_LOCALS,          "BWN_LOCALS",          WidgetCategory::Debugger,    false, false, true  },
    { BWN_STKVIEW,         "BWN_STKVIEW",         WidgetCategory::Debugger,    false, false, true  },
    { BWN_CHOOSER,         "BWN_CHOOSER",         WidgetCategory::Chooser,     false, false, true  },
    { BWN_SHORTCUTCSR,     "BWN_SHORTCUTCSR",     WidgetCategory::Chooser,     false, false, true  },
    { BWN_SHORTCUTWIN,     "BWN_SHORTCUTWIN",     WidgetCategory::Auxiliary,   false, false, false },
    { BWN_CPUREGS,         "BWN_CPUREGS",         WidgetCategory::Debugger,    false, false, false },
    { BWN_SO_STRUCTS,      "BWN_SO_STRUCTS",      WidgetCategory::Chooser,     false, false, true  },
    { BWN_SO_OFFSETS,      "BWN_SO_OFFSETS",      WidgetCategory::Chooser,     false, false, true  },
    { BWN_CMDPALCSR,       "BWN_CMDPALCSR",       WidgetCategory::Chooser,     false, false, true  },
    { BWN_CMDPALWIN,       "BWN_CMDPALWIN",       WidgetCategory::Auxiliary,   false, false, false },
    { BWN_SNIPPETS,        "BWN_SNIPPETS",        WidgetCategory::Script,      false, false, false },
    { BWN_CUSTVIEW,        "BWN_CUSTVIEW",        WidgetCategory::Auxiliary,   false, false, false },
    { BWN_ADDRWATCH,       "BWN_ADDRWATCH",       WidgetCategory::Debugger,    false, false, true  },
    { BWN_PSEUDOCODE,      "BWN_PSEUDOCODE",      WidgetCategory::Decompiler,  true,  true,  false },

    // --- Slot ids 47/48: callers/callees in 9.0-9.2; reserved in 9.3 ---
#ifdef BWN_CALLS_CALLERS
    { BWN_CALLS_CALLERS,   "BWN_CALLS_CALLERS",   WidgetCategory::Chooser,     false, false, true  },
#endif
#ifdef BWN_RESERVED_2
    { BWN_RESERVED_2,      "BWN_RESERVED_2",      WidgetCategory::Auxiliary,   false, false, false },
#endif
#ifdef BWN_CALLS_CALLEES
    { BWN_CALLS_CALLEES,   "BWN_CALLS_CALLEES",   WidgetCategory::Chooser,     false, false, true  },
#endif
#ifdef BWN_RESERVED_3
    { BWN_RESERVED_3,      "BWN_RESERVED_3",      WidgetCategory::Auxiliary,   false, false, false },
#endif

    { BWN_MDVIEWCSR,       "BWN_MDVIEWCSR",       WidgetCategory::Chooser,     false, false, true  },
    { BWN_DISASM_ARROWS,   "BWN_DISASM_ARROWS",   WidgetCategory::Auxiliary,   false, false, false },
    { BWN_CV_LINE_INFOS,   "BWN_CV_LINE_INFOS",   WidgetCategory::Auxiliary,   false, false, false },
    { BWN_SRCPTHMAP_CSR,   "BWN_SRCPTHMAP_CSR",   WidgetCategory::Chooser,     false, false, true  },
    { BWN_SRCPTHUND_CSR,   "BWN_SRCPTHUND_CSR",   WidgetCategory::Chooser,     false, false, true  },
    { BWN_UNDOHIST,        "BWN_UNDOHIST",        WidgetCategory::Chooser,     false, false, true  },
    { BWN_SNIPPETS_CSR,    "BWN_SNIPPETS_CSR",    WidgetCategory::Chooser,     false, false, true  },
    { BWN_SCRIPTS_CSR,     "BWN_SCRIPTS_CSR",     WidgetCategory::Chooser,     false, false, true  },
    { BWN_BOOKMARKS,       "BWN_BOOKMARKS",       WidgetCategory::Chooser,     false, false, true  },
    { BWN_TILIST,          "BWN_TILIST",          WidgetCategory::TypeView,    false, true,  false },

    // --- Added in 9.1+ ---
#ifdef BWN_TIL_VIEW
    { BWN_TIL_VIEW,        "BWN_TIL_VIEW",        WidgetCategory::TypeView,    false, false, true  },
#endif

    // --- Added in 9.2+ ---
#ifdef BWN_TYPE_EDITOR
    { BWN_TYPE_EDITOR,     "BWN_TYPE_EDITOR",     WidgetCategory::TypeView,    false, false, false },
#endif
#ifdef BWN_MICROCODE
    { BWN_MICROCODE,       "BWN_MICROCODE",       WidgetCategory::Decompiler,  true,  true,  false },
#endif
#ifdef BWN_XREF_TREE
    { BWN_XREF_TREE,       "BWN_XREF_TREE",       WidgetCategory::Chooser,     false, false, true  },
#endif
};

inline constexpr std::size_t kWidgetCatalogSize =
    sizeof(kWidgetCatalog) / sizeof(kWidgetCatalog[0]);

inline const WidgetCatalogEntry *widget_catalog_lookup(int widget_type)
{
    for (std::size_t i = 0; i < kWidgetCatalogSize; ++i)
    {
        if (kWidgetCatalog[i].id == widget_type)
            return &kWidgetCatalog[i];
    }
    return nullptr;
}

inline const char *widget_type_name(int widget_type)
{
    const WidgetCatalogEntry *entry = widget_catalog_lookup(widget_type);
    return entry != nullptr ? entry->name : nullptr;
}

inline std::string widget_type_name_or_unknown(int widget_type)
{
    const char *known = widget_type_name(widget_type);
    if (known != nullptr)
        return known;
    std::ostringstream out;
    out << "UNKNOWN_" << widget_type;
    return out.str();
}

// Cross-version canonical name. Currently only differs from the SDK macro
// name for the slot-10 "Local Types" widget (BWN_TILVIEW / BWN_TICSR /
// BWN_TITREE) which all map to "BWN_LOCAL_TYPES". For every other id,
// returns the SDK macro name (or "UNKNOWN_<n>").
inline std::string widget_canonical_name(int widget_type)
{
#if defined(BWN_TITREE)
    if (widget_type == BWN_TITREE)
        return "BWN_LOCAL_TYPES";
#elif defined(BWN_TICSR)
    if (widget_type == BWN_TICSR)
        return "BWN_LOCAL_TYPES";
#elif defined(BWN_TILVIEW)
    if (widget_type == BWN_TILVIEW)
        return "BWN_LOCAL_TYPES";
#endif
    return widget_type_name_or_unknown(widget_type);
}

inline WidgetCategory widget_category(int widget_type)
{
    const WidgetCatalogEntry *entry = widget_catalog_lookup(widget_type);
    return entry != nullptr ? entry->category : WidgetCategory::Unknown;
}

inline const char *widget_category_name(WidgetCategory c)
{
    switch (c)
    {
        case WidgetCategory::Disassembly: return "disassembly";
        case WidgetCategory::Decompiler:  return "decompiler";
        case WidgetCategory::HexView:     return "hex_view";
        case WidgetCategory::TypeView:    return "type_view";
        case WidgetCategory::Chooser:     return "chooser";
        case WidgetCategory::Debugger:    return "debugger";
        case WidgetCategory::Navigation:  return "navigation";
        case WidgetCategory::Output:      return "output";
        case WidgetCategory::Script:      return "script";
        case WidgetCategory::Auxiliary:   return "auxiliary";
        case WidgetCategory::Unknown:     break;
    }
    return "unknown";
}

inline bool is_custom_view_widget_type(int widget_type)
{
    const WidgetCatalogEntry *entry = widget_catalog_lookup(widget_type);
    return entry != nullptr && entry->is_custom_view;
}

inline bool is_address_widget_type(int widget_type)
{
    const WidgetCatalogEntry *entry = widget_catalog_lookup(widget_type);
    return entry != nullptr && entry->is_address;
}

inline bool is_chooser_like_widget_type(int widget_type)
{
    // OR the catalog's explicit flag with the SDK's own predicate so that
    // widgets the SDK identifies as choosers (but the catalog doesn't list)
    // are still recognized, while still forcing chooser-like behavior on
    // the widgets the catalog pins (notably the FUNCS / NAMES / IMPORTS /
    // BPTS / Local-Types set, which the SDK's 9.3 is_chooser_widget
    // excludes from its range test).
    const WidgetCatalogEntry *entry = widget_catalog_lookup(widget_type);
    if (entry != nullptr && entry->is_chooser_like)
        return true;
    return is_chooser_widget(widget_type);
}

} // namespace ui_context
} // namespace idasql
