// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// notepad — the one free-text note IDA keeps inside each database, shown in
// the "Database notepad" window. Read and written through nalt.hpp's
// get_ida_notepad_text / set_ida_notepad_text, which work under idalib too.
//
// nalt.hpp reserves 1000 indexes (1MB) for the notepad text: 1,024,000
// bytes, the terminating NUL included, which is also what IDA's notepad
// window keeps. Observed on IDA 9.0-9.4: the text is stored byte for byte
// (IDA does not touch line ends; the window writes CRLF), and a write longer
// than the field is cut off without its NUL. So this table writes CRLF like
// the window, shows \n, and refuses text above that size.

#include <idasql/platform.hpp>

#include <string>
#include <vector>

#include "metadata_notepad.hpp"

#include "ida_headers.hpp"

namespace idasql {
namespace metadata {
namespace {

// 1000 netnode indexes of MAXSPECSIZE bytes (nalt.hpp), the NUL included.
constexpr size_t kNotepadLimit = 1024000;

std::string read_stored_text() {
    qstring text;
    if (get_ida_notepad_text(&text) < 0)
        return {};
    return std::string(text.c_str(), text.length());
}

std::string replace_all(std::string s, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
    return s;
}

std::string to_lf(const std::string& s) {
    return replace_all(s, "\r\n", "\n");
}

std::string to_crlf(const std::string& s) {
    return replace_all(to_lf(s), "\n", "\r\n");
}

NotepadRow current_row() {
    const std::string stored = read_stored_text();
    NotepadRow row;
    row.text = to_lf(stored);
    row.size = static_cast<int64_t>(stored.size());
    return row;
}

std::string with_commas(size_t n) {
    std::string s = std::to_string(n);
    for (int i = static_cast<int>(s.size()) - 3; i > 0; i -= 3)
        s.insert(static_cast<size_t>(i), ",");
    return s;
}

} // namespace

CachedTableDef<NotepadRow> define_notepad() {
    return cached_table<NotepadRow>("notepad")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 1; })
        .cache_builder([](std::vector<NotepadRow>& rows) {
            rows.clear();
            rows.push_back(current_row());
        })
        .column_text_rw(
            "text",
            [](const NotepadRow& row) -> std::string { return row.text; },
            [](NotepadRow& row, xsql::FunctionArg value) -> bool {
                if (value.is_nochange())
                    return true;
                if (value.is_null()) {
                    xsql::set_vtab_error(
                        "notepad: text cannot be NULL; DELETE FROM notepad clears it");
                    return false;
                }
                const char* p = value.as_c_str();
                const std::string requested(p ? p : "", p ? static_cast<size_t>(value.bytes()) : 0);
                if (requested.find('\0') != std::string::npos) {
                    xsql::set_vtab_error("notepad: the text contains a NUL byte");
                    return false;
                }
                const std::string stored = to_crlf(requested);
                if (stored.size() + 1 > kNotepadLimit) {
                    xsql::set_vtab_error(
                        "notepad: the text is " + with_commas(stored.size()) +
                        " bytes with CRLF line ends; the notepad holds at most " +
                        with_commas(kNotepadLimit - 1) + " bytes (" +
                        with_commas(kNotepadLimit) + " with the terminating NUL)");
                    return false;
                }
                set_ida_notepad_text(stored.c_str());
                if (read_stored_text() != stored) {
                    xsql::set_vtab_error("notepad: IDA did not store the text as written");
                    return false;
                }
                row.text = to_lf(stored);
                row.size = static_cast<int64_t>(stored.size());
                return true;
            })
        .column_int64("size", [](const NotepadRow& row) -> int64_t { return row.size; })
        .deletable([](NotepadRow& row) -> bool {
            set_ida_notepad_text("");
            if (!read_stored_text().empty()) {
                xsql::set_vtab_error("notepad: IDA did not clear the notepad");
                return false;
            }
            row = NotepadRow{};
            return true;
        })
        .build();
}

} // namespace metadata
} // namespace idasql
