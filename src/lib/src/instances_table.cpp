// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "instances_table.hpp"

#include "os.hpp"
#include "remote_control.hpp"

#include <optional>
#include <string>

namespace idasql {
namespace instances {

namespace {

std::optional<std::string> text_or_null(const std::string& s) {
    if (s.empty()) return std::nullopt;
    return s;
}

thread_local int t_requests = 0;

bool fail(const std::string& message) {
    xsql::set_vtab_error("ida_instances: " + message);
    return false;
}

bool may_ask(const Entry& row, const char* what) {
    if (row.self)
        return fail(std::string("this row is this IDA: use ") + what + " here instead");
    if (!row.idasql)
        return fail("pid " + std::to_string(row.record.pid) + " runs no idasql plugin");
    if (++t_requests > 1)
        return fail("one request to another IDA per statement; narrow the WHERE to one row (WHERE pid = ...)");
    return true;
}

bool set_remote(Entry& row, xsql::FunctionArg v) {
    if (v.is_null()) return fail("remote is 1 (on) or 0 (off)");
    const int64_t on = v.as_int64();
    if (on != 0 && on != 1) return fail("remote is 1 (on) or 0 (off)");
    if (!may_ask(row, ".remote on|off")) return false;
    const remote::Result r = remote::set_remote(row.record, on == 1);
    if (!r.ok()) return fail(r.message);
    row.record.remote = on == 1;
    return true;
}

bool set_server(Entry& row, xsql::FunctionArg v, bool start) {
    if (v.is_null()) return true;
    const std::string service = v.as_text();
    if (service != "http" && service != "mcp")
        return fail(std::string(start ? "start" : "stop") + " is 'http' or 'mcp'");
    if (!may_ask(row, start ? ".http start / .mcp start" : ".http stop / .mcp stop")) return false;
    const remote::Result r = remote::server(row.record, service, start);
    if (!r.ok()) return fail(r.message);
    return true;
}

xsql::TransactionHooks statement_end_hooks() {
    xsql::TransactionHooks h;
    h.commit = [](const xsql::TransactionHooks::State&) { t_requests = 0; };
    h.rollback = [](const xsql::TransactionHooks::State&) { t_requests = 0; };
    return h;
}

std::vector<Entry> list_now() {
    ListOptions o;
    o.skip_ipc_pid = os::current_pid();
    o.ipc_io_timeout_ms = 2000;
    return list(o);
}

}

TableRegistry::TableRegistry()
    : table(cached_table<Entry>("ida_instances")
                .no_shared_cache()
                .counts_as_write(false)
                .estimate_rows([]() -> size_t { return 8; })
                .cache_builder([](std::vector<Entry>& rows) {
                    t_requests = 0;
                    rows = list_now();
                })
                .column_int64("pid", [](const Entry& e) -> int64_t { return static_cast<int64_t>(e.record.pid); })
                .column_text("host", [](const Entry& e) -> std::string { return e.record.host; })
                .column_text_nullable("ida_version", [](const Entry& e) { return text_or_null(e.record.ida_version); })
                .column_text_nullable("idasql_version",
                                      [](const Entry& e) { return text_or_null(e.record.idasql_version); })
                .column_text_nullable("idb_path", [](const Entry& e) { return text_or_null(e.record.idb_path); })
                .column_text_nullable("http", [](const Entry& e) { return text_or_null(e.record.http); })
                .column_int("http_auth", [](const Entry& e) { return e.record.http_auth ? 1 : 0; })
                .column_text_nullable("mcp", [](const Entry& e) { return text_or_null(e.record.mcp); })
                .column_int("mcp_auth", [](const Entry& e) { return e.record.mcp_auth ? 1 : 0; })
                .column_int("rescue", [](const Entry& e) { return e.record.rescue ? 1 : 0; })
                .column_int("idasql", [](const Entry& e) { return e.idasql ? 1 : 0; })
                .column_int("ipc", [](const Entry& e) { return e.ipc ? 1 : 0; })
                .column_int("responsive", [](const Entry& e) { return e.responsive ? 1 : 0; })
                .column_int("self", [](const Entry& e) { return e.self ? 1 : 0; })
                .column_text_nullable("started", [](const Entry& e) { return text_or_null(e.record.started); })
                .column_int_nullable_rw(
                    "remote",
                    [](const Entry& e) -> std::optional<int> {
                        if (!e.idasql || e.record.host != "gui") return std::nullopt;
                        return e.record.remote ? 1 : 0;
                    },
                    set_remote)
                .column_text_nullable_rw(
                    "start", [](const Entry&) { return std::optional<std::string>(); },
                    [](Entry& row, xsql::FunctionArg v) { return set_server(row, v, true); })
                .column_text_nullable_rw(
                    "stop", [](const Entry&) { return std::optional<std::string>(); },
                    [](Entry& row, xsql::FunctionArg v) { return set_server(row, v, false); })
                .rowid([](const Entry& e) -> int64_t { return static_cast<int64_t>(e.record.pid); })
                .row_lookup([](Entry& row, int64_t pid) -> bool {
                    for (auto& e : list_now()) {
                        if (static_cast<int64_t>(e.record.pid) == pid) {
                            row = std::move(e);
                            return true;
                        }
                    }
                    return false;
                })
                .transaction_hooks(statement_end_hooks())
                .build()) {}

void TableRegistry::register_all(xsql::Database& db) {
    db.register_cached_table("ida_instances", &table);
    db.create_table("ida_instances", "ida_instances");
}

}
}
