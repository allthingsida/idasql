// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "idapython_runs.hpp"

#include <idasql/runtime_settings.hpp>

#include <chrono>
#include <cstdio>
#include <ctime>
#include <deque>
#include <mutex>

#include "idapython_exec.hpp"
#include "python_bridge.hpp"

namespace idasql {
namespace idapython_runs {

namespace {

enum Col { kId, kCode, kPath, kSandbox, kShowOutput, kOutput, kSuccess, kError, kStarted, kDurationMs, kCols };

struct Store {
    std::mutex m;
    std::deque<RunRow> rows;
    int64_t next_id = 1;
};

Store& store() {
    static Store s;
    return s;
}

std::string utc_now() {
    const std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm u{};
#ifdef _WIN32
    gmtime_s(&u, &t);
#else
    gmtime_r(&t, &u);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &u);
    return buf;
}

std::optional<std::string> text_arg(int argc, xsql::FunctionArg* argv, int i) {
    if (i >= argc || argv[i].is_null()) return std::nullopt;
    return argv[i].as_text();
}

bool fail(const std::string& message) {
    xsql::set_vtab_error("idapython_runs: " + message);
    return false;
}

bool insert_run(int argc, xsql::FunctionArg* argv) {
    for (int i : {kId, kOutput, kSuccess, kError, kStarted, kDurationMs}) {
        if (i < argc && !argv[i].is_null())
            return fail("only code or path, sandbox and show_output can be given; the run fills in the rest");
    }
    const auto code = text_arg(argc, argv, kCode);
    const auto path = text_arg(argc, argv, kPath);
    if (code.has_value() == path.has_value())
        return fail("give exactly one of code or path");
    if ((code && code->empty()) || (path && path->empty()))
        return fail(code ? "code is empty" : "path is empty");
    const auto sandbox = text_arg(argc, argv, kSandbox);
    int show = 0;
    if (kShowOutput < argc && !argv[kShowOutput].is_null()) {
        show = argv[kShowOutput].as_int();
        if (show != 0 && show != 1) return fail("show_output is 0 or 1");
    }
    if (python_bridge::in_bridge_call())
        return fail("cannot run inside a query issued from Python through `import idasql` "
                    "(IDAPython is not re-entrant here)");
    if (!runtime_settings().enable_idapython())
        return fail("idapython is disabled (enable via UPDATE runtime_settings SET value='1' "
                    "WHERE key='enable_idapython')");
    (void)python_bridge::ensure_python_module(nullptr);

    RunRow row;
    row.code = code;
    row.path = path;
    row.sandbox = sandbox;
    row.show_output = show;
    row.started = utc_now();
    const auto t0 = std::chrono::steady_clock::now();
    const bool shown = show == 1;
    const idapython::ExecutionResult result =
        code ? idapython::execute_snippet(*code, sandbox.value_or(""), shown)
             : idapython::execute_file(*path, sandbox.value_or(""), shown);
    row.duration_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    row.output = result.output;
    row.success = result.success ? 1 : 0;
    if (!result.success) row.error = result.error.empty() ? std::string("the run failed") : result.error;
    {
        Store& s = store();
        std::lock_guard<std::mutex> lock(s.m);
        row.id = s.next_id++;
        s.rows.push_back(row);
        while (s.rows.size() > kKeptRuns) s.rows.pop_front();
    }
    if (!result.success) {
        xsql::set_vtab_error(*row.error);
        return false;
    }
    return true;
}

}

Registry::Registry()
    : runs(cached_table<RunRow>("idapython_runs")
               .no_shared_cache()
               .estimate_rows([]() -> size_t {
                   std::lock_guard<std::mutex> lock(store().m);
                   return store().rows.size();
               })
               .cache_builder([](std::vector<RunRow>& rows) {
                   std::lock_guard<std::mutex> lock(store().m);
                   rows.assign(store().rows.begin(), store().rows.end());
               })
               .column_int64("id", [](const RunRow& r) -> int64_t { return r.id; })
               .column_text_nullable("code", [](const RunRow& r) { return r.code; })
               .column_text_nullable("path", [](const RunRow& r) { return r.path; })
               .column_text_nullable("sandbox", [](const RunRow& r) { return r.sandbox; })
               .column_int("show_output", [](const RunRow& r) { return r.show_output; })
               .column_text("output", [](const RunRow& r) -> std::string { return r.output; })
               .column_int("success", [](const RunRow& r) { return r.success; })
               .column_text_nullable("error", [](const RunRow& r) { return r.error; })
               .column_text("started", [](const RunRow& r) -> std::string { return r.started; })
               .column_int64("duration_ms", [](const RunRow& r) -> int64_t { return r.duration_ms; })
               .rowid([](const RunRow& r) -> int64_t { return r.id; })
               .row_lookup([](RunRow& row, int64_t id) -> bool {
                   std::lock_guard<std::mutex> lock(store().m);
                   for (const auto& r : store().rows) {
                       if (r.id == id) {
                           row = r;
                           return true;
                       }
                   }
                   return false;
               })
               .insertable(insert_run)
               .deletable([](RunRow& row) -> bool {
                   Store& s = store();
                   std::lock_guard<std::mutex> lock(s.m);
                   for (auto it = s.rows.begin(); it != s.rows.end(); ++it) {
                       if (it->id == row.id) {
                           s.rows.erase(it);
                           break;
                       }
                   }
                   return true;
               })
               .build()) {}

void Registry::register_all(xsql::Database& db) {
    db.register_cached_table("idapython_runs", &runs);
    db.create_table("idapython_runs", "idapython_runs");
}

}
}
