// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "ui_actions.hpp"

#include <idasql/fwd.hpp>

#include <xsql/json.hpp>

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <mutex>
#include <set>

#include "decompiler.hpp"
#include "ida_compat.hpp"
#include "ida_headers.hpp"
#include "ui_actions_catalog.hpp"

namespace idasql {
namespace ui_actions {

namespace {

using json = xsql::json;

std::mutex g_handler_m;
QuitHandler g_handler;

struct LastRun {
    std::optional<std::string> result;
    std::optional<std::string> error;
};
std::mutex g_last_m;
std::map<std::string, LastRun> g_last;

struct Statement {
    bool ran = false;
    std::string ran_name;
    std::map<int64_t, std::string> args;
};
thread_local Statement t_stmt;

void reset_statement() { t_stmt = Statement{}; }

const char* state_name(action_state_t s) {
    switch (s) {
        case AST_ENABLE_ALWAYS: return "enable_always";
        case AST_ENABLE_FOR_IDB: return "enable_for_idb";
        case AST_ENABLE_FOR_WIDGET: return "enable_for_widget";
        case AST_ENABLE: return "enable";
        case AST_DISABLE_ALWAYS: return "disable_always";
        case AST_DISABLE_FOR_IDB: return "disable_for_idb";
        case AST_DISABLE_FOR_WIDGET: return "disable_for_widget";
        case AST_DISABLE: return "disable";
    }
    return "unknown";
}

int64_t row_id(const std::string& name) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : name) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return static_cast<int64_t>(h & 0x7FFFFFFFFFFFFFFFULL);
}

std::string hex(uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%" PRIX64, v);
    return buf;
}

struct QuitRequest : public exec_request_t {
    bool save;
    explicit QuitRequest(bool s) : save(s) {}
    ssize_t idaapi execute() override {
        if (!save) set_database_flag(DBFL_KILL);
        qexit(0);
        return 0;
    }
};

bool ida_action_enabled(const char* name) {
    action_state_t st = AST_DISABLE;
    return get_action_state(name, &st) && is_action_enabled(st);
}

std::optional<int> ida_action_checked(const char* name) {
    bool checkable = false;
    if (!get_action_checkable(name, &checkable) || !checkable) return std::nullopt;
    bool checked = false;
    get_action_checked(name, &checked);
    return checked ? 1 : 0;
}

bool read_args(const std::string& spec_text, const std::string& args_text, json& out, std::string& error) {
    const json spec = json::parse(spec_text, nullptr, false);
    const json args = args_text.empty() ? json::object() : json::parse(args_text, nullptr, false);
    if (args.is_discarded() || !args.is_object()) {
        error = "args must be a JSON object, e.g. {\"addr\": 4198400}";
        return false;
    }
    for (auto it = args.begin(); it != args.end(); ++it) {
        if (!spec.contains(it.key())) {
            std::string known;
            for (auto s = spec.begin(); s != spec.end(); ++s) known += (known.empty() ? "" : ", ") + s.key();
            error = "unknown argument '" + it.key() + "'" +
                    (known.empty() ? std::string(" (this action takes none)") : " (takes: " + known + ")");
            return false;
        }
    }
    out = json::object();
    for (auto s = spec.begin(); s != spec.end(); ++s) {
        const std::string& name = s.key();
        const std::string type = s.value().value("type", std::string("text"));
        if (!args.contains(name) || args[name].is_null()) {
            if (s.value().value("required", false)) {
                error = "argument '" + name + "' is required";
                return false;
            }
            if (s.value().contains("default")) out[name] = s.value()["default"];
            continue;
        }
        const json& v = args[name];
        if (type == "int") {
            if (v.is_number_unsigned()) {
                out[name] = v.get<uint64_t>();
            } else if (v.is_number_integer()) {
                out[name] = static_cast<uint64_t>(v.get<int64_t>());
            } else if (v.is_string()) {
                const std::string t = v.get<std::string>();
                char* end = nullptr;
                const unsigned long long n = std::strtoull(t.c_str(), &end, 0);
                if (t.empty() || *end != '\0') {
                    error = "argument '" + name + "' is an integer (or a \"0x...\" string)";
                    return false;
                }
                out[name] = static_cast<uint64_t>(n);
            } else {
                error = "argument '" + name + "' is an integer";
                return false;
            }
        } else if (type == "bool") {
            if (v.is_boolean()) {
                out[name] = v.get<bool>();
            } else if (v.is_number_integer() && (v.get<int64_t>() == 0 || v.get<int64_t>() == 1)) {
                out[name] = v.get<int64_t>() == 1;
            } else {
                error = "argument '" + name + "' is true or false";
                return false;
            }
        } else {
            if (!v.is_string()) {
                error = "argument '" + name + "' is a string";
                return false;
            }
            out[name] = v.get<std::string>();
        }
    }
    return true;
}

ea_t arg_ea(const json& a, const char* name) { return static_cast<ea_t>(a[name].get<uint64_t>()); }

using RunFn = bool (*)(const json& args, std::string& result, std::string& error);
using AvailFn = bool (*)();

bool in_gui() { return is_idaq(); }
bool always() { return true; }
bool quit_available() {
    if (is_idaq()) return true;
    std::lock_guard<std::mutex> lock(g_handler_m);
    return static_cast<bool>(g_handler);
}

bool run_quit(const json& a, std::string& result, std::string& error) {
    const bool save = a.value("save", true);
    if (!request_quit(save, error)) return false;
    result = save ? "quitting, saving the database" : "quitting without saving";
    return true;
}

bool run_jump_to(const json& a, std::string& result, std::string& error) {
    const ea_t ea = arg_ea(a, "addr");
    if (!jumpto(ea)) {
        error = "IDA could not move the cursor to " + hex(ea);
        return false;
    }
    result = "cursor at " + hex(ea);
    return true;
}

bool pseudocode_available() { return is_idaq() && decompiler::hexrays_available(); }

bool run_open_pseudocode(const json& a, std::string& result, std::string& error) {
    const ea_t ea = arg_ea(a, "func_addr");
#if IDASQL_HAS_EA_API
    const ea_t start = get_func_start(ea);
#else
    const func_t* f = get_func(ea);
    const ea_t start = f != nullptr ? f->start_ea : BADADDR;
#endif
    if (start == BADADDR) {
        error = "no function contains " + hex(ea);
        return false;
    }
    if (!decompiler::hexrays_available()) {
        error = "the Hex-Rays decompiler is not available";
        return false;
    }
    if (open_pseudocode(start, OPF_REUSE) == nullptr) {
        error = "IDA could not open the pseudocode of the function at " + hex(start);
        return false;
    }
    result = "pseudocode of " + hex(start);
    return true;
}

bool run_open_link(const json& a, std::string& result, std::string& error) {
    const std::string uri = a["uri"].get<std::string>();
    if (!deep_links::open_link(uri, error)) return false;
    result = "opened " + uri;
    return true;
}

bool run_batch_mode(const json& a, std::string& result, std::string&) {
    batch = a.contains("on") ? a["on"].get<bool>() : !batch;
    result = batch ? "batch mode on" : "batch mode off";
    return true;
}

bool run_toggle_breakpoint(const json& a, std::string& result, std::string& error) {
    const ea_t ea = arg_ea(a, "addr");
    if (exist_bpt(ea)) {
        if (!del_bpt(ea)) {
            error = "IDA could not remove the breakpoint at " + hex(ea);
            return false;
        }
        result = "removed the breakpoint at " + hex(ea);
    } else {
        if (!add_bpt(ea, 0, BPT_DEFAULT)) {
            error = "IDA could not add a breakpoint at " + hex(ea);
            return false;
        }
        result = "added a breakpoint at " + hex(ea);
    }
    return true;
}

bool run_run_to(const json& a, std::string& result, std::string& error) {
    const ea_t ea = arg_ea(a, "addr");
    if (!run_to(ea)) {
        error = "the debugger could not run to " + hex(ea);
        return false;
    }
    result = "running to " + hex(ea);
    return true;
}

struct Handler {
    const char* name;
    RunFn run;
    AvailFn available;
};

const Handler kHandlers[] = {
    {"quit", run_quit, quit_available},
    {"jump_to", run_jump_to, in_gui},
    {"open_pseudocode", run_open_pseudocode, pseudocode_available},
    {"open_link", run_open_link, in_gui},
    {"batch_mode", run_batch_mode, always},
    {"toggle_breakpoint", run_toggle_breakpoint, always},
    {"run_to", run_run_to, in_gui},
};

const Handler* find_handler(const std::string& name) {
    for (const auto& h : kHandlers)
        if (name == h.name) return &h;
    return nullptr;
}

bool in_this_build(const CatalogEntry& e) { return e.min_ida <= IDA_SDK_VERSION; }

std::string raw_description(const char* name) {
    qstring label, tip;
    get_action_label(&label, name);
    get_action_tooltip(&tip, name);
    std::string d;
    for (char c : std::string(label.c_str()))
        if (c != '~') d.push_back(c);
    const std::string t = tip.c_str();
    if (!t.empty() && t != d) d += d.empty() ? t : " - " + t;
    return d;
}

void build_rows(std::vector<ActionRow>& rows) {
    std::set<std::string> wrapped;
    for (const auto& e : kCatalog) {
        if (!in_this_build(e)) continue;
        ActionRow r;
        r.name = e.name;
        r.kind = e.kind;
        r.description = e.description;
        r.arg_spec = e.arg_spec;
        r.where = e.where;
        r.id = row_id(r.name);
        if (e.ida_action != nullptr) {
            r.ida_action = e.ida_action;
            wrapped.insert(e.ida_action);
            r.available = (is_idaq() && ida_action_enabled(e.ida_action)) ? 1 : 0;
            if (is_idaq()) r.checked = ida_action_checked(e.ida_action);
        } else {
            const Handler* h = find_handler(r.name);
            r.available = (h != nullptr && h->available()) ? 1 : 0;
            if (r.name == "batch_mode") r.checked = batch ? 1 : 0;
        }
        rows.push_back(std::move(r));
    }
    if (!is_idaq()) return;
    qstrvec_t names;
    get_registered_actions(&names);
    for (const qstring& qn : names) {
        const std::string n = qn.c_str();
        if (wrapped.count(n) != 0) continue;
        ActionRow r;
        r.name = n;
        r.kind = "raw";
        r.ida_action = n;
        r.description = raw_description(n.c_str());
        r.arg_spec = "{}";
        r.where = "gui";
        r.id = row_id(n);
        r.available = ida_action_enabled(n.c_str()) ? 1 : 0;
        r.checked = ida_action_checked(n.c_str());
        rows.push_back(std::move(r));
    }
}

bool fail(const std::string& message) {
    xsql::set_vtab_error("ui_actions: " + message);
    return false;
}

void record(const std::string& name, std::optional<std::string> result, std::optional<std::string> error) {
    std::lock_guard<std::mutex> lock(g_last_m);
    g_last[name] = LastRun{std::move(result), std::move(error)};
}

LastRun last_of(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_last_m);
    auto it = g_last.find(name);
    return it == g_last.end() ? LastRun{} : it->second;
}

bool set_args(ActionRow& row, xsql::FunctionArg v) {
    if (v.is_null()) {
        t_stmt.args.erase(row.id);
    } else {
        t_stmt.args[row.id] = v.as_text();
    }
    return true;
}

bool set_run(ActionRow& row, xsql::FunctionArg v) {
    if (v.is_null() || v.as_int() == 0) return true;
    if (v.as_int() != 1) return fail("run is 1 (run it) or 0");
    if (t_stmt.ran) {
        return fail("one action per statement: '" + t_stmt.ran_name +
                    "' already ran; narrow the WHERE to one row (WHERE name = '...')");
    }
    t_stmt.ran = true;
    t_stmt.ran_name = row.name;
    const auto args_it = t_stmt.args.find(row.id);
    const std::string args_text = args_it == t_stmt.args.end() ? std::string() : args_it->second;

    std::string result, error;
    bool ok = false;
    if (row.kind == "idasql") {
        json args;
        const Handler* h = find_handler(row.name);
        if (h == nullptr) {
            error = "idasql has no handler for " + row.name;
        } else if (read_args(row.arg_spec, args_text, args, error)) {
            if (row.where == "gui" && !h->available()) {
                error = "needs an IDA window (not available under idalib)";
            } else {
                ok = h->run(args, result, error);
            }
        }
    } else {
        json ignored;
        const std::string action = row.ida_action.value_or(row.name);
        action_state_t st = AST_DISABLE;
        if (!read_args("{}", args_text, ignored, error)) {
        } else if (!is_idaq()) {
            error = "there are no UI actions here (no IDA window; idalib)";
        } else if (!get_action_state(action.c_str(), &st)) {
            error = "IDA has no action " + action;
        } else if (!is_action_enabled(st)) {
            error = action + " is disabled now (" + std::string(state_name(st)) + ")";
        } else if (!process_ui_action(action.c_str())) {
            error = "IDA did not run " + action;
        } else {
            result = "ran " + action;
            ok = true;
        }
    }
    if (ok) {
        record(row.name, result, std::nullopt);
        return true;
    }
    record(row.name, std::nullopt, error);
    return fail(row.name + ": " + error);
}

xsql::TransactionHooks statement_end_hooks() {
    xsql::TransactionHooks h;
    h.commit = [](const xsql::TransactionHooks::State&) { reset_statement(); };
    h.rollback = [](const xsql::TransactionHooks::State&) { reset_statement(); };
    return h;
}

}

void set_quit_handler(QuitHandler handler) {
    std::lock_guard<std::mutex> lock(g_handler_m);
    g_handler = std::move(handler);
}

bool request_quit(bool save, std::string& error) {
    if (is_idaq()) {
        execute_sync(*new QuitRequest(save), MFF_NOWAIT);
        return true;
    }
    QuitHandler h;
    {
        std::lock_guard<std::mutex> lock(g_handler_m);
        h = g_handler;
    }
    if (!h) {
        error = "this idasql session serves no SQL server, so nothing can close it from outside; "
                "quit it where it runs";
        return false;
    }
    return h(save, error);
}

std::vector<std::string> catalog_problems() {
    std::vector<std::string> out;
    for (const auto& e : kCatalog) {
        if (!in_this_build(e)) continue;
        if (std::string(e.kind) == "idasql" && find_handler(e.name) == nullptr)
            out.push_back(std::string(e.name) + ": no handler");
        if (std::string(e.kind) == "ida" && e.ida_action == nullptr)
            out.push_back(std::string(e.name) + ": no ida_action");
    }
    return out;
}

Registry::Registry()
    : table(cached_table<ActionRow>("ui_actions")
                .no_shared_cache()
                .counts_as_write(false)
                .estimate_rows([]() -> size_t { return is_idaq() ? 900 : 16; })
                .cache_builder([](std::vector<ActionRow>& rows) {
                    reset_statement();
                    build_rows(rows);
                })
                .column_text("name", [](const ActionRow& r) -> std::string { return r.name; })
                .column_text("kind", [](const ActionRow& r) -> std::string { return r.kind; })
                .column_text_nullable("ida_action", [](const ActionRow& r) { return r.ida_action; })
                .column_text("description", [](const ActionRow& r) -> std::string { return r.description; })
                .column_text("arg_spec", [](const ActionRow& r) -> std::string { return r.arg_spec; })
                .column_text("works_in", [](const ActionRow& r) -> std::string { return r.where; })
                .column_int("available", [](const ActionRow& r) { return r.available; })
                .column_int_nullable("checked", [](const ActionRow& r) { return r.checked; })
                .column_text_nullable_rw("args", [](const ActionRow&) { return std::optional<std::string>(); },
                                         set_args)
                .column_int_rw("run", [](const ActionRow&) { return 0; }, set_run)
                .column_text_nullable("last_result", [](const ActionRow& r) { return last_of(r.name).result; })
                .column_text_nullable("last_error", [](const ActionRow& r) { return last_of(r.name).error; })
                .rowid([](const ActionRow& r) -> int64_t { return r.id; })
                .row_lookup([](ActionRow& row, int64_t id) -> bool {
                    std::vector<ActionRow> rows;
                    build_rows(rows);
                    for (auto& r : rows) {
                        if (r.id == id) {
                            row = std::move(r);
                            return true;
                        }
                    }
                    return false;
                })
                .transaction_hooks(statement_end_hooks())
                .build()) {}

void Registry::register_all(xsql::Database& db) {
    db.register_cached_table("ui_actions", &table);
    db.create_table("ui_actions", "ui_actions");
}

}
}
