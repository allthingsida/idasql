// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * deep_links_tables.cpp - the SQL surface for IDA 9.4 deep links.
 *
 *   deep_links        generator: WHERE resource = ... AND addr|rva|name = ... -> one link
 *   deep_link_parse   generator: WHERE uri = ... -> the link's parts, validated
 *   ida_open_link()   scalar: navigate (in-process in the GUI plugin, IPC otherwise)
 *   enable_deep_link_navigation   runtime setting gating ida_open_link()
 *
 * The link format and the IPC client live in deep_link.hpp. Everything here exists
 * only in IDA 9.4+ builds (IDASQL_HAS_DEEP_LINKS); older builds register nothing.
 */

#include <idasql/fwd.hpp>

#include <xsql/database.hpp>

#include "ida_headers.hpp"

#if IDASQL_HAS_DEEP_LINKS

#include "decompiler.hpp"
#include "deep_link.hpp"

#include <idasql/runtime_settings.hpp>

#include <xsql/vtable.hpp>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

namespace idasql {
namespace deep_links {

namespace dl = ::idasql::deep_link;

namespace {

constexpr const char* kNavSetting = "enable_deep_link_navigation";

// The setting lives in the typed runtime-settings registry.
void register_nav_setting(RuntimeSettings& settings) {
    (void)settings.register_bool_setting(kNavSetting, false, "idasql");
}

bool nav_setting(const RuntimeSettings& settings) {
    return settings.bool_value(kNavSetting, false);
}

void set_nav_setting(RuntimeSettings& settings, bool on) {
    (void)settings.apply(kNavSetting, on ? "1" : "0", "idasql");
}

std::string current_idb_path() {
    const char* p = get_path(PATH_TYPE_IDB);
    return p ? std::string(p) : std::string();
}

std::string current_idb_name() {
    const std::string path = current_idb_path();
    const size_t pos = path.find_last_of("/\\");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

// A UTF-8 path (links carry UTF-8) as a filesystem path on every platform.
std::filesystem::path utf8_path(const std::string& s) {
    return std::filesystem::path(std::u8string(s.begin(), s.end()));
}

// IDA's own check for "does this address resolve to this resource" (the ones that
// are cheap to ask here); the rest IDA verifies when the link is opened.
std::string entity_problem(const std::string& resource, ea_t ea) {
    if (resource == "functions") {
        if (idasql_func_start(ea) == BADADDR) return "No function at address " + dl::format_hex(ea);
    } else if (resource == "addresses" || resource == "bookmarks") {
        if (!is_mapped(ea)) return "Address " + dl::format_hex(ea) + " is not mapped in database";
    } else if (resource == "strings") {
        if (!is_strlit(get_flags(ea))) return "No string at address " + dl::format_hex(ea);
    } else if (resource == "segments") {
        idasql_segment_info_t si;
        if (!idasql_segment_info(ea, &si)) return "No segment at address " + dl::format_hex(ea);
    } else if (resource == "names") {
        qstring name;
        if (get_ea_name(&name, ea) <= 0 || name.empty()) return "No name at address " + dl::format_hex(ea);
    }
    return {};
}

// A link should open code. IDA's own default for most resources is a list window
// (the Functions or Strings chooser), which is rarely what a reader wants: functions
// open pseudocode (disassembly without a decompiler), everything with an address
// opens disassembly, types open the type. An explicit view always wins.
std::string code_view(const std::string& resource) {
    if (resource == "functions") return decompiler::hexrays_available() ? "pseudocode" : "disasm";
    for (const auto& v : dl::allowed_views(resource)) {
        if (v == "disasm") return v;
    }
    return dl::default_view(resource);
}

// ---------------------------------------------------------------------------
// deep_links
// ---------------------------------------------------------------------------

enum DeepLinkColumn : int {
    COL_URI = 0,
    COL_RESOURCE,
    COL_VIEW,
    COL_EA,
    COL_RVA,
    COL_NAME,
    COL_IDB_NAME,
    COL_SOURCE,
    COL_ADDRESS_MODE,
    COL_VALID,
    COL_DIAGNOSTIC,
    COL_DEFAULT_VIEW,
    COL_ALLOWED_VIEWS,
    COL_IMAGE_BASE,
};

struct DeepLinkRow {
    std::string uri;
    std::string resource;
    std::string view;
    std::optional<int64_t> ea;
    std::optional<int64_t> rva;
    std::string name;
    std::string idb_name;
    std::string source;
    std::string address_mode = "auto";
    bool valid = false;
    std::string diagnostic;
    std::string default_view;
    std::string allowed_views;
    int64_t image_base = 0;
};

template <typename Row>
class OneRowGenerator final : public xsql::Generator<Row> {
public:
    explicit OneRowGenerator(Row row) : row_(std::move(row)) {}
    bool next() override {
        if (done_) return false;
        done_ = true;
        return true;
    }
    const Row& current() const override { return row_; }
    int64_t rowid() const override { return 1; }

private:
    Row row_;
    bool done_ = false;
};

std::string text_of(const xsql::FunctionArg& v) {
    const char* t = v.as_c_str();
    return t ? std::string(t) : std::string();
}

std::unique_ptr<xsql::Generator<DeepLinkRow>> make_deep_link(const std::vector<xsql::GeneratorConstraintArg>& args) {
    DeepLinkRow row;
    std::optional<std::string> idb_name_arg;
    // The row echoes its constraints, which are omit=1: a value its column
    // could never hold (addr = 4096.5, addr = NULL, resource = NULL) has no
    // row, rather than a row carrying the truncated or empty value.
    for (const auto& arg : args) {
        if (arg.op != xsql::ConstraintOp::Eq) continue;
        if (arg.column_index == COL_EA || arg.column_index == COL_RVA) {
            const std::optional<int64_t> value = xsql::exact_int64(arg.value);
            if (!value) return nullptr;
            (arg.column_index == COL_EA ? row.ea : row.rva) = *value;
            continue;
        }
        std::string* text = nullptr;
        switch (arg.column_index) {
            case COL_RESOURCE: text = &row.resource; break;
            case COL_VIEW: text = &row.view; break;
            case COL_NAME: text = &row.name; break;
            case COL_IDB_NAME: text = &idb_name_arg.emplace(); break;
            case COL_SOURCE: text = &row.source; break;
            case COL_ADDRESS_MODE: text = &row.address_mode; break;
            default: break;
        }
        if (!text) continue;
        std::optional<std::string> value = xsql::exact_text(arg.value);
        if (!value) return nullptr;
        *text = std::move(*value);
    }

    const uint64_t image_base = static_cast<uint64_t>(get_imagebase());
    row.image_base = static_cast<int64_t>(image_base);
    row.idb_name = idb_name_arg ? *idb_name_arg : current_idb_name();
    row.default_view = code_view(row.resource);
    {
        std::string list;
        for (const auto& v : dl::allowed_views(row.resource)) list += (list.empty() ? "" : ",") + v;
        row.allowed_views = list;
    }

    auto invalid = [&](std::string why) {
        row.valid = false;
        row.diagnostic = std::move(why);
        return std::make_unique<OneRowGenerator<DeepLinkRow>>(row);
    };

    dl::LinkTarget target;
    target.source = row.source;
    target.idb_name = row.idb_name;
    target.resource = row.resource;
    target.view = row.view.empty() ? row.default_view : row.view;
    // The path belongs to this database: a link for another one, or for none, has none.
    if (row.idb_name == current_idb_name()) target.idb_path = current_idb_path();

    if (row.resource == "types") {
        target.name = row.name;
        if (!row.name.empty()) {
            tinfo_t tif;
            if (!tif.get_named_type(get_idati(), row.name.c_str())) {
                return invalid("Type '" + row.name + "' not found");
            }
        }
    } else if (dl::is_resource(row.resource)) {
        if (row.ea && row.rva) return invalid("addr and rva are mutually exclusive");
        if (!row.ea && !row.rva) return invalid("deep_links needs addr or rva");
        const uint64_t ea = row.ea ? static_cast<uint64_t>(*row.ea) : image_base + static_cast<uint64_t>(*row.rva);
        if (!row.ea) row.ea = static_cast<int64_t>(ea);
        const std::string mode = row.address_mode;
        if (mode != "auto" && mode != "rva" && mode != "ea") {
            return invalid("addr_mode must be 'auto', 'rva' or 'ea'");
        }
        if (mode == "ea") {
            target.ea = ea;
        } else if (ea >= image_base) {
            target.rva = ea - image_base;
        } else if (mode == "rva") {
            return invalid("Address " + dl::format_hex(ea) + " is below the image base " +
                           dl::format_hex(image_base) + "; no rva form exists");
        } else {
            target.ea = ea;
        }
        if (!row.rva && target.rva) row.rva = static_cast<int64_t>(*target.rva);
        if (const std::string problem = entity_problem(row.resource, static_cast<ea_t>(ea)); !problem.empty()) {
            return invalid(problem);
        }
    }

    const dl::BuildResult link = dl::build(target);
    if (!link.valid) return invalid(link.diagnostic);
    row.uri = link.uri;
    if (row.view.empty()) row.view = link.view;
    row.valid = true;
    return std::make_unique<OneRowGenerator<DeepLinkRow>>(row);
}

void result_opt_int(xsql::FunctionContext& ctx, const std::optional<int64_t>& v) {
    if (v) {
        ctx.result_int64(*v);
    } else {
        ctx.result_null();
    }
}

void result_opt_text(xsql::FunctionContext& ctx, const std::string& v) {
    if (v.empty()) {
        ctx.result_null();
    } else {
        ctx.result_text(v);
    }
}

xsql::GeneratorTableDef<DeepLinkRow> define_deep_links() {
    using xsql::ColumnType;
    return xsql::generator_table<DeepLinkRow>("deep_links")
        .column("uri", ColumnType::Text, [](xsql::FunctionContext& c, const DeepLinkRow& r) { result_opt_text(c, r.uri); })
        .column_text("resource", [](const DeepLinkRow& r) { return r.resource; })
        .column("view", ColumnType::Text, [](xsql::FunctionContext& c, const DeepLinkRow& r) { result_opt_text(c, r.view); })
        .column("addr", ColumnType::Integer, [](xsql::FunctionContext& c, const DeepLinkRow& r) { result_opt_int(c, r.ea); })
        .column("rva", ColumnType::Integer, [](xsql::FunctionContext& c, const DeepLinkRow& r) { result_opt_int(c, r.rva); })
        .column("name", ColumnType::Text, [](xsql::FunctionContext& c, const DeepLinkRow& r) { result_opt_text(c, r.name); })
        .column_text("idb_name", [](const DeepLinkRow& r) { return r.idb_name; })
        .column_text("source", [](const DeepLinkRow& r) { return r.source; })
        .column_text("addr_mode", [](const DeepLinkRow& r) { return r.address_mode; })
        .column_int("valid", [](const DeepLinkRow& r) { return r.valid ? 1 : 0; })
        .column("diagnostic", ColumnType::Text,
                [](xsql::FunctionContext& c, const DeepLinkRow& r) { result_opt_text(c, r.diagnostic); })
        .column_text("default_view", [](const DeepLinkRow& r) { return r.default_view; })
        .column_text("allowed_views", [](const DeepLinkRow& r) { return r.allowed_views; })
        .column_int64("image_base", [](const DeepLinkRow& r) { return r.image_base; })
        .full_scan_error(
            "deep_links requires WHERE resource = '<resource>' plus the target "
            "(addr = <addr>, rva = <offset>, or name = '<type>' for resource 'types'); "
            "join it per row, e.g. JOIN deep_links dl ON dl.resource = 'functions' AND dl.addr = f.addr")
        // One filter per coordinate, each requiring resource AND its coordinate. With
        // resource alone usable, no filter matches, so the planner never puts
        // deep_links on the outer side of a join (where it would see no address and
        // emit nothing): it drives the join from the other table and feeds one
        // address per row into here.
        .constraint_filter(
            {
                xsql::required_eq("resource", "deep_links requires WHERE resource = '<resource>'"),
                xsql::required_eq("addr", "deep_links requires WHERE addr = <addr> (or rva / name)"),
                xsql::optional_eq("rva"),  // only so ea AND rva can be reported as exclusive
                xsql::optional_eq("view"),
                xsql::optional_eq("idb_name"),
                xsql::optional_eq("source"),
                xsql::optional_eq("addr_mode"),
            },
            make_deep_link, 1.0, 1.0)
        .constraint_filter(
            {
                xsql::required_eq("resource", "deep_links requires WHERE resource = '<resource>'"),
                xsql::required_eq("rva", "deep_links requires WHERE rva = <offset> (or addr / name)"),
                xsql::optional_eq("view"),
                xsql::optional_eq("idb_name"),
                xsql::optional_eq("source"),
                xsql::optional_eq("addr_mode"),
            },
            make_deep_link, 1.0, 1.0)
        .constraint_filter(
            {
                xsql::required_eq("resource", "deep_links requires WHERE resource = '<resource>'"),
                xsql::required_eq("name", "deep_links requires WHERE name = '<type>' (or addr / rva)"),
                xsql::optional_eq("view"),
                xsql::optional_eq("idb_name"),
                xsql::optional_eq("source"),
                xsql::optional_eq("addr_mode"),
            },
            make_deep_link, 1.0, 1.0)
        .build();
}

// ---------------------------------------------------------------------------
// deep_link_parse
// ---------------------------------------------------------------------------

struct ParseRow {
    std::string uri;
    dl::ParsedLink link;
};

std::unique_ptr<xsql::Generator<ParseRow>> make_parse(const std::vector<xsql::GeneratorConstraintArg>& args) {
    ParseRow row;
    for (const auto& arg : args) {
        if (arg.column_index != 0 || arg.op != xsql::ConstraintOp::Eq) continue;
        std::optional<std::string> uri = xsql::exact_text(arg.value);
        if (!uri) return nullptr;  // uri = NULL (omit=1) parses nothing
        row.uri = std::move(*uri);
    }
    row.link = dl::parse(row.uri);
    return std::make_unique<OneRowGenerator<ParseRow>>(row);
}

xsql::GeneratorTableDef<ParseRow> define_deep_link_parse() {
    using xsql::ColumnType;
    auto text = [](auto get) {
        return [get](xsql::FunctionContext& c, const ParseRow& r) { result_opt_text(c, get(r)); };
    };
    return xsql::generator_table<ParseRow>("deep_link_parse")
        .column_text("uri", [](const ParseRow& r) { return r.uri; })
        .column("source", ColumnType::Text, text([](const ParseRow& r) { return r.link.target.source; }))
        .column("idb_name", ColumnType::Text, text([](const ParseRow& r) { return r.link.target.idb_name; }))
        .column("resource", ColumnType::Text, text([](const ParseRow& r) { return r.link.target.resource; }))
        .column("addr", ColumnType::Integer,
                [](xsql::FunctionContext& c, const ParseRow& r) {
                    result_opt_int(c, r.link.target.ea ? std::optional<int64_t>(static_cast<int64_t>(*r.link.target.ea))
                                                       : std::nullopt);
                })
        .column("rva", ColumnType::Integer,
                [](xsql::FunctionContext& c, const ParseRow& r) {
                    result_opt_int(c, r.link.target.rva
                                          ? std::optional<int64_t>(static_cast<int64_t>(*r.link.target.rva))
                                          : std::nullopt);
                })
        .column("name", ColumnType::Text, text([](const ParseRow& r) { return r.link.target.name; }))
        .column("view", ColumnType::Text, text([](const ParseRow& r) { return r.link.target.view; }))
        .column("idb_path", ColumnType::Text, text([](const ParseRow& r) { return r.link.target.idb_path; }))
        .column_int("is_ke", [](const ParseRow& r) { return r.link.is_ke ? 1 : 0; })
        .column_int("valid", [](const ParseRow& r) { return r.link.valid ? 1 : 0; })
        .column("diagnostic", ColumnType::Text, text([](const ParseRow& r) { return r.link.diagnostic; }))
        .column("ida_uri", ColumnType::Text, text([](const ParseRow& r) { return dl::to_ida_uri(r.link); }))
        .full_scan_error("deep_link_parse requires WHERE uri = '<ida:// link>'")
        .constraint_filter({xsql::required_eq("uri", "deep_link_parse requires WHERE uri = '<link>'")}, make_parse,
                           1.0, 1.0)
        .build();
}

// ---------------------------------------------------------------------------
// ida_open_link(uri)
// ---------------------------------------------------------------------------

void sql_ida_open_link_impl(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc != 1 || argv[0].is_null()) {
        ctx.result_error("ida_open_link(uri) requires one ida:// link");
        return;
    }
    if (!nav_setting(runtime_settings())) {
        ctx.result_error(
            "deep-link navigation is disabled; enable it with UPDATE runtime_settings SET value='1' "
            "WHERE key='enable_deep_link_navigation'");
        return;
    }
    const std::string uri = text_of(argv[0]);
    if (const std::string why = dl::screen_untrusted_uri(uri); !why.empty()) {
        ctx.result_error("ida_open_link: " + why);
        return;
    }
    const dl::ParsedLink link = dl::parse(uri);
    if (!link.valid) {
        ctx.result_error("ida_open_link: invalid link: " + link.diagnostic);
        return;
    }
    const std::string ida_uri = dl::to_ida_uri(link);
    if (ida_uri.empty()) {
        ctx.result_error("ida_open_link: invalid link: cannot be re-encoded for IDA");
        return;
    }

    // The other running IDA 9.4 instances, over their IPC endpoints. In the GUI never
    // our own endpoint: its server runs on the UI thread this query is blocking, so
    // asking ourselves would deadlock. (idalib runs no IPC server, so there is
    // nothing of ours to skip.) This runs on IDA's UI thread too, so discovery uses
    // short timeouts; only the navigation itself gets the full IO timeout.
    const bool in_gui = !idasql_is_ida_library();
    const uint64_t self = dl::current_pid();
    const dl::IpcOptions nav_options = dl::effective_ipc_options();
    dl::IpcOptions discovery = nav_options;
    discovery.connect_timeout_ms = (std::min)(discovery.connect_timeout_ms, 500);
    discovery.io_timeout_ms = (std::min)(discovery.io_timeout_ms, 2000);
    std::vector<dl::Instance> instances;
    for (auto& i : dl::list_instances(discovery)) {
        if (!in_gui || i.pid != self) instances.push_back(std::move(i));
    }

    // The exact file is on this machine: a same-named database elsewhere is a
    // different database, never a stand-in for it.
    const auto& t = link.target;
    std::error_code ec;
    const bool allow_name_fallback = t.idb_path.empty() || !std::filesystem::exists(utf8_path(t.idb_path), ec);
    // In the GUI, a link for this database (or for no particular one) opens right
    // here; we already run on the UI thread (SQL is dispatched with execute_sync).
    const dl::SessionChoice choice =
        dl::choose_from_session(instances, t, in_gui ? current_idb_path() : std::string(), allow_name_fallback);
    if (in_gui && choice.here) {
        if (open_ida_link(ida_uri.c_str())) {
            ctx.result_int(1);
        } else {
            ctx.result_error("IDA could not open " + ida_uri + " (the reason is in the Output window)");
        }
        return;
    }
    // Under idalib "here" is not a place a link can open (no UI); steer instead.
    const dl::Selection sel =
        in_gui ? choice.other : dl::select_instance(instances, t, std::nullopt, allow_name_fallback);
    if (!sel.chosen) {
        std::string text = "ida_open_link: " + sel.error;
        for (const auto& c : sel.candidates) text += "; PID " + std::to_string(c.pid) + " has " + c.idb_path;
        ctx.result_error(text);
        return;
    }
    std::string message;
    if (dl::open_in({sel.chosen->pid, sel.chosen->endpoint}, ida_uri, message, nav_options)) {
        ctx.result_int(1);
    } else {
        ctx.result_error("IDA (PID " + std::to_string(sel.chosen->pid) + ") could not open " + ida_uri + ": " +
                         message);
    }
}

// A scalar runs inside SQLite's C frames: nothing may escape it.
void sql_ida_open_link(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    try {
        sql_ida_open_link_impl(ctx, argc, argv);
    } catch (const std::exception& e) {
        ctx.result_error(std::string("ida_open_link: internal error: ") + e.what());
    } catch (...) {
        ctx.result_error("ida_open_link: internal error");
    }
}

}  // namespace

bool register_deep_links(xsql::Database& db) {
    register_nav_setting(runtime_settings());

    static auto deep_links = define_deep_links();
    static auto parse = define_deep_link_parse();
    bool ok = db.register_generator_table("deep_links", &deep_links) && db.create_table("deep_links", "deep_links") &&
              db.register_generator_table("deep_link_parse", &parse) &&
              db.create_table("deep_link_parse", "deep_link_parse");

    ok = db.register_function("ida_open_link", 1, xsql::ScalarFn(sql_ida_open_link)) == xsql::Status::ok && ok;
    return ok;
}

void enable_navigation_default_for_gui() { set_nav_setting(runtime_settings(), true); }

}  // namespace deep_links
}  // namespace idasql

#else  // IDA SDK before 9.4: no deep links.

namespace idasql {
namespace deep_links {
bool register_deep_links(xsql::Database&) { return true; }
void enable_navigation_default_for_gui() {}
}  // namespace deep_links
}  // namespace idasql

#endif
