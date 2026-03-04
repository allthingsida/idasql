// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

#include <idasql/platform.hpp>

#include <algorithm>
#include <exception>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "ida_headers.hpp"

#include <xsql/json.hpp>
#include "idapython_exec.hpp"
#include <idasql/ui_context_provider.hpp>

namespace idasql {
namespace ui_context {
namespace {

static const int k_selection_preview_lines = 10;
static const char* k_capture_action_name = "idasql:capture_ui_context";
static const char* k_snapshot_marker = "__IDASQL_UI_CTX__";

struct UiActionContextSnapshot {
    bool valid = false;

    int widget_type = -1;
    std::string widget_title;

    bool has_cur_ea = false;
    uint64_t cur_ea = 0;

    bool focus_known = false;
    bool focus = false;

    uint64_t sequence = 0;
    int64_t timestamp_ms = 0;

    xsql::json chooser_rows = xsql::json::array();
};

struct CaptureMetadata {
    std::string source = "viewer_fallback";
    bool fresh = false;
    bool have_sequence = false;
    uint64_t sequence = 0;
    bool have_timestamp = false;
    int64_t timestamp_ms = 0;
    std::string error;
};

struct ContextSourceData {
    bool has_widget = false;
    twidget_type_t widget_type = static_cast<twidget_type_t>(-1);
    bool have_title = false;
    std::string widget_title;

    bool focus_known = false;
    bool focus = false;

    ea_t current_ea = BADADDR;
    TWidget* viewer = nullptr;

    bool have_chooser_rows = false;
    xsql::json chooser_rows = xsql::json::array();
};

static const char* k_install_helper_code = R"PY(
import builtins
import json
import time
import idaapi
import ida_kernwin

_ACTION_NAME = "idasql:capture_ui_context"
_SNAPSHOT_KEY = "__idasql_ui_ctx_snapshot_json__"
_SEQUENCE_KEY = "__idasql_ui_ctx_sequence__"
_HANDLER_KEY = "__idasql_ui_ctx_handlers__"

def _idasql_unregister_action():
    try:
        if ida_kernwin.get_action_state(_ACTION_NAME) is not None:
            ida_kernwin.unregister_action(_ACTION_NAME)
    except Exception:
        try:
            ida_kernwin.unregister_action(_ACTION_NAME)
        except Exception:
            pass

class _IDASQLCaptureHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        snap = {}
        seq = int(getattr(builtins, _SEQUENCE_KEY, 0)) + 1
        setattr(builtins, _SEQUENCE_KEY, seq)

        snap["sequence"] = seq
        snap["timestamp_ms"] = int(time.time() * 1000)
        snap["widget_type"] = None
        snap["widget_title"] = ""
        snap["cur_ea"] = None
        snap["focus"] = bool(getattr(ctx, "focus")) if hasattr(ctx, "focus") else None

        widget = getattr(ctx, "widget", None)
        if widget is not None:
            try:
                wt = ida_kernwin.get_widget_type(widget)
                snap["widget_type"] = int(wt)
            except Exception:
                pass

            try:
                title = ida_kernwin.get_widget_title(widget)
                if title is not None:
                    snap["widget_title"] = str(title)
            except Exception:
                pass

        if snap["widget_type"] is None and hasattr(ctx, "widget_type"):
            try:
                snap["widget_type"] = int(getattr(ctx, "widget_type"))
            except Exception:
                pass

        if not snap["widget_title"] and hasattr(ctx, "widget_title"):
            try:
                title = getattr(ctx, "widget_title")
                if title is not None:
                    snap["widget_title"] = str(title)
            except Exception:
                pass

        try:
            cur_ea = int(getattr(ctx, "cur_ea", idaapi.BADADDR))
            if cur_ea != idaapi.BADADDR:
                snap["cur_ea"] = cur_ea
        except Exception:
            pass

        rows = []
        title = snap.get("widget_title", "")
        if title:
            selected = None
            try:
                selected = ida_kernwin.get_chooser_rows(title, ida_kernwin.GCRF_SELECTION)
            except Exception:
                selected = None
            if not selected:
                try:
                    selected = ida_kernwin.get_chooser_rows(title, ida_kernwin.GCRF_CURRENT)
                except Exception:
                    selected = None
            if selected:
                for row in selected:
                    cols = []
                    for text in getattr(row, "texts", []):
                        cols.append(str(text))
                    icon = getattr(row, "icon", -1)
                    try:
                        icon = int(icon)
                    except Exception:
                        icon = -1
                    rows.append({"columns": cols, "icon": icon})

        snap["chooser_rows"] = rows
        setattr(builtins, _SNAPSHOT_KEY, json.dumps(snap, ensure_ascii=True))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

_idasql_unregister_action()
handler = _IDASQLCaptureHandler()
desc = ida_kernwin.action_desc_t(
    _ACTION_NAME,
    "idasql: Capture UI context",
    handler,
    None,
    "Capture UI context for SQL context queries",
    -1
)
if not ida_kernwin.register_action(desc):
    raise RuntimeError("Failed to register idasql capture action")

if not hasattr(builtins, _HANDLER_KEY):
    setattr(builtins, _HANDLER_KEY, {})
getattr(builtins, _HANDLER_KEY)[_ACTION_NAME] = handler
)PY";

static const char* k_uninstall_helper_code = R"PY(
import builtins
import ida_kernwin

_ACTION_NAME = "idasql:capture_ui_context"
_HANDLER_KEY = "__idasql_ui_ctx_handlers__"

try:
    if ida_kernwin.get_action_state(_ACTION_NAME) is not None:
        ida_kernwin.unregister_action(_ACTION_NAME)
except Exception:
    try:
        ida_kernwin.unregister_action(_ACTION_NAME)
    except Exception:
        pass

if hasattr(builtins, _HANDLER_KEY):
    handlers = getattr(builtins, _HANDLER_KEY)
    if isinstance(handlers, dict) and _ACTION_NAME in handlers:
        del handlers[_ACTION_NAME]
)PY";

static const char* k_read_snapshot_code = R"PY(
import builtins
snapshot = getattr(builtins, "__idasql_ui_ctx_snapshot_json__", "")
print("__IDASQL_UI_CTX__" + str(snapshot))
)PY";

static std::mutex g_capture_mutex;
static bool g_helper_installed = false;

static bool is_custom_view_widget_type(twidget_type_t widget_type) {
    return widget_type == BWN_DISASM ||
           widget_type == BWN_HEXVIEW ||
           widget_type == BWN_PSEUDOCODE ||
           widget_type == BWN_TILIST;
}

static bool is_address_widget_type(twidget_type_t widget_type) {
    return widget_type == BWN_DISASM ||
           widget_type == BWN_HEXVIEW ||
           widget_type == BWN_PSEUDOCODE;
}

static bool is_chooser_like_widget_type(twidget_type_t widget_type) {
    return is_chooser_widget(widget_type) ||
           widget_type == BWN_FUNCS ||
           widget_type == BWN_NAMES ||
           widget_type == BWN_IMPORTS ||
           widget_type == BWN_BPTS ||
           widget_type == BWN_TITREE;
}

static const char* widget_type_name(twidget_type_t widget_type) {
    switch (widget_type) {
        case BWN_DISASM: return "BWN_DISASM";
        case BWN_HEXVIEW: return "BWN_HEXVIEW";
        case BWN_PSEUDOCODE: return "BWN_PSEUDOCODE";
        case BWN_TILIST: return "BWN_TILIST";
        case BWN_OUTPUT: return "BWN_OUTPUT";
        case BWN_CLI: return "BWN_CLI";
        case BWN_FUNCS: return "BWN_FUNCS";
        case BWN_NAMES: return "BWN_NAMES";
        case BWN_IMPORTS: return "BWN_IMPORTS";
        case BWN_BPTS: return "BWN_BPTS";
        case BWN_TITREE: return "BWN_TITREE";
        default: break;
    }
    return nullptr;
}

static std::string widget_type_name_or_unknown(twidget_type_t widget_type) {
    const char* known = widget_type_name(widget_type);
    if (known != nullptr) {
        return known;
    }
    std::ostringstream out;
    out << "UNKNOWN_" << static_cast<int>(widget_type);
    return out.str();
}

static std::string format_hex_ea(ea_t ea) {
    std::ostringstream out;
    out << "0x" << std::hex << static_cast<uint64>(ea);
    return out.str();
}

static xsql::json make_selection_object(const char* kind) {
    return xsql::json{
        {"kind", kind},
        {"start", nullptr},
        {"end", nullptr},
        {"text_lines", xsql::json::array()},
        {"line_count", 0},
        {"rows", xsql::json::array()},
        {"row_count", 0}
    };
}

static TWidget* get_authoritative_main_viewer() {
    TWidget* current_viewer = get_current_viewer();
    if (current_viewer != nullptr) {
        return current_viewer;
    }
    return get_current_widget();
}

static void merge_from_active_widget(ContextSourceData& source, TWidget* viewer) {
    if (viewer == nullptr) {
        return;
    }

    source.viewer = viewer;
    source.widget_type = get_widget_type(viewer);
    source.has_widget = true;

    qstring title;
    if (get_widget_title(&title, viewer)) {
        source.widget_title = title.c_str();
        source.have_title = !source.widget_title.empty();
    } else {
        source.widget_title.clear();
        source.have_title = false;
    }

    if (!source.has_widget || !is_address_widget_type(source.widget_type)) {
        // Do not keep stale action-context addresses for non-address widgets.
        source.current_ea = BADADDR;
        return;
    }

    const ea_t candidate_ea = get_screen_ea();
    if (candidate_ea != BADADDR) {
        source.current_ea = candidate_ea;
    }
}

static bool append_chooser_row(
        const std::vector<std::string>& columns,
        int icon,
        xsql::json& selection) {
    if (columns.empty()) {
        return false;
    }

    xsql::json columns_json = xsql::json::array();
    std::string display;
    for (const std::string& value : columns) {
        columns_json.push_back(value);
        if (!display.empty()) {
            display += " | ";
        }
        display += value;
    }

    xsql::json icon_value = nullptr;
    if (icon >= 0) {
        icon_value = icon;
    }

    selection["rows"].push_back({
        {"columns", std::move(columns_json)},
        {"display", display},
        {"icon", std::move(icon_value)}
    });
    selection["text_lines"].push_back(display);
    return true;
}

static bool extract_selection_preview_lines(
        TWidget* viewer,
        const twinpos_t& selection_start,
        const twinpos_t& selection_end,
        xsql::json& out_lines) {
    if (viewer == nullptr || selection_start.at == nullptr || selection_end.at == nullptr) {
        return false;
    }

    void* user_data = get_viewer_user_data(viewer);
    if (user_data == nullptr) {
        return false;
    }

    linearray_t line_array(user_data);
    line_array.set_place(selection_start.at);

    int line_count = 0;
    while (line_count < k_selection_preview_lines) {
        const place_t* current_place = line_array.get_place();
        if (current_place == nullptr) {
            break;
        }

        const int first_line_ref = l_compare2(current_place, selection_start.at, user_data);
        const int last_line_ref = l_compare2(current_place, selection_end.at, user_data);
        if (last_line_ref > 0) {
            break;
        }

        const qstring* tagged_line = line_array.down();
        if (tagged_line == nullptr) {
            break;
        }

        qstring plain = *tagged_line;
        tag_remove(&plain);
        std::string line = plain.c_str();

        if (last_line_ref == 0 && selection_end.x >= 0) {
            const size_t end_column = static_cast<size_t>(selection_end.x);
            if (end_column < line.size()) {
                line.resize(end_column);
            }
        } else if (first_line_ref == 0 && selection_start.x > 0) {
            const size_t start_column = static_cast<size_t>(selection_start.x);
            if (start_column < line.size()) {
                line = std::string(start_column, ' ') + line.substr(start_column);
            } else {
                line = std::string(start_column, ' ');
            }
        }

        out_lines.push_back(line);
        ++line_count;
    }

    return line_count > 0;
}

static bool extract_selection_preview_lines_from_eas(
        const twinpos_t& selection_start,
        const twinpos_t& selection_end,
        xsql::json& out_lines) {
    if (selection_start.at == nullptr || selection_end.at == nullptr) {
        return false;
    }

    ea_t start_ea = selection_start.at->toea();
    ea_t end_ea = selection_end.at->toea();
    if (start_ea == BADADDR || end_ea == BADADDR) {
        return false;
    }

    if (end_ea < start_ea) {
        std::swap(start_ea, end_ea);
    }

    const size_t original_size = out_lines.size();
    const size_t max_lines = static_cast<size_t>(k_selection_preview_lines);
    ea_t ea = start_ea;
    while (ea != BADADDR && ea <= end_ea && out_lines.size() < max_lines) {
        qstring plain_line;
        if (generate_disasm_line(&plain_line, ea, GENDSM_REMOVE_TAGS | GENDSM_UNHIDE)) {
            out_lines.push_back(std::string(plain_line.c_str()));
        }

        const ea_t next = next_head(ea, end_ea + 1);
        if (next == BADADDR || next <= ea) {
            break;
        }
        ea = next;
    }

    return out_lines.size() > original_size;
}

static bool extract_listing_selection(TWidget* viewer, xsql::json& out_selection) {
    twinpos_t selection_start;
    twinpos_t selection_end;
    if (!read_selection(viewer, &selection_start, &selection_end)) {
        return false;
    }

    xsql::json selection = make_selection_object("listing");
    if (selection_start.at != nullptr) {
        const ea_t start_ea = selection_start.at->toea();
        if (start_ea != BADADDR) {
            selection["start"] = format_hex_ea(start_ea);
        }
    }

    if (selection_end.at != nullptr) {
        const ea_t end_ea = selection_end.at->toea();
        if (end_ea != BADADDR) {
            selection["end"] = format_hex_ea(end_ea);
        }
    }

    (void) extract_selection_preview_lines(viewer, selection_start, selection_end, selection["text_lines"]);
    if (selection["text_lines"].empty()) {
        (void) extract_selection_preview_lines_from_eas(selection_start, selection_end, selection["text_lines"]);
    }
    selection["line_count"] = selection["text_lines"].size();

    const bool has_address_range = !selection["start"].is_null() || !selection["end"].is_null();
    const bool has_text_lines = !selection["text_lines"].empty();
    if (!has_address_range && !has_text_lines) {
        return false;
    }

    out_selection = std::move(selection);
    return true;
}

static bool extract_chooser_selection_from_widget_title(
        const std::string& widget_title,
        xsql::json& out_selection) {
    if (widget_title.empty()) {
        return false;
    }

    chooser_row_info_vec_t rows;
    bool have_rows = get_chooser_rows(&rows, widget_title.c_str(), GCRF_SELECTION);
    if (!have_rows || rows.empty()) {
        have_rows = get_chooser_rows(&rows, widget_title.c_str(), GCRF_CURRENT);
    }
    if (!have_rows || rows.empty()) {
        return false;
    }

    xsql::json selection = make_selection_object("chooser");
    for (const chooser_row_info_t& row : rows) {
        std::vector<std::string> columns;
        columns.reserve(row.texts.size());
        for (const qstring& text : row.texts) {
            columns.push_back(text.c_str());
        }
        (void) append_chooser_row(columns, row.icon, selection);
    }

    selection["line_count"] = selection["text_lines"].size();
    selection["row_count"] = selection["rows"].size();
    if (selection["row_count"].get<int>() == 0) {
        return false;
    }

    out_selection = std::move(selection);
    return true;
}

static bool extract_chooser_selection_from_snapshot_rows(
        const xsql::json& chooser_rows,
        xsql::json& out_selection) {
    if (!chooser_rows.is_array() || chooser_rows.empty()) {
        return false;
    }

    xsql::json selection = make_selection_object("chooser");
    for (const xsql::json& row : chooser_rows) {
        if (!row.is_object()) {
            continue;
        }

        std::vector<std::string> columns;
        if (row.contains("columns") && row["columns"].is_array()) {
            for (const xsql::json& col : row["columns"]) {
                if (col.is_string()) {
                    columns.push_back(col.get<std::string>());
                } else if (!col.is_null()) {
                    columns.push_back(col.dump());
                }
            }
        }

        int icon = -1;
        if (row.contains("icon") && row["icon"].is_number_integer()) {
            icon = row["icon"].get<int>();
        }

        (void) append_chooser_row(columns, icon, selection);
    }

    selection["line_count"] = selection["text_lines"].size();
    selection["row_count"] = selection["rows"].size();
    if (selection["row_count"].get<int>() == 0) {
        return false;
    }

    out_selection = std::move(selection);
    return true;
}

static bool execute_python_helper(
        const char* snippet,
        std::string* error,
        std::string* output) {
    idasql::idapython::ExecutionResult result =
        idasql::idapython::execute_snippet(snippet, "idasql.ui_context_capture");
    if (output != nullptr) {
        *output = result.output;
    }
    if (!result.success) {
        if (error != nullptr) {
            if (!result.error.empty()) {
                *error = result.error;
            } else {
                *error = "Python helper execution failed";
            }
        }
        return false;
    }
    return true;
}

static bool install_helper_unlocked(std::string* error) {
    if (g_helper_installed) {
        return true;
    }

    if (!execute_python_helper(k_install_helper_code, error, nullptr)) {
        return false;
    }

    g_helper_installed = true;
    return true;
}

static bool extract_marker_payload(
        const std::string& output,
        const char* marker,
        std::string* payload) {
    const std::string marker_text = marker;
    const size_t marker_pos = output.rfind(marker_text);
    if (marker_pos == std::string::npos) {
        return false;
    }

    const size_t payload_start = marker_pos + marker_text.size();
    size_t payload_end = output.find('\n', payload_start);
    if (payload_end == std::string::npos) {
        payload_end = output.size();
    }

    *payload = output.substr(payload_start, payload_end - payload_start);
    return true;
}

static bool parse_snapshot_json(
        const std::string& output,
        UiActionContextSnapshot& out_snapshot,
        std::string* error) {
    std::string payload;
    if (!extract_marker_payload(output, k_snapshot_marker, &payload)) {
        if (error != nullptr) {
            *error = "Context snapshot marker not found in Python output";
        }
        return false;
    }

    if (payload.empty()) {
        if (error != nullptr) {
            *error = "No action context snapshot available";
        }
        return false;
    }

    xsql::json snapshot_json;
    try {
        snapshot_json = xsql::json::parse(payload);
    } catch (const std::exception& ex) {
        if (error != nullptr) {
            *error = std::string("Failed to parse action snapshot JSON: ") + ex.what();
        }
        return false;
    }

    UiActionContextSnapshot parsed;
    parsed.valid = true;

    if (snapshot_json.contains("widget_type") && snapshot_json["widget_type"].is_number_integer()) {
        parsed.widget_type = snapshot_json["widget_type"].get<int>();
    }
    if (snapshot_json.contains("widget_title") && snapshot_json["widget_title"].is_string()) {
        parsed.widget_title = snapshot_json["widget_title"].get<std::string>();
    }
    if (snapshot_json.contains("cur_ea") && snapshot_json["cur_ea"].is_number_integer()) {
        parsed.has_cur_ea = true;
        parsed.cur_ea = snapshot_json["cur_ea"].get<uint64_t>();
    }
    if (snapshot_json.contains("focus") && snapshot_json["focus"].is_boolean()) {
        parsed.focus_known = true;
        parsed.focus = snapshot_json["focus"].get<bool>();
    }
    if (snapshot_json.contains("sequence") && snapshot_json["sequence"].is_number_integer()) {
        const int64_t seq = snapshot_json["sequence"].get<int64_t>();
        if (seq > 0) {
            parsed.sequence = static_cast<uint64_t>(seq);
        }
    }
    if (snapshot_json.contains("timestamp_ms") && snapshot_json["timestamp_ms"].is_number_integer()) {
        parsed.timestamp_ms = snapshot_json["timestamp_ms"].get<int64_t>();
    }
    if (snapshot_json.contains("chooser_rows") && snapshot_json["chooser_rows"].is_array()) {
        parsed.chooser_rows = snapshot_json["chooser_rows"];
    }

    out_snapshot = std::move(parsed);
    return true;
}

static bool capture_ui_action_context(UiActionContextSnapshot& out_snapshot, std::string* error) {
    std::lock_guard<std::mutex> lock(g_capture_mutex);

    if (!install_helper_unlocked(error)) {
        return false;
    }

    if (!process_ui_action(k_capture_action_name)) {
        if (error != nullptr) {
            *error = "Failed to dispatch UI capture action";
        }
        return false;
    }

    std::string output;
    if (!execute_python_helper(k_read_snapshot_code, error, &output)) {
        return false;
    }

    return parse_snapshot_json(output, out_snapshot, error);
}

static bool resolve_action_context_source(ContextSourceData& source, CaptureMetadata& capture) {
    UiActionContextSnapshot snapshot;
    std::string capture_error;
    if (!capture_ui_action_context(snapshot, &capture_error)) {
        capture.error = capture_error;
        return false;
    }

    capture.source = "action";
    capture.fresh = true;
    if (snapshot.sequence > 0) {
        capture.have_sequence = true;
        capture.sequence = snapshot.sequence;
    }
    if (snapshot.timestamp_ms > 0) {
        capture.have_timestamp = true;
        capture.timestamp_ms = snapshot.timestamp_ms;
    }

    if (snapshot.widget_type >= 0) {
        source.has_widget = true;
        source.widget_type = static_cast<twidget_type_t>(snapshot.widget_type);
    }
    if (!snapshot.widget_title.empty()) {
        source.have_title = true;
        source.widget_title = snapshot.widget_title;
    }
    if (snapshot.has_cur_ea) {
        source.current_ea = static_cast<ea_t>(snapshot.cur_ea);
    }
    if (snapshot.focus_known) {
        source.focus_known = true;
        source.focus = snapshot.focus;
    }
    if (snapshot.chooser_rows.is_array() && !snapshot.chooser_rows.empty()) {
        source.have_chooser_rows = true;
        source.chooser_rows = snapshot.chooser_rows;
    }

    merge_from_active_widget(source, get_authoritative_main_viewer());
    return true;
}

static void resolve_viewer_fallback_source(ContextSourceData& source) {
    merge_from_active_widget(source, get_authoritative_main_viewer());
}

static void populate_code_context_json(const ContextSourceData& source, xsql::json& out_code_context) {
    if (source.current_ea != BADADDR) {
        xsql::json code_context = {
            {"has_address", true},
            {"address", format_hex_ea(source.current_ea)}
        };

        if (func_t* current_func = get_func(source.current_ea); current_func != nullptr) {
            qstring func_name;
            const bool have_func_name = get_func_name(&func_name, current_func->start_ea) > 0;
            code_context["function"] = {
                {"name", have_func_name ? func_name.c_str() : ""},
                {"start", format_hex_ea(current_func->start_ea)},
                {"end", format_hex_ea(current_func->end_ea)},
                {"size", static_cast<uint64>(current_func->end_ea - current_func->start_ea)}
            };
        }

        if (segment_t* current_seg = getseg(source.current_ea); current_seg != nullptr) {
            qstring seg_name;
            const bool have_seg_name = get_segm_name(&seg_name, current_seg) > 0;
            code_context["segment"] = {
                {"name", have_seg_name ? seg_name.c_str() : ""},
                {"start", format_hex_ea(current_seg->start_ea)},
                {"end", format_hex_ea(current_seg->end_ea)}
            };
        }

        out_code_context = std::move(code_context);
        return;
    }

    if (!source.has_widget) {
        out_code_context = {
            {"has_address", false},
            {"reason", "No active widget"}
        };
        return;
    }

    std::ostringstream reason;
    reason << "Not in address view (type: " << widget_type_name_or_unknown(source.widget_type) << ")";
    out_code_context = {
        {"has_address", false},
        {"reason", reason.str()}
    };
}

static xsql::json build_ui_context_json(const ContextSourceData& source, const CaptureMetadata& capture) {
    const bool is_custom_view = source.has_widget && is_custom_view_widget_type(source.widget_type);
    const bool is_chooser_like = source.has_widget && is_chooser_like_widget_type(source.widget_type);

    xsql::json type_id = nullptr;
    std::string type_name = "unknown";
    if (source.has_widget) {
        type_id = static_cast<int>(source.widget_type);
        type_name = widget_type_name_or_unknown(source.widget_type);
    }

    xsql::json result = {
        {"capture", {
            {"source", capture.source},
            {"fresh", capture.fresh},
            {"sequence", capture.have_sequence ? xsql::json(capture.sequence) : xsql::json(nullptr)},
            {"timestamp_ms", capture.have_timestamp ? xsql::json(capture.timestamp_ms) : xsql::json(nullptr)},
            {"error", capture.error.empty() ? xsql::json(nullptr) : xsql::json(capture.error)}
        }},
        {"focused_widget", {
            {"type_id", type_id},
            {"type_name", type_name},
            {"title", source.have_title ? source.widget_title : std::string()},
            {"is_custom_view", is_custom_view},
            {"is_chooser_like", is_chooser_like}
        }},
        {"main_viewer", {
            {"type_id", type_id},
            {"type_name", type_name},
            {"title", source.have_title ? source.widget_title : std::string()},
            {"is_custom_view", is_custom_view}
        }},
        {"code_context", xsql::json::object()},
        {"selection", nullptr}
    };

    if (source.focus_known) {
        result["focused_widget"]["focus"] = source.focus;
    }

    populate_code_context_json(source, result["code_context"]);

    xsql::json selection;
    bool have_selection = false;
    if (source.viewer != nullptr) {
        have_selection = extract_listing_selection(source.viewer, selection);
    }
    if (!have_selection && source.have_chooser_rows &&
        source.has_widget && is_chooser_like_widget_type(source.widget_type)) {
        have_selection = extract_chooser_selection_from_snapshot_rows(source.chooser_rows, selection);
    }
    if (!have_selection && source.have_title &&
        (!source.has_widget || is_chooser_like_widget_type(source.widget_type))) {
        have_selection = extract_chooser_selection_from_widget_title(source.widget_title, selection);
    }
    if (have_selection) {
        result["selection"] = std::move(selection);
    }

    return result;
}

} // namespace

bool initialize_capture_helper(std::string* error) {
    std::lock_guard<std::mutex> lock(g_capture_mutex);
    return install_helper_unlocked(error);
}

void shutdown_capture_helper() {
    std::lock_guard<std::mutex> lock(g_capture_mutex);
    if (!g_helper_installed) {
        return;
    }
    std::string ignored;
    (void) execute_python_helper(k_uninstall_helper_code, &ignored, nullptr);
    g_helper_installed = false;
}

xsql::json get_ui_context_json() {
    ContextSourceData source;
    CaptureMetadata capture;

    if (!resolve_action_context_source(source, capture)) {
        capture.source = "viewer_fallback";
        capture.fresh = false;
        if (capture.error.empty()) {
            capture.error = "Action capture unavailable";
        }
        resolve_viewer_fallback_source(source);
    }

    if (!capture.fresh && !source.has_widget) {
        const std::string unavailable_hint = "UI context unavailable in current runtime (no active widget)";
        if (capture.error.empty()) {
            capture.error = unavailable_hint;
        } else if (capture.error.find(unavailable_hint) == std::string::npos) {
            capture.error += "; " + unavailable_hint;
        }
    }

    return build_ui_context_json(source, capture);
}

} // namespace ui_context
} // namespace idasql
