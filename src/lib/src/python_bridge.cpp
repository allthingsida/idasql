// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// In-process `import idasql` for IDAPython. The mechanism (a native IDC
// function reached through ida_expr.eval_idc_expr, plus a pure-Python module
// injected with the extlang's eval_snippet) follows the prototype po0p posted
// with the feature request. See python_bridge.hpp for the surface and rules.

// json before IDA headers (IDA poisons some stdlib functions on Windows).
#include <xsql/json.hpp>
#include <xsql/script.hpp>

#include "python_bridge.hpp"

#include <idasql/database.hpp>

#include "idapython_exec.hpp"
#include "ida_headers.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace idasql {
namespace python_bridge {
namespace {

constexpr int kModuleVersion = 1;
constexpr const char* kIdcName = "__idasql_bridge";

// Live engines in attach order; the newest is the target. A short-lived engine
// (an embedder's second QueryEngine) going away hands calls back to the one
// that was serving before it.
std::vector<QueryEngine*>& engines() {
    static std::vector<QueryEngine*> list;
    return list;
}

bool g_idc_registered = false;
thread_local int t_depth = 0;

QueryEngine* target() {
    auto& list = engines();
    return list.empty() ? nullptr : list.back();
}

// --------------------------------------------------------------------------
// Python side
// --------------------------------------------------------------------------

constexpr const char* kModuleSource = R"py(
import json as _json
import ida_expr as _ida_expr
import ida_idaapi as _ida_idaapi
import ida_kernwin as _ida_kernwin
import ida_pro as _ida_pro

__all__ = ["Error", "Result", "Row", "available", "query", "rows", "scalar", "script"]
_active = True
# Captured at import, on the main thread: is_idaq() itself refuses worker-thread callers.
_IS_GUI = bool(_ida_kernwin.is_idaq())


class Error(Exception):
    """An SQL or bridge error. str(e) is the message; e.sql the statement."""

    def __init__(self, message, sql=None):
        super().__init__(message)
        self.message = message
        self.sql = sql


class Row(tuple):
    """A result row: a tuple that also exposes its columns as attributes."""
    __slots__ = ()
    _columns = ()

    def __getattr__(self, name):
        try:
            return self[self._columns.index(name)]
        except ValueError:
            raise AttributeError(name) from None

    def as_dict(self):
        return dict(zip(self._columns, self))


def _decode(v):
    if isinstance(v, dict) and "$bytes" in v:
        return bytes.fromhex(v["$bytes"])
    return v


def _encode(v):
    if v is None or isinstance(v, (str, float)):
        return v
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        if not -(1 << 63) <= v < (1 << 64):
            raise Error("integer parameter out of 64-bit range: %r" % (v,))
        return v - (1 << 64) if v >= (1 << 63) else v
    if isinstance(v, (bytes, bytearray, memoryview)):
        return {"$bytes": bytes(v).hex()}
    raise Error("unsupported parameter type: %s" % type(v).__name__)


class Result:
    """columns, rows (Row tuples of typed values), warnings, elapsed_ms, timed_out, partial."""

    def __init__(self, env, sql):
        self.sql = sql
        self.columns = list(env.get("columns") or [])
        row_type = type("Row", (Row,), {"__slots__": (), "_columns": tuple(self.columns)})
        self.rows = [row_type(_decode(v) for v in r) for r in (env.get("rows") or [])]
        self.warnings = list(env.get("warnings") or [])
        self.elapsed_ms = int(env.get("elapsed_ms") or 0)
        self.timed_out = bool(env.get("timed_out"))
        self.partial = bool(env.get("partial"))

    def __len__(self):
        return len(self.rows)

    def __iter__(self):
        return iter(self.rows)

    def __getitem__(self, i):
        return self.rows[i]

    def dicts(self):
        return [r.as_dict() for r in self.rows]

    def __repr__(self):
        return "<idasql.Result %d row(s) x %d column(s)>" % (len(self.rows), len(self.columns))


def _call(payload):
    if not _active:
        raise Error("idasql is no longer loaded for this database")
    if not _ida_pro.is_main_thread():
        if not _IS_GUI:
            raise Error("idasql calls must run on IDA's main thread: under idalib (idasql CLI, "
                        "--http, --mcp) requests from other threads are never serviced")
        box = {}

        def work():
            try:
                box["r"] = _call(payload)
            except BaseException as e:  # re-raised on the calling thread
                box["e"] = e
            return 0

        _ida_kernwin.execute_sync(work, _ida_kernwin.MFF_WRITE)
        if "e" in box:
            raise box["e"]
        if "r" not in box:
            raise Error("idasql main-thread request was cancelled")
        return box["r"]
    arg = _json.dumps(payload).encode("utf-8").hex()
    value = _ida_expr.idc_value_t()
    err = _ida_expr.eval_idc_expr(value, _ida_idaapi.BADADDR, '__idasql_bridge("%s")' % arg)
    if err:
        raise Error("idasql bridge unavailable: %s" % err)
    return _json.loads(value.c_str())


def available():
    """True when the bridge can reach an open idasql database."""
    try:
        return bool(_call({"op": "ping"}).get("success"))
    except Error:
        return False


def _params(params):
    # query(sql, a, b) and sqlite3-style query(sql, [a, b]) / query(sql, (a, b)) both work.
    if len(params) == 1 and isinstance(params[0], (list, tuple)):
        params = params[0]
    return [_encode(p) for p in params]


def query(sql, *params):
    """Run ONE statement; `?` placeholders are bound to params by SQLite.
    Params may be given inline or as a single list/tuple."""
    env = _call({"op": "query", "sql": sql, "params": _params(params)})
    if not env.get("success"):
        raise Error(env.get("error") or "query failed", sql)
    return Result(env, sql)


def rows(sql, *params):
    """query() as a list of dicts."""
    return query(sql, *params).dicts()


def scalar(sql, *params):
    """First column of the first row, or None."""
    r = query(sql, *params)
    return r.rows[0][0] if r.rows and r.columns else None


def script(sql):
    """Run several statements; returns one Result per statement."""
    env = _call({"op": "script", "sql": sql})
    if not env.get("success"):
        raise Error(env.get("error") or "script failed", sql)
    return [Result(e, s) for s, e in zip(env.get("statements") or [], env.get("results") or [])]
)py";

std::string install_snippet() {
    std::string s;
    s += "def __idasql_install_bridge():\n";
    s += "    import sys, types\n";
    s += "    version = " + std::to_string(kModuleVersion) + "\n";
    s += "    mod = sys.modules.get('idasql')\n";
    s += "    if mod is not None:\n";
    s += "        if getattr(mod, '_idasql_bridge_version', None) == version:\n";
    s += "            mod._active = True\n";
    s += "            return\n";
    s += "        if getattr(mod, '_idasql_bridge_version', None) is None:\n";
    s += "            raise RuntimeError(\"a different module named 'idasql' is already imported\")\n";
    s += "    mod = types.ModuleType('idasql', 'In-process SQL over the open IDA database (idasql).')\n";
    s += "    mod._idasql_bridge_version = version\n";
    s += "    exec(compile(bytes.fromhex('" + idapython::hex_encode(kModuleSource) +
         "').decode('utf-8'), '<idasql bridge>', 'exec'), mod.__dict__)\n";
    s += "    sys.modules['idasql'] = mod\n";
    s += "try:\n";
    s += "    __idasql_install_bridge()\n";
    s += "finally:\n";
    s += "    del __idasql_install_bridge\n";
    return s;
}

const char* kDeactivateSnippet =
    "import sys\n"
    "_m = sys.modules.get('idasql')\n"
    "if _m is not None and getattr(_m, '_idasql_bridge_version', None) is not None:\n"
    "    _m._active = False\n"
    "del _m\n";

// A fresh lookup (not idapython's cached pointer): teardown can run late.
bool eval_python(const char* code, std::string* error) {
    extlang_object_t py = find_extlang_by_name("Python");
    if (py == nullptr || py->eval_snippet == nullptr) {
        if (error != nullptr) *error = "IDAPython is not available";
        return false;
    }
    qstring err;
    if (!py->eval_snippet(code, &err)) {
        if (error != nullptr) *error = err.c_str();
        return false;
    }
    return true;
}

// --------------------------------------------------------------------------
// Late injection: IDAPython can load after the engine (plugin load order).
// --------------------------------------------------------------------------

struct LateInjector : public event_listener_t {
    bool hooked = false;

    ssize_t idaapi on_event(ssize_t code, va_list) override {
        if (code == ui_plugin_loaded || code == ui_ready_to_run) {
            if (target() != nullptr && ensure_python_module(nullptr))
                stop();
        }
        return 0;
    }

    void start() {
        if (!hooked)
            hooked = hook_event_listener(HT_UI, this, nullptr);
    }

    void stop() {
        if (hooked) {
            unhook_event_listener(HT_UI, this);
            hooked = false;
        }
    }
};

LateInjector& late_injector() {
    static LateInjector injector;
    return injector;
}

// --------------------------------------------------------------------------
// Native side: __idasql_bridge(hex_json) -> json
// --------------------------------------------------------------------------

bool hex_decode(const char* hex, size_t n, std::string& out) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    if (n % 2 != 0) return false;
    out.clear();
    out.reserve(n / 2);
    for (size_t i = 0; i < n; i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return true;
}

xsql::json typed_cell(const Row& row, size_t i) {
    if (row.is_null(i)) return nullptr;
    const std::string& v = row.values[i];
    switch (row.type(i)) {
    case SQLITE_INTEGER:
        try { return static_cast<int64_t>(std::stoll(v)); } catch (...) { return v; }
    case SQLITE_FLOAT:
        try { return std::stod(v); } catch (...) { return v; }
    case SQLITE_BLOB:
        return xsql::json{{"$bytes", idapython::hex_encode(v)}};
    default:
        return v;
    }
}

xsql::json result_json(const QueryResult& r) {
    xsql::json rows = xsql::json::array();
    for (const auto& row : r.rows) {
        xsql::json cells = xsql::json::array();
        for (size_t i = 0; i < row.values.size(); ++i)
            cells.push_back(typed_cell(row, i));
        rows.push_back(std::move(cells));
    }
    return {
        {"success", r.success},
        {"error", r.error},
        {"columns", r.columns},
        {"rows", std::move(rows)},
        {"warnings", r.warnings},
        {"elapsed_ms", r.elapsed_ms},
        {"timed_out", r.timed_out},
        {"partial", r.partial},
    };
}

bool to_param(const xsql::json& v, xsql::QueryParam& out, std::string& error) {
    if (v.is_null()) { out = nullptr; return true; }
    if (v.is_boolean()) { out = static_cast<int64_t>(v.get<bool>() ? 1 : 0); return true; }
    if (v.is_number_integer()) { out = v.get<int64_t>(); return true; }
    if (v.is_number_float()) { out = v.get<double>(); return true; }
    if (v.is_string()) { out = v.get<std::string>(); return true; }
    if (v.is_object() && v.contains("$bytes") && v["$bytes"].is_string()) {
        const std::string hex = v["$bytes"].get<std::string>();
        std::string raw;
        if (!hex_decode(hex.data(), hex.size(), raw)) {
            error = "bad bytes parameter";
            return false;
        }
        out = std::vector<uint8_t>(raw.begin(), raw.end());
        return true;
    }
    error = "unsupported parameter: " + v.dump();
    return false;
}

xsql::json error_json(const std::string& message) {
    return {{"success", false}, {"error", message}};
}

// A string field of the request, "" when absent or not a string (value() would
// throw for a present field of another type).
std::string string_field(const xsql::json& req, const char* key) {
    const auto it = req.find(key);
    return it != req.end() && it->is_string() ? it->get<std::string>() : std::string();
}

xsql::json dispatch(QueryEngine& engine, const xsql::json& req) {
    const std::string op = string_field(req, "op");
    if (op == "ping") return {{"success", true}};

    const std::string sql = string_field(req, "sql");
    if (op == "query") {
        std::vector<xsql::QueryParam> params;
        if (req.contains("params") && req["params"].is_array()) {
            for (const auto& p : req["params"]) {
                xsql::QueryParam qp;
                std::string error;
                if (!to_param(p, qp, error)) return error_json(error);
                params.push_back(std::move(qp));
            }
        }
        // Even with no parameters: a statement with a `?` left unbound must fail
        // rather than read NULL.
        return result_json(engine.query(sql.c_str(), params));
    }
    if (op == "script") {
        std::vector<std::string> statements;
        std::string error;
        if (!xsql::collect_statements(sql, statements, error))
            return error_json(error.empty() ? "invalid SQL script" : error);
        xsql::json results = xsql::json::array();
        for (const auto& stmt : statements) {
            const QueryResult r = engine.query(stmt.c_str());
            if (!r.success) {
                return error_json("statement " + std::to_string(results.size() + 1) + ": " + r.error);
            }
            results.push_back(result_json(r));
        }
        return {{"success", true}, {"statements", statements}, {"results", std::move(results)}};
    }
    return error_json("unknown bridge op '" + op + "'");
}

error_t idaapi idc_bridge(idc_value_t* argv, idc_value_t* res) {
    xsql::json out;
    QueryEngine* engine = target();
    if (!is_main_thread()) {
        out = error_json("idasql bridge called off the main thread");
    } else if (engine == nullptr || !engine->is_valid()) {
        out = error_json("idasql is not loaded for the current database");
    } else if (t_depth >= kMaxDepth) {
        out = error_json("idasql bridge: nesting too deep (max " + std::to_string(kMaxDepth) +
                         " levels of SQL -> Python -> SQL)");
    } else {
        std::string payload;
        if (argv[0].vtype != VT_STR ||
            !hex_decode(argv[0].c_str(), argv[0].qstr().length(), payload)) {
            out = error_json("idasql bridge: malformed request");
        } else {
            ++t_depth;
            try {
                out = dispatch(*engine, xsql::json::parse(payload));
            } catch (const std::exception& e) {
                out = error_json(std::string("idasql bridge: ") + e.what());
            }
            --t_depth;
        }
    }
    const std::string text = out.dump(-1, ' ', false, xsql::json::error_handler_t::replace);
    res->set_string(text.c_str(), text.size());
    return eOk;
}

const char kBridgeArgs[] = {VT_STR, 0};
const ext_idcfunc_t kBridgeFunc = {kIdcName, idc_bridge, kBridgeArgs, nullptr, 0, EXTFUN_BASE};

}  // namespace

void attach(QueryEngine* engine) {
    auto& list = engines();
    list.erase(std::remove(list.begin(), list.end(), engine), list.end());
    list.push_back(engine);
    if (!g_idc_registered)
        g_idc_registered = add_idc_func(kBridgeFunc);
    if (!ensure_python_module(nullptr))
        late_injector().start();
}

void detach(QueryEngine* engine) {
    auto& list = engines();
    const auto it = std::find(list.begin(), list.end(), engine);
    if (it == list.end())
        return;
    list.erase(it);
    if (!list.empty())
        return;
    // Nobody left to serve: drop the IDC entry point (it points into this
    // binary, which may be unloaded next) and deactivate the module.
    late_injector().stop();
    if (g_idc_registered) {
        del_idc_func(kIdcName);
        g_idc_registered = false;
    }
    if (t_depth == 0)
        (void)eval_python(kDeactivateSnippet, nullptr);
}

void retarget(QueryEngine* from, QueryEngine* to) {
    for (auto& e : engines()) {
        if (e == from)
            e = to;
    }
}

bool in_bridge_call() {
    return t_depth > 0;
}

bool ensure_python_module(std::string* error) {
    if (in_bridge_call()) {
        if (error != nullptr) *error = "cannot re-enter IDAPython from a bridge call";
        return false;
    }
    static const std::string snippet = install_snippet();
    return eval_python(snippet.c_str(), error);
}

} // namespace python_bridge
} // namespace idasql
