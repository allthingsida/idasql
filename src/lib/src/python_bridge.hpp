// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * python_bridge.hpp - in-process `import idasql` for IDAPython.
 *
 * A native IDC function, __idasql_bridge(hex_json), runs SQL on the current
 * QueryEngine and returns a JSON envelope. A small pure-Python module named
 * `idasql`, injected into sys.modules through IDAPython's extlang
 * (expr.hpp eval_snippet), calls it with ida_expr.eval_idc_expr. idasql never
 * links or imports Python itself: without IDAPython every SQL surface works
 * unchanged and the module is simply never injected.
 *
 *   import idasql
 *   idasql.available()          -> bool
 *   idasql.query(sql, *params)  -> Result (columns, typed rows, warnings, ...)
 *   idasql.rows(sql, *params)   -> list[dict]
 *   idasql.scalar(sql, *params) -> first column of the first row, or None
 *   idasql.script(sql)          -> list[Result]
 *   idasql.Error                -> .message, .sql
 *
 * Calls must come from IDA's main thread. In the GUI a call from another thread
 * is forwarded with execute_sync; under idalib (idasql CLI, --http, --mcp) it
 * fails fast, because idalib never services execute_sync from a worker thread.
 * SQL issued from Python that idasql itself runs (idapython_snippet) is a
 * nested query: it shares the outer statement's deadline and cancellation, and
 * nesting is limited to kMaxDepth levels. Re-entering IDAPython from SQL that
 * Python issued is refused (IDAPython is not re-entrant from an IDC call it
 * made; measured as an access violation).
 */

#pragma once

#include <string>

namespace idasql {

class QueryEngine;

namespace python_bridge {

// Maximum SQL -> Python -> SQL nesting depth.
constexpr int kMaxDepth = 8;

// Make `engine` the target of bridge calls (the most recently attached live
// engine is the target), register the IDC entry point if needed, and inject the
// Python module when IDAPython is already loaded. Otherwise the module is
// injected later: before idasql runs Python, or when IDAPython loads.
void attach(QueryEngine* engine);

// Stop routing calls to `engine`. When no engine is left, the IDC entry point
// is removed and the module is deactivated: a saved idasql.query then raises
// idasql.Error instead of touching a closed database.
void detach(QueryEngine* engine);

// The engine object moved: keep routing to its new address.
void retarget(QueryEngine* from, QueryEngine* to);

// Inject (or re-activate) the `idasql` module. Idempotent. Returns false with
// `error` set when IDAPython is not available or refused the module.
bool ensure_python_module(std::string* error = nullptr);

// True while SQL issued from Python through the bridge runs on this thread.
// idapython_snippet / idapython_file must refuse to run in that window.
bool in_bridge_call();

} // namespace python_bridge
} // namespace idasql
