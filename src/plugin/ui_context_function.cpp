// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

#include <idasql/platform.hpp>

#include <idasql/ui_context_provider.hpp>
#include <xsql/database.hpp>

#include "ui_context_function.hpp"

namespace idasql {
namespace plugin_functions {
namespace {

static void sql_get_ui_context_json(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* /*argv*/) {
    if (argc != 0) {
        ctx.result_error("get_ui_context_json requires 0 arguments");
        return;
    }
    ctx.result_text(idasql::ui_context::get_ui_context_json().dump());
}

} // namespace

bool register_ui_context_sql_functions(xsql::Database& db) {
    return xsql::is_ok(db.register_function(
        "get_ui_context_json",
        0,
        xsql::ScalarFn(sql_get_ui_context_json)));
}

} // namespace plugin_functions
} // namespace idasql
