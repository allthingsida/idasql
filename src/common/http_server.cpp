// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "http_server.hpp"
#include <idasql/runtime_settings.hpp>
#include "welcome_query.hpp"

#include <sstream>

namespace idasql {

static std::string build_http_help_text() {
    std::ostringstream out;
    out << "IDASQL HTTP REST API\n"
        << "====================\n\n"
        << "SQL interface for IDA Pro databases via HTTP.\n\n"
        << "Endpoints:\n"
        << "  GET  /         - Welcome message\n"
        << "  GET  /help     - This documentation\n"
        << "  POST /query    - Execute SQL (body = raw SQL, response = JSON)\n"
        << "  GET  /status   - Server health check\n"
        << "  POST /shutdown - Stop server\n\n"
        << "Discover Schema:\n"
        << "  SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY type, name;\n"
        << "  PRAGMA table_info(funcs);\n\n"
        << "Starter Query:\n"
        << "  SELECT * FROM welcome;\n\n"
        << "Response Format (JSON envelope; single statement = array of one):\n"
        << "  {\"success\": true, \"statement_count\": N, \"results\": [\n"
        << "     {\"statement_index\": 0, \"success\": true, \"columns\": [...], \"rows\": [[...]],\n"
        << "      \"row_count\": N, \"elapsed_ms\": N, \"error\": null}],\n"
        << "   \"row_count_total\": N, \"elapsed_ms_total\": N, \"first_error_index\": null}\n\n"
        << "Query Options (query string):\n"
        << "  format=json|text|csv|tsv  (default json; text/csv/tsv are for terminal/\n"
        << "                             pipe use - agents should consume json)\n\n"
        << "Example:\n"
        << "  curl http://localhost:<port>/help\n"
        << "  " << format_query_curl_example("http://localhost:<port>") << "\n";
    return out.str();
}

static xsql::thinclient::http_query_server_config make_idasql_config(
        int port, const std::string& bind_addr, bool use_queue) {
    xsql::thinclient::http_query_server_config config;
    config.tool_name = "idasql";
    config.help_text = build_http_help_text();
    config.port = port;
    config.bind_address = bind_addr;
    config.use_queue = use_queue;
    config.queue_admission_timeout_ms_fn = []() {
        return idasql::runtime_settings().queue_admission_timeout_ms();
    };
    config.max_queue_fn = []() {
        return idasql::runtime_settings().max_queue();
    };
    config.status_fn = []() {
        const auto settings = idasql::runtime_settings().snapshot();
        return xsql::json{
            {"mode", "repl"},
            {"query_timeout_ms", settings.query_timeout_ms},
            {"queue_admission_timeout_ms", settings.queue_admission_timeout_ms},
            {"max_queue", settings.max_queue},
            {"hints_enabled", settings.hints_enabled ? 1 : 0}
        };
    };
    return config;
}

// Legacy: whole-script JSON callback (used by the in-process plugin).
int IDAHTTPServer::start(int port, HTTPQueryCallback query_cb,
                         const std::string& bind_addr, bool use_queue) {
    if (impl_ && impl_->is_running()) {
        return impl_->port();
    }
    bind_addr_ = bind_addr.empty() ? "127.0.0.1" : bind_addr;
    auto config = make_idasql_config(port, bind_addr_, use_queue);
    config.query_fn = std::move(query_cb);
    impl_ = std::make_unique<xsql::thinclient::http_query_server>(config);
    return impl_->start();
}

// Preferred: single-statement executor (CLI). Enables continue_on_error/
// include_sql and round-trip-free format=.
int IDAHTTPServer::start(int port, HTTPStatementExecutor executor,
                         const std::string& bind_addr, bool use_queue,
                         const std::string& auth_token) {
    if (impl_ && impl_->is_running()) {
        return impl_->port();
    }
    bind_addr_ = bind_addr.empty() ? "127.0.0.1" : bind_addr;
    auto config = make_idasql_config(port, bind_addr_, use_queue);
    config.statement_executor = std::move(executor);
    // Non-queue servers (REPL/plugin background) run the executor on the HTTP
    // worker; serialize so the non-concurrency-safe IDA DB handle is safe.
    config.serialize_requests = !use_queue;
    if (!auth_token.empty()) config.auth_token = auth_token;
    impl_ = std::make_unique<xsql::thinclient::http_query_server>(config);
    return impl_->start();
}

void IDAHTTPServer::run_until_stopped() {
    if (impl_) impl_->run_until_stopped();
}

void IDAHTTPServer::stop() {
    if (impl_) {
        impl_->stop();
        impl_.reset();
    }
}

bool IDAHTTPServer::is_running() const {
    return impl_ && impl_->is_running();
}

int IDAHTTPServer::port() const {
    return impl_ ? impl_->port() : 0;
}

std::string IDAHTTPServer::url() const {
    return impl_ ? impl_->url() : "";
}

void IDAHTTPServer::set_interrupt_check(std::function<bool()> check) {
    if (impl_) impl_->set_interrupt_check(std::move(check));
}

std::string format_http_info(int port, const std::string& stop_hint) {
    return format_http_info(port, "127.0.0.1", stop_hint);
}

std::string format_http_info(int port, const std::string& bind_addr, const std::string& stop_hint) {
    const std::string rendered_host = xsql::thinclient::format_url_host(bind_addr);
    const std::string base_url = "http://" + rendered_host + ":" + std::to_string(port);
    std::ostringstream ss;
    ss << "IDASQL HTTP server: " << base_url << "\n";
    ss << stop_hint << "\n";
    return ss.str();
}

std::string format_http_status(int port, bool running) {
    return format_http_status(port, running, "127.0.0.1");
}

std::string format_http_status(int port, bool running, const std::string& bind_addr) {
    return xsql::thinclient::format_http_status(port, running, bind_addr);
}

} // namespace idasql
