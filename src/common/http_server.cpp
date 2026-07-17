// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "http_server.hpp"
#include <idasql/runtime_settings.hpp>
#include "binary_query.hpp"

#include <cstdio>
#include <sstream>

namespace idasql {

static std::string build_http_help_text() {
    std::ostringstream out;
    out << "IDASQL HTTP REST API\n"
        << "====================\n\n"
        << "SQL interface for IDA Pro databases via HTTP.\n\n"
        << "Endpoints:\n"
        << "  GET  /         - Server greeting\n"
        << "  GET  /help     - This documentation\n"
        << "  POST /query    - Execute SQL (body = raw SQL, response = JSON)\n"
        << "  GET  /status   - Server health check\n"
        << "  POST /shutdown - Stop server\n\n"
        << "Discover Schema:\n"
        << "  SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY type, name;\n"
        << "  PRAGMA table_info(funcs);\n\n"
        << "Starter Query:\n"
        << "  SELECT * FROM binary;\n\n"
        << "Response Format (canonical JSON):\n"
        << "  {\"success\": true, \"statement_count\": N, \"results\": [{\"columns\": [...], \"rows\": [[...]], \"row_count\": N, \"error\": null}], ...}\n"
        << "  A single statement returns a one-element results[]. Use ?format=text|csv|tsv for non-JSON output.\n"
        << "  Error: {\"success\": false, \"error\": \"message\"} (request-level) or per-statement results[i].error\n\n"
        << "Example:\n"
        << "  curl http://localhost:<port>/help\n"
        << "  " << format_query_curl_example("http://localhost:<port>") << "\n";
    return out.str();
}

int IDAHTTPServer::start(int port, HTTPQueryCallback query_cb,
                         const std::string& bind_addr, bool use_queue,
                         const std::string& auth_token) {
    if (impl_ && impl_->is_running()) {
        return impl_->port();
    }

    bind_addr_ = bind_addr.empty() ? "127.0.0.1" : bind_addr;

    // Security notice: the REPL/plugin `.http` server exposes a read/write SQL
    // endpoint (queries can save_database(), edit types, etc.). A token makes it
    // require `Authorization: Bearer <token>`; WITHOUT one it is unauthenticated
    // (fine on loopback). Binding a non-loopback interface with no token makes it
    // reachable by other hosts with no auth — warn so an operator who pins 0.0.0.0
    // without a token sees the exposure. (Set a token via `.http start --token` or
    // `.pin http --token`; the standalone `idasql --http --token` path is separate.)
    if (auth_token.empty()
        && bind_addr_ != "127.0.0.1" && bind_addr_ != "localhost" && bind_addr_ != "::1") {
        std::fprintf(stderr,
            "WARNING: idasql HTTP server bound to non-loopback address %s with no "
            "authentication.\n         The read/write SQL endpoint is reachable by "
            "other hosts. Prefer 127.0.0.1 or set --token.\n",
            bind_addr_.c_str());
    }

    xsql::thinclient::http_query_server_config config;
    config.tool_name = "idasql";
    config.help_text = build_http_help_text();
    config.port = port;
    config.bind_address = bind_addr_;
    config.query_fn = std::move(query_cb);
    config.use_queue = use_queue;
    if (!auth_token.empty()) config.auth_token = auth_token;
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
            {"query_timeout_ms", settings.core.query_timeout_ms},
            {"queue_admission_timeout_ms", settings.core.queue_admission_timeout_ms},
            {"max_queue", settings.core.max_queue},
            {"hints_enabled", settings.core.hints_enabled ? 1 : 0}
        };
    };

    impl_ = std::make_unique<xsql::thinclient::http_query_server>(config);
    const int started = impl_->start();
    if (started <= 0) {
        // Failed bind: drop the impl so a later retry starts from clean state
        // (no stale not-running server, no stale port in status()).
        impl_.reset();
        return -1;
    }
    return started;
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
