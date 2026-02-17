#include "http_server.hpp"

#include <sstream>

namespace idasql {

// Help text served at /help endpoint
static const char* HTTP_HELP_TEXT = R"(IDASQL HTTP REST API
====================

SQL interface for IDA Pro databases via HTTP.

Endpoints:
  GET  /         - Welcome message
  GET  /help     - This documentation
  POST /query    - Execute SQL (body = raw SQL, response = JSON)
  GET  /status   - Server health check
  POST /shutdown - Stop server

Response Format:
  Success: {"success": true, "columns": [...], "rows": [[...]], "row_count": N}
  Error:   {"success": false, "error": "message"}

Example:
  curl http://localhost:<port>/help
  curl -X POST http://localhost:<port>/query -d "SELECT name FROM funcs LIMIT 5"
)";

int IDAHTTPServer::start(int port, HTTPQueryCallback query_cb,
                         const std::string& bind_addr, bool use_queue) {
    if (impl_ && impl_->is_running()) {
        return impl_->port();
    }

    xsql::thinclient::http_query_server_config config;
    config.tool_name = "idasql";
    config.help_text = HTTP_HELP_TEXT;
    config.port = port;
    config.bind_address = bind_addr;
    config.query_fn = std::move(query_cb);
    config.use_queue = use_queue;
    config.status_fn = []() {
        return xsql::json{{"mode", "repl"}};
    };

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
    return xsql::thinclient::format_http_info("idasql", port, stop_hint);
}

std::string format_http_status(int port, bool running) {
    return xsql::thinclient::format_http_status(port, running);
}

} // namespace idasql
