#include "mcp_server.hpp"

#include <fastmcpp/mcp/handler.hpp>
#include <fastmcpp/server/sse_server.hpp>
#include <fastmcpp/tools/manager.hpp>
#include <fastmcpp/tools/tool.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <random>
#include <sstream>

namespace idasql {

using Json = nlohmann::json;

class IDAMCPServer::Impl {
public:
    fastmcpp::tools::ToolManager tool_manager;
    std::unique_ptr<fastmcpp::server::SseServerWrapper> server;
};

IDAMCPServer::IDAMCPServer() = default;

IDAMCPServer::~IDAMCPServer() {
    stop();
}

MCPQueueResult IDAMCPServer::queue_and_wait(MCPPendingCommand::Type type, const std::string& input) {
    if (!running_.load()) {
        return {false, "Error: MCP server is not running"};
    }

    MCPPendingCommand cmd;
    cmd.type = type;
    cmd.input = input;
    cmd.completed = false;

    std::mutex done_mutex;
    std::condition_variable done_cv;
    cmd.done_mutex = &done_mutex;
    cmd.done_cv = &done_cv;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        pending_commands_.push(&cmd);
    }
    queue_cv_.notify_one();

    {
        std::unique_lock<std::mutex> lock(done_mutex);
        done_cv.wait(lock, [&]() { return cmd.completed || !running_.load(); });
    }

    if (!cmd.completed) {
        return {false, "Error: MCP server stopped"};
    }

    return {true, cmd.result};
}

int IDAMCPServer::start(int port, QueryCallback query_cb, AskCallback ask_cb,
                        const std::string& bind_addr, bool use_queue) {
    if (running_.load()) {
        return port_;
    }

    query_cb_ = query_cb;
    ask_cb_ = ask_cb;
    bind_addr_ = bind_addr;
    use_queue_.store(use_queue);

    // If port is 0, pick a random port in the 9000-9999 range
    if (port == 0) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(9000, 9999);
        port = dis(gen);
    }

    impl_ = std::make_unique<Impl>();

    // Register idasql_query tool - direct SQL execution
    Json query_input_schema = {
        {"type", "object"},
        {"properties", {
            {"query", {
                {"type", "string"},
                {"description", "SQL query to execute against the IDA database"}
            }}
        }},
        {"required", Json::array({"query"})}
    };

    Json query_output_schema = {
        {"type", "object"},
        {"properties", {
            {"result", {{"type", "string"}}},
            {"success", {{"type", "boolean"}}}
        }}
    };

    fastmcpp::tools::Tool sql_query_tool{
        "idasql_query",
        query_input_schema,
        query_output_schema,
        [this](const Json& args) -> Json {
            std::string query = args.value("query", "");
            if (query.empty()) {
                return Json{
                    {"content", Json::array({
                        Json{{"type", "text"}, {"text", "Error: missing query"}}
                    })},
                    {"isError", true}
                };
            }

            std::string result;
            bool success = true;

            if (use_queue_.load()) {
                // Queue mode (CLI): queue command for main thread execution
                auto qr = queue_and_wait(MCPPendingCommand::Type::Query, query);
                result = qr.payload;
                success = qr.success;
            } else {
                // Direct mode (plugin): callback uses execute_sync internally
                if (!query_cb_) {
                    return Json{
                        {"content", Json::array({
                            Json{{"type", "text"}, {"text", "Error: query callback not set"}}
                        })},
                        {"isError", true}
                    };
                }
                result = query_cb_(query);
            }

            // MCP tools/call expects content array format
            return Json{
                {"content", Json::array({
                    Json{{"type", "text"}, {"text", result}}
                })},
                {"isError", !success}
            };
        }
    };
    sql_query_tool.set_description("Execute a SQL query against the IDA database and return results");
    impl_->tool_manager.register_tool(sql_query_tool);

    // Register idasql_agent tool - natural language query (if ask_cb provided)
    if (ask_cb_) {
        Json ask_input_schema = {
            {"type", "object"},
            {"properties", {
                {"question", {
                    {"type", "string"},
                    {"description", "Natural language question about the binary (e.g., 'What functions call malloc?')"}
                }}
            }},
            {"required", Json::array({"question"})}
        };

        Json ask_output_schema = {
            {"type", "object"},
            {"properties", {
                {"response", {{"type", "string"}}},
                {"success", {{"type", "boolean"}}}
            }}
        };

        fastmcpp::tools::Tool agent_ask_tool{
            "idasql_agent",
            ask_input_schema,
            ask_output_schema,
            [this](const Json& args) -> Json {
                std::string question = args.value("question", "");
                if (question.empty()) {
                    return Json{
                        {"content", Json::array({
                            Json{{"type", "text"}, {"text", "Error: missing question"}}
                        })},
                        {"isError", true}
                    };
                }

                std::string result;
                bool success = true;

                if (use_queue_.load()) {
                    // Queue mode (CLI): queue command for main thread execution
                    auto qr = queue_and_wait(MCPPendingCommand::Type::Ask, question);
                    result = qr.payload;
                    success = qr.success;
                } else {
                    // Direct mode (plugin): callback handles thread safety
                    result = ask_cb_(question);
                }

                return Json{
                    {"content", Json::array({
                        Json{{"type", "text"}, {"text", result}}
                    })},
                    {"isError", !success}
                };
            }
        };
        agent_ask_tool.set_description("Ask a natural language question about the binary - AI translates to SQL and returns results");
        impl_->tool_manager.register_tool(agent_ask_tool);
    }

    // Create MCP handler
    std::unordered_map<std::string, std::string> descriptions = {
        {"idasql_query", "Execute a SQL query against the IDA database and return results"}
    };
    if (ask_cb_) {
        descriptions["idasql_agent"] = "Ask a natural language question about the binary - AI translates to SQL and returns results";
    }

    auto handler = fastmcpp::mcp::make_mcp_handler(
        "idasql",
        "1.0.0",
        impl_->tool_manager,
        descriptions
    );

    // Create and start SSE server
    impl_->server = std::make_unique<fastmcpp::server::SseServerWrapper>(
        handler,
        bind_addr_,
        port,
        "/sse",
        "/messages"
    );

    if (!impl_->server->start()) {
        impl_.reset();
        return -1;
    }

    port_ = impl_->server->port();
    running_.store(true);

    return port_;
}

void IDAMCPServer::set_interrupt_check(std::function<bool()> check) {
    interrupt_check_ = check;
}

void IDAMCPServer::run_until_stopped() {
    while (running_.load()) {
        if (interrupt_check_ && interrupt_check_()) {
            stop();
            break;
        }

        MCPPendingCommand* cmd = nullptr;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (queue_cv_.wait_for(lock, std::chrono::milliseconds(100),
                                   [this]() { return !pending_commands_.empty() || !running_.load(); })) {
                if (!pending_commands_.empty()) {
                    cmd = pending_commands_.front();
                    pending_commands_.pop();
                }
            }
        }

        if (cmd) {
            try {
                if (cmd->type == MCPPendingCommand::Type::Query && query_cb_) {
                    cmd->result = query_cb_(cmd->input);
                } else if (cmd->type == MCPPendingCommand::Type::Ask && ask_cb_) {
                    cmd->result = ask_cb_(cmd->input);
                } else {
                    cmd->result = "Error: No handler for command type";
                }
            } catch (const std::exception& e) {
                cmd->result = std::string("Error: ") + e.what();
            }

            if (cmd->done_mutex && cmd->done_cv) {
                {
                    std::lock_guard<std::mutex> lock(*cmd->done_mutex);
                    cmd->completed = true;
                }
                cmd->done_cv->notify_one();
            }
        }
    }
}

void IDAMCPServer::stop() {
    running_.store(false);
    queue_cv_.notify_all();
    complete_pending_commands("Error: MCP server stopped");

    if (impl_ && impl_->server) {
        impl_->server->stop();
    }

    impl_.reset();
}

void IDAMCPServer::complete_pending_commands(const std::string& result) {
    std::queue<MCPPendingCommand*> pending;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        std::swap(pending, pending_commands_);
    }

    while (!pending.empty()) {
        MCPPendingCommand* cmd = pending.front();
        pending.pop();
        if (!cmd || !cmd->done_mutex || !cmd->done_cv) {
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(*cmd->done_mutex);
            if (!cmd->completed) {
                cmd->result = result;
                cmd->completed = true;
            }
        }
        cmd->done_cv->notify_one();
    }
}

std::string IDAMCPServer::url() const {
    std::ostringstream ss;
    ss << "http://" << bind_addr_ << ":" << port_;
    return ss.str();
}

std::string format_mcp_info(int port, bool has_agent) {
    std::ostringstream ss;
    ss << "MCP server started on port " << port << "\n";
    ss << "SSE endpoint: http://127.0.0.1:" << port << "/sse\n\n";

    ss << "Available tools:\n";
    ss << "  idasql_query  - Execute SQL query directly\n";
    if (has_agent) {
        ss << "  idasql_agent  - Ask natural language question (AI-powered)\n";
    }
    ss << "\n";

    ss << "Add to Claude Desktop config:\n";
    ss << "{\n";
    ss << "  \"mcpServers\": {\n";
    ss << "    \"idasql\": {\n";
    ss << "      \"url\": \"http://127.0.0.1:" << port << "/sse\"\n";
    ss << "    }\n";
    ss << "  }\n";
    ss << "}\n";

    return ss.str();
}

std::string format_mcp_status(int port, bool running) {
    std::ostringstream ss;
    if (running) {
        ss << "MCP server running on port " << port << "\n";
        ss << "SSE endpoint: http://127.0.0.1:" << port << "/sse\n";
    } else {
        ss << "MCP server not running\n";
        ss << "Use '.mcp start' to start\n";
    }
    return ss.str();
}

} // namespace idasql
