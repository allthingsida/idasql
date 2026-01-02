#include "claude_agent.hpp"

#ifdef IDASQL_HAS_CLAUDE_AGENT

// Embedded documentation from prompts/idasql_agent.md
// Used for first-message priming (can't use system_prompt - breaks MCP tool visibility)
#include "idasql_agent_prompt.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <iostream>

namespace idasql {

// ============================================================================
// Construction / Destruction
// ============================================================================

ClaudeAgent::ClaudeAgent(SqlExecutor executor, bool verbose)
    : executor_(std::move(executor)), verbose_(verbose)
{
}

ClaudeAgent::~ClaudeAgent() {
    stop();
}

// ============================================================================
// Lifecycle
// ============================================================================

void ClaudeAgent::start() {
    if (running_.load()) return;

    running_.store(true);
    quit_requested_.store(false);

    client_thread_ = std::thread(&ClaudeAgent::client_thread_loop, this);

    if (verbose_) {
        std::cerr << "[AGENT] Client thread started" << std::endl;
    }
}

void ClaudeAgent::stop() {
    if (!running_.load()) return;

    if (verbose_) {
        std::cerr << "[AGENT] Stopping..." << std::endl;
    }

    running_.store(false);
    query_queue_.stop();
    main_queue_.stop();

    if (client_thread_.joinable()) {
        client_thread_.join();
    }

    if (verbose_) {
        std::cerr << "[AGENT] Stopped" << std::endl;
    }
}

void ClaudeAgent::request_quit() {
    quit_requested_.store(true);
    main_queue_.stop();  // Unblock main thread if waiting
}

void ClaudeAgent::reset_session() {
    if (verbose_) {
        std::cerr << "[AGENT] Resetting session..." << std::endl;
    }

    // Stop current session
    bool was_running = running_.load();
    stop();

    // Reset state
    docs_primed_ = false;
    quit_requested_.store(false);

    // Reset queues (stop() leaves them in stopped state)
    query_queue_.reset();
    main_queue_.reset();

    // Restart if was running
    if (was_running) {
        start();
    }

    if (verbose_) {
        std::cerr << "[AGENT] Session reset complete" << std::endl;
    }
}

// ============================================================================
// Client Thread
// ============================================================================

void ClaudeAgent::client_thread_loop() {
    try {
        auto opts = create_options();
        claude::ClaudeClient client(opts);
        client.connect();

        if (verbose_) {
            std::cerr << "[CLIENT] Connected to Claude CLI" << std::endl;
        }

        // Process queries until stopped
        while (running_.load()) {
            auto req = query_queue_.pop();
            if (!req) break;  // Queue stopped

            if (verbose_) {
                std::cerr << "[CLIENT] Processing query: "
                          << req->prompt.substr(0, 50)
                          << (req->prompt.size() > 50 ? "..." : "") << std::endl;
            }

            // Build message (prime with docs if needed)
            std::string message = req->primed ? req->prompt : build_primed_message(req->prompt);

            client.send_query(message);

            // Stream messages to main queue
            for (const auto& msg : client.receive_messages()) {
                main_queue_.push(ClaudeMessage{msg});

                if (claude::is_result_message(msg)) {
                    if (verbose_) {
                        std::cerr << "[CLIENT] Query complete" << std::endl;
                    }
                    break;
                }
            }
        }

        client.disconnect();

    } catch (const claude::CLINotFoundError&) {
        // Push error as a fake message
        claude::AssistantMessage err_msg;
        err_msg.content.push_back(claude::TextBlock{
            "Error: Claude CLI not found. Please install it with: npm install -g @anthropic-ai/claude-code"
        });
        main_queue_.push(ClaudeMessage{err_msg});
    } catch (const std::exception& e) {
        claude::AssistantMessage err_msg;
        err_msg.content.push_back(claude::TextBlock{
            std::string("Error: ") + e.what()
        });
        main_queue_.push(ClaudeMessage{err_msg});
    }

    if (verbose_) {
        std::cerr << "[CLIENT] Thread exiting" << std::endl;
    }
}

claude::ClaudeOptions ClaudeAgent::create_options() {
    using namespace claude::mcp;

    claude::ClaudeOptions opts;

    // NOTE: Don't set system_prompt or system_prompt_append - they break MCP tool visibility
    // Instead, embed instructions in the first message (priming)

    // Create MCP tool that dispatches to main thread via queue
    // This lambda runs on the SDK's reader thread - we can't call IDA APIs here!
    auto idasql_tool = make_tool(
        "idasql",
        "Execute a SQL query against an IDA Pro database. "
        "Available tables: funcs, strings, imports, segments, names, xrefs, instructions, "
        "blocks, comments, types, entries, heads, fchunks, bookmarks, pseudocode, ctree, "
        "ctree_lvars, ctree_call_args. "
        "Example: SELECT name, size FROM funcs WHERE name LIKE 'sub_%' ORDER BY size DESC LIMIT 10",
        [this](std::string query) -> std::string {
            if (verbose_) {
                std::cerr << "[MCP] Dispatching query to main thread: "
                          << query.substr(0, 80)
                          << (query.size() > 80 ? "..." : "") << std::endl;
            }

            // Create promise/future pair
            std::promise<claude::json> promise;
            auto future = promise.get_future();

            // Create dispatch with query in JSON format
            claude::json request = {{"query", query}};

            // Push to main queue - main thread will execute and fulfill promise
            main_queue_.push(McpDispatch{std::move(request), std::move(promise)});

            // Block until main thread processes (this is OK - we're on reader thread)
            try {
                auto result = future.get();
                return result.value("result", "");
            } catch (const std::exception& e) {
                return std::string("Error: ") + e.what();
            }
        },
        std::vector<std::string>{"query"}
    );

    // Create in-process MCP server with our tool
    auto server = create_server("idasql", "1.0.0", idasql_tool);

    // Wrap with debug logging if verbose
    if (verbose_) {
        auto base_server = server;
        server = [base_server](const claude::json& request) -> claude::json {
            std::cerr << "[MCP] " << request.value("method", "?") << std::endl;
            return base_server(request);
        };
    }

    // Register as in-process handler
    opts.sdk_mcp_handlers["idasql"] = server;

    // Register the SDK MCP server with the CLI via mcp_config
    claude::json mcp_config = {
        {"mcpServers", {
            {"idasql", {
                {"type", "sdk"},
                {"name", "idasql"}
            }}
        }}
    };
    opts.mcp_config = mcp_config.dump();

    // Allow our MCP tool
    opts.allowed_tools = {"mcp__idasql__idasql", "idasql"};

    // Bypass permission prompts for automation
    opts.permission_mode = "bypassPermissions";

    // Add stderr callback when verbose mode is enabled
    if (verbose_) {
        opts.stderr_callback = [](const std::string& line) {
            std::cerr << "[CLAUDE] " << line << std::endl;
        };
    }

    return opts;
}

// ============================================================================
// Main Thread Interface
// ============================================================================

void ClaudeAgent::send_query(const std::string& prompt) {
    // Check if it's raw SQL - execute directly on main thread
    if (looks_like_sql(prompt)) {
        std::string result = executor_(prompt);
        claude::AssistantMessage msg;
        msg.content.push_back(claude::TextBlock{result});
        main_queue_.push(ClaudeMessage{msg});

        // Also push a fake result message to signal completion
        claude::ResultMessage result_msg;
        result_msg.subtype = "success";
        main_queue_.push(ClaudeMessage{result_msg});
        return;
    }

    // Queue for Claude processing
    bool needs_priming = !docs_primed_;
    query_queue_.push(QueryRequest{prompt, docs_primed_});
    docs_primed_ = true;
}

std::optional<claude::Message> ClaudeAgent::pump_once() {
    auto item = main_queue_.try_pop();
    if (!item) return std::nullopt;

    return std::visit([this](auto&& arg) -> std::optional<claude::Message> {
        using T = std::decay_t<decltype(arg)>;

        if constexpr (std::is_same_v<T, ClaudeMessage>) {
            return arg.msg;
        } else if constexpr (std::is_same_v<T, McpDispatch>) {
            handle_mcp_dispatch(const_cast<McpDispatch&>(arg));
            return std::nullopt;
        }
        return std::nullopt;
    }, *item);
}

std::string ClaudeAgent::pump_until_result(MessageCallback on_message) {
    std::string result;

    while (!quit_requested_.load()) {
        auto item = main_queue_.pop();
        if (!item) break;  // Queue stopped

        std::visit([&](auto&& arg) {
            using T = std::decay_t<decltype(arg)>;

            if constexpr (std::is_same_v<T, ClaudeMessage>) {
                const auto& msg = arg.msg;

                // Notify callback
                if (on_message) {
                    on_message(msg);
                }

                // Extract text from assistant messages
                if (claude::is_assistant_message(msg)) {
                    const auto& assistant = std::get<claude::AssistantMessage>(msg);
                    for (const auto& block : assistant.content) {
                        if (std::holds_alternative<claude::TextBlock>(block)) {
                            if (!result.empty()) result += "\n";
                            result += std::get<claude::TextBlock>(block).text;
                        }
                    }
                }

            } else if constexpr (std::is_same_v<T, McpDispatch>) {
                handle_mcp_dispatch(const_cast<McpDispatch&>(arg));
            }
        }, *item);

        // Check if this was the result message
        if (auto* cm = std::get_if<ClaudeMessage>(&*item)) {
            if (claude::is_result_message(cm->msg)) {
                break;
            }
        }
    }

    return result;
}

void ClaudeAgent::handle_mcp_dispatch(McpDispatch& dispatch) {
    try {
        std::string query = dispatch.request.value("query", "");

        if (verbose_) {
            std::cerr << "[MAIN] Executing SQL: " << query.substr(0, 80)
                      << (query.size() > 80 ? "..." : "") << std::endl;
        }

        // Execute on main thread - THIS IS SAFE!
        std::string result = executor_(query);

        if (verbose_) {
            std::cerr << "[MAIN] SQL result: " << result.size() << " bytes" << std::endl;
        }

        // Fulfill promise
        claude::json response = {{"result", result}};
        dispatch.promise.set_value(response);

    } catch (const std::exception& e) {
        dispatch.promise.set_exception(std::current_exception());
    }
}

// ============================================================================
// Helpers
// ============================================================================

std::string ClaudeAgent::build_primed_message(const std::string& user_message) {
    return std::string(SYSTEM_PROMPT) +
        "\n\n---\n\n"
        "# User Request\n\n"
        "Use the `mcp__idasql__idasql` tool to execute SQL queries. "
        "Do not use Bash, Grep, or other tools - only use the idasql MCP tool.\n\n" +
        user_message;
}

bool ClaudeAgent::looks_like_sql(const std::string& input) {
    if (input.empty()) return false;

    // Find first non-whitespace character
    size_t start = 0;
    while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start]))) {
        ++start;
    }
    if (start >= input.size()) return false;

    // Convert first ~20 chars to uppercase for comparison
    std::string prefix;
    for (size_t i = start; i < input.size() && i < start + 20; ++i) {
        prefix += static_cast<char>(std::toupper(static_cast<unsigned char>(input[i])));
    }

    // Check for SQL keywords
    return prefix.rfind("SELECT ", 0) == 0 ||
           prefix.rfind("INSERT ", 0) == 0 ||
           prefix.rfind("UPDATE ", 0) == 0 ||
           prefix.rfind("DELETE ", 0) == 0 ||
           prefix.rfind("CREATE ", 0) == 0 ||
           prefix.rfind("DROP ", 0) == 0 ||
           prefix.rfind("PRAGMA ", 0) == 0 ||
           prefix.rfind("WITH ", 0) == 0 ||
           prefix.rfind("EXPLAIN ", 0) == 0 ||
           prefix.rfind(".TABLES", 0) == 0 ||
           prefix.rfind(".SCHEMA", 0) == 0 ||
           prefix.rfind(".HELP", 0) == 0 ||
           prefix.rfind(".QUIT", 0) == 0 ||
           prefix.rfind(".EXIT", 0) == 0;
}

bool ClaudeAgent::is_available() {
    try {
        claude::ClaudeOptions opts;
        opts.permission_mode = "bypassPermissions";
        claude::ClaudeClient client(opts);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace idasql

#endif // IDASQL_HAS_CLAUDE_AGENT
