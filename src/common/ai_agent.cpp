#include "ai_agent.hpp"

#ifdef IDASQL_HAS_AI_AGENT

// Embedded documentation from prompts/idasql_agent.md
#include "idasql_agent_prompt.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>

namespace idasql {

// ============================================================================
// Construction / Destruction
// ============================================================================

AIAgent::AIAgent(SqlExecutor executor, bool verbose)
    : executor_(std::move(executor)), verbose_(verbose)
{
    // Create agent with default provider (Claude for now, Copilot support planned)
    agent_ = libagents::create_agent(libagents::ProviderType::Claude);
}

AIAgent::~AIAgent() {
    stop();
}

// ============================================================================
// Lifecycle
// ============================================================================

void AIAgent::start() {
    if (!agent_) return;

    setup_tools();

    // Note: We don't use set_system_prompt() because it can break MCP tool
    // visibility with some providers. Instead, we embed the prompt in the
    // first message (priming).

    if (!agent_->initialize()) {
        if (verbose_) {
            std::cerr << "[AGENT] Failed to initialize agent" << std::endl;
        }
        return;
    }

    if (verbose_) {
        std::cerr << "[AGENT] Agent initialized (" << agent_->provider_name() << ")" << std::endl;
    }
}

void AIAgent::stop() {
    if (agent_ && agent_->is_initialized()) {
        agent_->shutdown();
        if (verbose_) {
            std::cerr << "[AGENT] Agent shutdown" << std::endl;
        }
    }
}

void AIAgent::reset_session() {
    if (verbose_) {
        std::cerr << "[AGENT] Resetting session..." << std::endl;
    }

    docs_primed_ = false;
    quit_requested_.store(false);

    if (agent_) {
        agent_->clear_session();
    }

    if (verbose_) {
        std::cerr << "[AGENT] Session reset complete" << std::endl;
    }
}

void AIAgent::request_quit() {
    quit_requested_.store(true);
    if (agent_) {
        agent_->abort();
    }
}

// ============================================================================
// Tool Registration
// ============================================================================

void AIAgent::setup_tools() {
    libagents::Tool idasql_tool;
    idasql_tool.name = "idasql";
    idasql_tool.description =
        "Execute a SQL query against an IDA Pro database. "
        "Available tables: funcs, strings, imports, segments, names, xrefs, instructions, "
        "blocks, comments, types, entries, heads, fchunks, bookmarks, pseudocode, ctree, "
        "ctree_lvars, ctree_call_args. "
        "Example: SELECT name, size FROM funcs WHERE name LIKE 'sub_%' ORDER BY size DESC LIMIT 10";

    idasql_tool.parameters_schema = R"({
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "SQL query to execute against the IDA database"
            }
        },
        "required": ["query"]
    })";

    // Tool handler - executes on caller thread via query_hosted()
    idasql_tool.handler = [this](const std::string& args) -> std::string {
        try {
            auto j = libagents::json::parse(args);
            std::string sql = j.value("query", "");

            if (verbose_) {
                std::cerr << "[TOOL] Executing SQL: " << sql.substr(0, 80)
                          << (sql.size() > 80 ? "..." : "") << std::endl;
            }

            // This runs on the main thread (query_hosted guarantees this)
            std::string result = executor_(sql);

            if (verbose_) {
                std::cerr << "[TOOL] Result: " << result.size() << " bytes" << std::endl;
            }

            return result;

        } catch (const std::exception& e) {
            return std::string("Error: ") + e.what();
        }
    };

    agent_->register_tool(idasql_tool);

    if (verbose_) {
        std::cerr << "[AGENT] Registered idasql tool" << std::endl;
    }
}

// ============================================================================
// Query Interface
// ============================================================================

std::string AIAgent::query(const std::string& prompt) {
    // SQL passthrough - execute directly
    if (looks_like_sql(prompt)) {
        return executor_(prompt);
    }

    if (!agent_ || !agent_->is_initialized()) {
        return "Error: Agent not initialized";
    }

    // Build message (prime with docs if first message)
    std::string message = docs_primed_ ? prompt : build_primed_message(prompt);
    docs_primed_ = true;

    // Use query_hosted for main-thread tool dispatch
    libagents::HostContext host;
    host.should_abort = [this]() { return quit_requested_.load(); };

    try {
        return agent_->query_hosted(message, host);
    } catch (const std::exception& e) {
        return std::string("Error: ") + e.what();
    }
}

std::string AIAgent::query_streaming(const std::string& prompt, ContentCallback on_content) {
    // SQL passthrough
    if (looks_like_sql(prompt)) {
        std::string result = executor_(prompt);
        if (on_content) on_content(result);
        return result;
    }

    if (!agent_ || !agent_->is_initialized()) {
        std::string err = "Error: Agent not initialized";
        if (on_content) on_content(err);
        return err;
    }

    // Build message
    std::string message = docs_primed_ ? prompt : build_primed_message(prompt);
    docs_primed_ = true;

    // Use query_hosted with streaming callback
    libagents::HostContext host;
    host.should_abort = [this]() { return quit_requested_.load(); };
    host.on_event = [on_content](const libagents::Event& event) {
        if (on_content && event.type == libagents::EventType::ContentDelta) {
            on_content(event.content);
        }
    };

    try {
        return agent_->query_hosted(message, host);
    } catch (const std::exception& e) {
        return std::string("Error: ") + e.what();
    }
}

// ============================================================================
// Helpers
// ============================================================================

std::string AIAgent::build_primed_message(const std::string& user_message) {
    return std::string(SYSTEM_PROMPT) +
        "\n\n---\n\n"
        "# User Request\n\n"
        "Use the `idasql` tool to execute SQL queries. "
        "Do not use Bash, Grep, or other tools - only use the idasql tool.\n\n" +
        user_message;
}

bool AIAgent::looks_like_sql(const std::string& input) {
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

bool AIAgent::is_available() {
    try {
        // Just check if we can create an agent - don't initialize
        // (initialization is expensive and would be redundant if we're about to
        // create another agent anyway)
        auto agent = libagents::create_agent(libagents::ProviderType::Claude);
        return agent != nullptr;
    } catch (...) {
        return false;
    }
}

} // namespace idasql

#endif // IDASQL_HAS_AI_AGENT
