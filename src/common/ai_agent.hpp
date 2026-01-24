#pragma once

#ifdef IDASQL_HAS_AI_AGENT

#include <libagents/agent.hpp>
#include <libagents/config.hpp>
#include "agent_settings.hpp"
#include <atomic>
#include <functional>
#include <memory>
#include <string>

namespace idasql {

/**
 * AIAgent - Natural language interface for IDASQL using libagents
 *
 * This is a simplified wrapper around libagents that provides:
 * - Tool registration for SQL execution
 * - Main-thread tool dispatch via query_hosted() (required for IDA safety)
 * - SQL passthrough detection
 * - Signal handling for Ctrl-C
 * - BYOK (Bring Your Own Key) support for Copilot provider
 *
 * Architecture:
 *   - libagents handles all threading internally
 *   - query_hosted() ensures tool handlers run on the caller thread
 *   - No custom queues or thread management needed
 */
class AIAgent {
public:
    /// Callback to execute SQL and return formatted results
    using SqlExecutor = std::function<std::string(const std::string& sql)>;

    /// Callback for streaming content
    using ContentCallback = std::function<void(const std::string& content)>;

    /**
     * Construct agent with SQL executor and settings
     * @param executor Function that executes SQL and returns formatted results
     * @param settings Agent settings (provider, BYOK, timeout, etc.)
     * @param verbose If true, show debug output
     */
    explicit AIAgent(SqlExecutor executor, const AgentSettings& settings, bool verbose = false);

    /**
     * Construct agent with SQL executor (uses stored settings)
     * @param executor Function that executes SQL and returns formatted results
     * @param verbose If true, show debug output
     */
    explicit AIAgent(SqlExecutor executor, bool verbose = false);

    /**
     * Configure BYOK (Bring Your Own Key) - call before start()
     * Required for Copilot provider, optional for Claude
     * @param config BYOK configuration (api_key, base_url, model, provider_type)
     */
    void set_byok(const libagents::BYOKConfig& config);

    /**
     * Load BYOK config from environment variables (fallback)
     * Looks for COPILOT_SDK_BYOK_API_KEY, COPILOT_SDK_BYOK_BASE_URL, etc.
     * @return true if BYOK was configured from environment
     */
    bool load_byok_from_env();

    /**
     * Get the current provider type
     */
    libagents::ProviderType provider_type() const { return provider_type_; }

    ~AIAgent();

    // Non-copyable, non-movable
    AIAgent(const AIAgent&) = delete;
    AIAgent& operator=(const AIAgent&) = delete;
    AIAgent(AIAgent&&) = delete;
    AIAgent& operator=(AIAgent&&) = delete;

    /**
     * Start the agent and connect to provider
     */
    void start();

    /**
     * Stop the agent and disconnect
     */
    void stop();

    /**
     * Reset the session - clears conversation history
     */
    void reset_session();

    /**
     * Request to quit (e.g., from Ctrl-C handler)
     * Thread-safe, can be called from signal handler
     */
    void request_quit();

    /**
     * Check if quit was requested
     */
    bool quit_requested() const { return quit_requested_.load(); }

    /**
     * Send a query and get response (blocking)
     * SQL is passed through directly, natural language goes to AI.
     * Tool handlers execute on the caller thread (main thread safe).
     *
     * @param prompt User input (natural language or SQL)
     * @return Response text
     */
    std::string query(const std::string& prompt);

    /**
     * Send a query with streaming output
     * @param prompt User input
     * @param on_content Callback for content deltas
     * @return Final response text
     */
    std::string query_streaming(const std::string& prompt, ContentCallback on_content);

    /**
     * Check if input looks like SQL (for passthrough)
     * @param input User input string
     * @return true if input appears to be SQL
     */
    static bool looks_like_sql(const std::string& input);

    /**
     * Check if AI agent is available
     * @return true if the default provider is available
     */
    static bool is_available();

private:
    SqlExecutor executor_;
    bool verbose_ = false;
    bool docs_primed_ = false;
    std::atomic<bool> quit_requested_{false};
    std::unique_ptr<libagents::IAgent> agent_;
    libagents::ProviderType provider_type_ = libagents::ProviderType::Claude;
    libagents::BYOKConfig byok_config_;
    bool byok_configured_ = false;
    int response_timeout_ms_ = 0;

    /// Register the idasql tool with libagents
    void setup_tools();

    /// Build primed message with documentation prepended
    std::string build_primed_message(const std::string& user_message);
};

} // namespace idasql

#endif // IDASQL_HAS_AI_AGENT
