#pragma once

#ifdef IDASQL_HAS_AI_AGENT

#include <libagents/config.hpp>
#include <libagents/provider.hpp>
#include <nlohmann/json.hpp>

#include <string>
#include <unordered_map>
#include <fstream>
#include <cstdlib>

#ifdef _WIN32
#include <shlobj.h>
#include <windows.h>
#else
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

namespace idasql {

// BYOK (Bring Your Own Key) settings for a single provider
struct BYOKSettings {
    bool enabled = false;
    std::string api_key;
    std::string base_url;
    std::string model;
    std::string provider_type;  // "openai", "anthropic", "azure"
    int timeout_ms = 0;

    // Convert to libagents BYOKConfig
    libagents::BYOKConfig to_config() const {
        libagents::BYOKConfig config;
        config.api_key = api_key;
        config.base_url = base_url;
        config.model = model;
        config.provider_type = provider_type;
        config.timeout_ms = timeout_ms;
        return config;
    }

    // Check if BYOK is usable (enabled and has API key)
    bool is_usable() const { return enabled && !api_key.empty(); }
};

// Agent settings stored in ~/.idasql/agent_settings.json
struct AgentSettings {
    // Default provider (claude, copilot)
    libagents::ProviderType default_provider = libagents::ProviderType::Claude;

    // User's custom prompt (additive to system prompt)
    std::string custom_prompt;

    // Response timeout in milliseconds (0 = use default)
    int response_timeout_ms = 120000;  // 2 minutes default

    // BYOK configuration per provider
    // Key: provider name ("copilot", "claude")
    std::unordered_map<std::string, BYOKSettings> byok;

    // Get BYOK settings for the current provider
    const BYOKSettings* get_byok() const {
        std::string provider_name = libagents::provider_type_name(default_provider);
        auto it = byok.find(provider_name);
        if (it != byok.end())
            return &it->second;
        return nullptr;
    }

    // Get or create BYOK settings for the current provider
    BYOKSettings& get_or_create_byok() {
        std::string provider_name = libagents::provider_type_name(default_provider);
        return byok[provider_name];
    }
};

// Get the settings directory path (~/.idasql or %APPDATA%\idasql)
inline std::string GetSettingsDir() {
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        return std::string(path) + "\\idasql";
    }
    // Fallback to USERPROFILE
    const char* userprofile = std::getenv("USERPROFILE");
    if (userprofile) {
        return std::string(userprofile) + "\\.idasql";
    }
    return ".idasql";
#else
    const char* home = std::getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (home) {
        return std::string(home) + "/.idasql";
    }
    return ".idasql";
#endif
}

// Get the settings file path
inline std::string GetSettingsPath() {
    return GetSettingsDir() +
#ifdef _WIN32
        "\\agent_settings.json";
#else
        "/agent_settings.json";
#endif
}

// Ensure directory exists
inline bool EnsureDir(const std::string& path) {
#ifdef _WIN32
    return CreateDirectoryA(path.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
#else
    return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
#endif
}

// JSON serialization
inline void to_json(nlohmann::json& j, const BYOKSettings& s) {
    j = nlohmann::json{
        {"enabled", s.enabled},
        {"api_key", s.api_key},
        {"base_url", s.base_url},
        {"model", s.model},
        {"provider_type", s.provider_type},
        {"timeout_ms", s.timeout_ms}
    };
}

inline void from_json(const nlohmann::json& j, BYOKSettings& s) {
    s.enabled = j.value("enabled", false);
    s.api_key = j.value("api_key", "");
    s.base_url = j.value("base_url", "");
    s.model = j.value("model", "");
    s.provider_type = j.value("provider_type", "");
    s.timeout_ms = j.value("timeout_ms", 0);
}

inline void to_json(nlohmann::json& j, const AgentSettings& s) {
    j = nlohmann::json{
        {"default_provider", libagents::provider_type_name(s.default_provider)},
        {"custom_prompt", s.custom_prompt},
        {"response_timeout_ms", s.response_timeout_ms},
        {"byok", s.byok}
    };
}

inline void from_json(const nlohmann::json& j, AgentSettings& s) {
    std::string provider_str = j.value("default_provider", "claude");
    if (provider_str == "copilot") {
        s.default_provider = libagents::ProviderType::Copilot;
    } else {
        s.default_provider = libagents::ProviderType::Claude;
    }
    s.custom_prompt = j.value("custom_prompt", "");
    s.response_timeout_ms = j.value("response_timeout_ms", 120000);
    if (j.contains("byok") && j["byok"].is_object()) {
        s.byok = j["byok"].get<std::unordered_map<std::string, BYOKSettings>>();
    }
}

// Load settings from disk (creates default if not exists)
inline AgentSettings LoadAgentSettings() {
    AgentSettings settings;
    std::string path = GetSettingsPath();

    std::ifstream f(path);
    if (f.is_open()) {
        try {
            nlohmann::json j = nlohmann::json::parse(f);
            settings = j.get<AgentSettings>();
        } catch (...) {
            // Ignore parse errors, use defaults
        }
    }
    return settings;
}

// Save settings to disk
inline bool SaveAgentSettings(const AgentSettings& settings) {
    std::string dir = GetSettingsDir();
    if (!EnsureDir(dir)) {
        return false;
    }

    std::string path = GetSettingsPath();
    std::ofstream f(path);
    if (!f.is_open()) {
        return false;
    }

    try {
        nlohmann::json j = settings;
        f << j.dump(2);
        return true;
    } catch (...) {
        return false;
    }
}

// Parse provider type from string
inline libagents::ProviderType ParseProviderType(const std::string& name) {
    if (name == "copilot" || name == "Copilot" || name == "COPILOT") {
        return libagents::ProviderType::Copilot;
    }
    if (name == "claude" || name == "Claude" || name == "CLAUDE") {
        return libagents::ProviderType::Claude;
    }
    throw std::runtime_error("Unknown provider: " + name + " (use 'claude' or 'copilot')");
}

} // namespace idasql

#endif // IDASQL_HAS_AI_AGENT
