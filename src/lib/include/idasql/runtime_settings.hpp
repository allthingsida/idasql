// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <xsql/runtime_settings.hpp>

#include <cstddef>
#include <limits>
#include <string>

namespace idasql {

struct RuntimeSettingsSnapshot {
    // The shared settings (query_timeout_ms / queue_admission_timeout_ms / max_queue
    // / hints_enabled / timeout_stack_depth) live in the core -- the single source of
    // truth for the fields AND their defaults, so an idasql snapshot cannot drift.
    xsql::runtime::RuntimeSettingsSnapshot core;
    // idasql-only knobs:
    bool enable_idapython = false;
    // Max captured IDAPython print output in bytes; 0 == unbounded (the default).
    // When >0, snippet output past the cap is dropped with a truncation marker.
    size_t idapython_output_max = 0;
    // 'off' or 'statement': every top-level statement that writes gets its own
    // undo checkpoint.
    std::string auto_checkpoint = "off";
};

// auto_checkpoint takes one of two values; the runtime_settings table refuses
// anything else with this message.
inline constexpr const char* kAutoCheckpointValueError =
    "runtime_settings: auto_checkpoint must be 'off' or 'statement'";

inline bool is_auto_checkpoint_value(const std::string& value) {
    return value == "off" || value == "statement";
}


// idasql's runtime-settings singleton IS-A shared RuntimeSettingsCore: common
// and product keys use one typed registry and one transactional SQL adapter.
// Only timeout_push/timeout_pop remain PRAGMAs.
class RuntimeSettings : public xsql::runtime::RuntimeSettingsCore {
public:
    static RuntimeSettings& instance() {
        static RuntimeSettings settings;
        return settings;
    }

    bool enable_idapython() const {
        return bool_value("enable_idapython", false);
    }

    size_t idapython_output_max() const {
        return static_cast<size_t>(integer_value("idapython_output_max", 0));
    }

    std::string auto_checkpoint() const {
        const auto current = value("auto_checkpoint");
        return current ? *current : std::string("off");
    }

    void set_enable_idapython(bool enabled) {
        (void)apply("enable_idapython", enabled ? "1" : "0", "idasql");
    }

    void set_idapython_output_max(size_t max_bytes) {
        (void)apply("idapython_output_max", std::to_string(max_bytes), "idasql");
    }

    RuntimeSettingsSnapshot snapshot() const {
        RuntimeSettingsSnapshot snap;
        snap.core = xsql::runtime::RuntimeSettingsCore::snapshot();
        snap.enable_idapython = enable_idapython();
        snap.idapython_output_max = idapython_output_max();
        snap.auto_checkpoint = auto_checkpoint();
        return snap;
    }

    // The object IS the core; kept so callers passing a RuntimeSettingsCore&
    // remain unchanged.
    xsql::runtime::RuntimeSettingsCore& common_settings() { return *this; }
    const xsql::runtime::RuntimeSettingsCore& common_settings() const {
        return *this;
    }

private:
    RuntimeSettings()
        : RuntimeSettingsCore(xsql::runtime::RuntimeSettingsCoreOptions{64}) {
        (void)register_bool_setting("enable_idapython", false, "idasql");
        (void)register_integer_setting(
            "idapython_output_max", 0, 0, (std::numeric_limits<int>::max)(), "idasql");
        // 'off' | 'statement' (checked by idasql's runtime_settings table).
        (void)register_string_setting("auto_checkpoint", "off", "idasql");
    }
};

inline RuntimeSettings& runtime_settings() {
    return RuntimeSettings::instance();
}

}  // namespace idasql
