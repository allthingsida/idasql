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
    xsql::runtime::RuntimeSettingsSnapshot core;
    bool enable_idapython = false;
    size_t idapython_output_max = 0;
    bool idapython_echo = false;
    std::string auto_checkpoint = "off";
};

inline constexpr const char* kAutoCheckpointValueError =
    "runtime_settings: auto_checkpoint must be 'off' or 'statement'";

inline bool is_auto_checkpoint_value(const std::string& value) {
    return value == "off" || value == "statement";
}

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

    bool idapython_echo() const {
        return bool_value("idapython_echo", false);
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
        snap.idapython_echo = idapython_echo();
        snap.auto_checkpoint = auto_checkpoint();
        return snap;
    }

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
        (void)register_bool_setting("idapython_echo", false, "idasql");
        (void)register_string_setting("auto_checkpoint", "off", "idasql");
    }
};

inline RuntimeSettings& runtime_settings() {
    return RuntimeSettings::instance();
}

}
