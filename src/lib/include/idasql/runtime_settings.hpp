// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <xsql/runtime_settings.hpp>

#include <cstddef>
#include <mutex>

namespace idasql {

struct RuntimeSettingsSnapshot {
    // The shared settings (query_timeout_ms / queue_admission_timeout_ms / max_queue
    // / hints_enabled / timeout_stack_depth) live in the core struct -- the single
    // source of truth for both the fields AND their default values, so a
    // default-constructed idasql snapshot can never silently drift from the core.
    xsql::runtime::RuntimeSettingsSnapshot core;
    // idasql-only knobs:
    bool enable_idapython = false;
    // Max captured IDAPython print output in bytes; 0 == unbounded (the default).
    // When >0, snippet output past the cap is dropped with a truncation marker.
    size_t idapython_output_max = 0;
};

class RuntimeSettings {
public:
    static RuntimeSettings& instance() {
        static RuntimeSettings settings;
        return settings;
    }

    RuntimeSettingsSnapshot snapshot() const {
        RuntimeSettingsSnapshot snap;
        snap.core = common_.snapshot();
        snap.enable_idapython = enable_idapython();
        snap.idapython_output_max = idapython_output_max();
        return snap;
    }

    int query_timeout_ms() const {
        return common_.query_timeout_ms();
    }

    int queue_admission_timeout_ms() const {
        return common_.queue_admission_timeout_ms();
    }

    size_t max_queue() const {
        return common_.max_queue();
    }

    bool hints_enabled() const {
        return common_.hints_enabled();
    }

    bool enable_idapython() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return enable_idapython_;
    }

    size_t idapython_output_max() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return idapython_output_max_;
    }

    bool set_query_timeout_ms(int value) {
        return common_.set_query_timeout_ms(value);
    }

    bool set_queue_admission_timeout_ms(int value) {
        return common_.set_queue_admission_timeout_ms(value);
    }

    bool set_max_queue(size_t value) {
        return common_.set_max_queue(value);
    }

    void set_hints_enabled(bool enabled) {
        common_.set_hints_enabled(enabled);
    }

    void set_enable_idapython(bool enabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        enable_idapython_ = enabled;
    }

    void set_idapython_output_max(size_t max_bytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        idapython_output_max_ = max_bytes;
    }

    bool timeout_push(int timeout_ms, int* effective_timeout_ms = nullptr) {
        return common_.timeout_push(timeout_ms, effective_timeout_ms);
    }

    bool timeout_pop(int* effective_timeout_ms = nullptr) {
        return common_.timeout_pop(effective_timeout_ms);
    }

    xsql::runtime::RuntimeSettingsCore& common_settings() {
        return common_;
    }

    const xsql::runtime::RuntimeSettingsCore& common_settings() const {
        return common_;
    }

private:
    // Cap the client-driven PRAGMA idasql.timeout_push stack (matches bnsql's 64,
    // which is also the shared-core default). Stated explicitly so the bound is
    // visible at the adopter and independent of the core's default.
    RuntimeSettings() : common_(xsql::runtime::RuntimeSettingsCoreOptions{64}) {}

    xsql::runtime::RuntimeSettingsCore common_;
    mutable std::mutex mutex_;
    bool enable_idapython_ = false;
    size_t idapython_output_max_ = 0;  // 0 == unbounded
};

inline RuntimeSettings& runtime_settings() {
    return RuntimeSettings::instance();
}

}  // namespace idasql
