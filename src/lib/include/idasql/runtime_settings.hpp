#pragma once

#include <cstddef>
#include <mutex>
#include <vector>

namespace idasql {

struct RuntimeSettingsSnapshot {
    int query_timeout_ms = 60000;
    int queue_admission_timeout_ms = 120000;
    size_t max_queue = 64;
    bool hints_enabled = true;
    size_t timeout_stack_depth = 0;
};

class RuntimeSettings {
public:
    static RuntimeSettings& instance() {
        static RuntimeSettings settings;
        return settings;
    }

    RuntimeSettingsSnapshot snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        RuntimeSettingsSnapshot snap;
        snap.query_timeout_ms = query_timeout_ms_;
        snap.queue_admission_timeout_ms = queue_admission_timeout_ms_;
        snap.max_queue = max_queue_;
        snap.hints_enabled = hints_enabled_;
        snap.timeout_stack_depth = timeout_stack_.size();
        return snap;
    }

    int query_timeout_ms() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return query_timeout_ms_;
    }

    int queue_admission_timeout_ms() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_admission_timeout_ms_;
    }

    size_t max_queue() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return max_queue_;
    }

    bool hints_enabled() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return hints_enabled_;
    }

    bool set_query_timeout_ms(int value) {
        if (!is_valid_timeout(value)) {
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        query_timeout_ms_ = value;
        return true;
    }

    bool set_queue_admission_timeout_ms(int value) {
        if (!is_valid_timeout(value)) {
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        queue_admission_timeout_ms_ = value;
        return true;
    }

    bool set_max_queue(size_t value) {
        // 0 means "unbounded".
        if (value > kMaxQueueLimit) {
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        max_queue_ = value;
        return true;
    }

    void set_hints_enabled(bool enabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        hints_enabled_ = enabled;
    }

    bool timeout_push(int timeout_ms, int* effective_timeout_ms = nullptr) {
        if (!is_valid_timeout(timeout_ms)) {
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        timeout_stack_.push_back(query_timeout_ms_);
        query_timeout_ms_ = timeout_ms;
        if (effective_timeout_ms != nullptr) {
            *effective_timeout_ms = query_timeout_ms_;
        }
        return true;
    }

    bool timeout_pop(int* effective_timeout_ms = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (timeout_stack_.empty()) {
            return false;
        }
        query_timeout_ms_ = timeout_stack_.back();
        timeout_stack_.pop_back();
        if (effective_timeout_ms != nullptr) {
            *effective_timeout_ms = query_timeout_ms_;
        }
        return true;
    }

private:
    static constexpr int kMaxTimeoutMs = 3600 * 1000;  // 1 hour
    static constexpr size_t kMaxQueueLimit = 10000;

    static bool is_valid_timeout(int value) {
        return value >= 0 && value <= kMaxTimeoutMs;
    }

    RuntimeSettings() = default;

    mutable std::mutex mutex_;
    int query_timeout_ms_ = 60000;
    int queue_admission_timeout_ms_ = 120000;
    size_t max_queue_ = 64;
    bool hints_enabled_ = true;
    std::vector<int> timeout_stack_;
};

inline RuntimeSettings& runtime_settings() {
    return RuntimeSettings::instance();
}

}  // namespace idasql

