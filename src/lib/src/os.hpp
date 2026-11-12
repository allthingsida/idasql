// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>

namespace idasql {
namespace os {

enum class WaitResult { signaled, timeout, error };

class NamedSemaphore {
public:
    static constexpr size_t kMaxName = 30;

    NamedSemaphore() = default;
    NamedSemaphore(const NamedSemaphore&) = delete;
    NamedSemaphore& operator=(const NamedSemaphore&) = delete;
    ~NamedSemaphore() { close(); }

    bool create(const std::string& name);
    bool open(const std::string& name);
    bool post();
    WaitResult wait(int timeout_ms = -1);
    void close();
    bool valid() const;

    static bool valid_name(const std::string& name);

private:
    void* handle_ = nullptr;
    std::string platform_name_;
    bool owner_ = false;
};

class SemaphoreWaiter {
public:
    SemaphoreWaiter() = default;
    SemaphoreWaiter(const SemaphoreWaiter&) = delete;
    SemaphoreWaiter& operator=(const SemaphoreWaiter&) = delete;
    ~SemaphoreWaiter() { stop(); }

    bool start(const std::string& name, std::function<void()> callback);
    void signal();
    void stop();
    bool running() const { return thread_.joinable(); }

private:
    NamedSemaphore sem_;
    std::thread thread_;
    std::atomic<bool> stop_{false};
    std::function<void()> callback_;
};

std::filesystem::path config_dir();

uint64_t current_pid();

std::string current_exe_name();

bool pid_alive(uint64_t pid);

}
}
