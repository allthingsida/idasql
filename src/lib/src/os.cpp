// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "os.hpp"

#include <chrono>
#include <string>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <fcntl.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace idasql {
namespace os {

bool NamedSemaphore::valid_name(const std::string& name) {
    if (name.empty() || name.size() > kMaxName) return false;
    for (char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
                        c == '-';
        if (!ok) return false;
    }
    return true;
}

#ifdef _WIN32

bool NamedSemaphore::create(const std::string& name) {
    close();
    if (!valid_name(name)) return false;
    HANDLE h = CreateSemaphoreA(nullptr, 0, 0x7fffffff, ("Local\\" + name).c_str());
    if (h == nullptr) return false;
    handle_ = h;
    owner_ = true;
    return true;
}

bool NamedSemaphore::open(const std::string& name) {
    close();
    if (!valid_name(name)) return false;
    HANDLE h = OpenSemaphoreA(SEMAPHORE_MODIFY_STATE | SYNCHRONIZE, FALSE, ("Local\\" + name).c_str());
    if (h == nullptr) return false;
    handle_ = h;
    owner_ = false;
    return true;
}

bool NamedSemaphore::post() {
    return handle_ != nullptr && ReleaseSemaphore(static_cast<HANDLE>(handle_), 1, nullptr) != 0;
}

WaitResult NamedSemaphore::wait(int timeout_ms) {
    if (handle_ == nullptr) return WaitResult::error;
    const DWORD rc =
        WaitForSingleObject(static_cast<HANDLE>(handle_), timeout_ms < 0 ? INFINITE : static_cast<DWORD>(timeout_ms));
    if (rc == WAIT_OBJECT_0) return WaitResult::signaled;
    if (rc == WAIT_TIMEOUT) return WaitResult::timeout;
    return WaitResult::error;
}

void NamedSemaphore::close() {
    if (handle_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = nullptr;
    }
    owner_ = false;
}

bool NamedSemaphore::valid() const { return handle_ != nullptr; }

#else

namespace {
sem_t* as_sem(void* p) { return static_cast<sem_t*>(p); }
}

bool NamedSemaphore::create(const std::string& name) {
    close();
    if (!valid_name(name)) return false;
    const std::string pname = "/" + name;
    sem_unlink(pname.c_str());
    sem_t* s = sem_open(pname.c_str(), O_CREAT | O_EXCL, 0600, 0);
    if (s == SEM_FAILED) return false;
    handle_ = s;
    platform_name_ = pname;
    owner_ = true;
    return true;
}

bool NamedSemaphore::open(const std::string& name) {
    close();
    if (!valid_name(name)) return false;
    sem_t* s = sem_open(("/" + name).c_str(), 0);
    if (s == SEM_FAILED) return false;
    handle_ = s;
    owner_ = false;
    return true;
}

bool NamedSemaphore::post() { return handle_ != nullptr && sem_post(as_sem(handle_)) == 0; }

WaitResult NamedSemaphore::wait(int timeout_ms) {
    if (handle_ == nullptr) return WaitResult::error;
    sem_t* s = as_sem(handle_);
    if (timeout_ms < 0) {
        for (;;) {
            if (sem_wait(s) == 0) return WaitResult::signaled;
            if (errno != EINTR) return WaitResult::error;
        }
    }
#if defined(__APPLE__)
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        if (sem_trywait(s) == 0) return WaitResult::signaled;
        if (errno != EAGAIN && errno != EINTR) return WaitResult::error;
        if (std::chrono::steady_clock::now() >= deadline) return WaitResult::timeout;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
#else
    timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += static_cast<long>(timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }
    for (;;) {
        if (sem_timedwait(s, &ts) == 0) return WaitResult::signaled;
        if (errno == ETIMEDOUT) return WaitResult::timeout;
        if (errno != EINTR) return WaitResult::error;
    }
#endif
}

void NamedSemaphore::close() {
    if (handle_ != nullptr) {
        sem_close(as_sem(handle_));
        handle_ = nullptr;
    }
    if (owner_ && !platform_name_.empty()) sem_unlink(platform_name_.c_str());
    platform_name_.clear();
    owner_ = false;
}

bool NamedSemaphore::valid() const { return handle_ != nullptr; }

#endif

bool SemaphoreWaiter::start(const std::string& name, std::function<void()> callback) {
    stop();
    if (!sem_.create(name)) return false;
    callback_ = std::move(callback);
    stop_.store(false);
    thread_ = std::thread([this] {
        while (sem_.wait(-1) == WaitResult::signaled) {
            if (stop_.load()) break;
            if (callback_) callback_();
        }
    });
    return true;
}

void SemaphoreWaiter::signal() {
    if (sem_.valid()) sem_.post();
}

void SemaphoreWaiter::stop() {
    if (!thread_.joinable()) return;
    stop_.store(true);
    sem_.post();
    thread_.join();
    sem_.close();
}

std::filesystem::path config_dir() {
    namespace fs = std::filesystem;
#ifdef _WIN32
    auto wenv = [](const wchar_t* name) -> std::wstring {
        const DWORD len = GetEnvironmentVariableW(name, nullptr, 0);
        if (len == 0) return std::wstring();
        std::wstring v(len, L'\0');
        v.resize(GetEnvironmentVariableW(name, v.data(), len));
        return v;
    };
    std::wstring base = wenv(L"APPDATA");
    if (base.empty()) base = wenv(L"USERPROFILE");
    return fs::path(base) / "idasql";
#else
    auto env = [](const char* name) -> std::string {
        const char* v = std::getenv(name);
        return v ? std::string(v) : std::string();
    };
#if defined(__APPLE__)
    return fs::path(env("HOME")) / "Library" / "Application Support" / "idasql";
#else
    std::string base = env("XDG_CONFIG_HOME");
    if (base.empty()) base = env("HOME") + "/.config";
    return fs::path(base) / "idasql";
#endif
#endif
}

uint64_t current_pid() {
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return static_cast<uint64_t>(::getpid());
#endif
}

std::string current_exe_name() {
    std::string path;
#ifdef _WIN32
    char buf[MAX_PATH] = {0};
    const DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) path.assign(buf, n);
#elif defined(__APPLE__)
    char buf[4096] = {0};
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) path = buf;
#else
    char buf[4096] = {0};
    const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) path.assign(buf, static_cast<size_t>(n));
#endif
    const size_t slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

bool pid_alive(uint64_t pid) {
    if (pid == 0) return false;
#ifdef _WIN32
    HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (h == nullptr) return GetLastError() == ERROR_ACCESS_DENIED;
    const bool running = WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
    CloseHandle(h);
    return running;
#else
    return ::kill(static_cast<pid_t>(pid), 0) == 0 || errno == EPERM;
#endif
}

}
}
