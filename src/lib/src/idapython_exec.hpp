// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * idapython_exec.hpp - IDAPython bridge
 */

#pragma once

#include <idasql/platform.hpp>

#include <cstddef>
#include <cstdarg>
#include <string>
#include <sstream>
#include <mutex>

#include "ida_headers.hpp"

namespace idasql {
namespace idapython {

struct ExecutionResult {
    bool success = false;
    std::string output;
    std::string error;
};

std::string hex_encode(const std::string& input);

class UiMessageCapture : public event_listener_t {
public:
    static UiMessageCapture& instance();

    bool acquire_runtime(std::string* error = nullptr);
    void release_runtime();
    bool begin_capture(std::string* error = nullptr);
    std::string end_capture();

    virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

private:
    UiMessageCapture() = default;

    bool ensure_hook_locked(std::string* error);
    void maybe_unhook_locked();

    std::mutex mutex_;
    bool hooked_ = false;
    bool capturing_ = false;
    size_t runtime_refcount_ = 0;
    std::ostringstream buffer_;
};

bool runtime_acquire(std::string* error = nullptr);
void runtime_release();

class ScopedCapture {
public:
    ScopedCapture();
    ~ScopedCapture();
    bool ok() const { return active_; }
    const std::string& error() const { return error_; }
    std::string finish();

private:
    bool active_ = false;
    bool finished_ = false;
    std::string error_;
    std::string output_;
};

extlang_t* get_python_extlang();
std::string build_namespace_preamble(const std::string& sandbox);
std::string build_namespaced_snippet(const std::string& code, const std::string& sandbox);
std::string build_namespaced_file_snippet(const std::string& path, const std::string& sandbox);
ExecutionResult execute_snippet(const std::string& code, const std::string& sandbox);
ExecutionResult execute_file(const std::string& path, const std::string& sandbox);

} // namespace idapython
} // namespace idasql
