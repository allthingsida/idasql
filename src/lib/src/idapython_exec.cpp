// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

#include "idapython_exec.hpp"

namespace idasql {
namespace idapython {

std::string hex_encode(const std::string& input) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(input.size() * 2);
    for (unsigned char c : input) {
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0x0f]);
    }
    return out;
}

UiMessageCapture& UiMessageCapture::instance() {
    static UiMessageCapture capture;
    return capture;
}

bool UiMessageCapture::acquire_runtime(std::string* error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ensure_hook_locked(error)) {
        return false;
    }
    ++runtime_refcount_;
    return true;
}

void UiMessageCapture::release_runtime() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (runtime_refcount_ == 0) {
        return;
    }
    --runtime_refcount_;
    maybe_unhook_locked();
}

bool UiMessageCapture::begin_capture(std::string* error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ensure_hook_locked(error)) {
        return false;
    }
    if (capturing_) {
        if (error != nullptr) {
            *error = "Python output capture is already active";
        }
        return false;
    }
    buffer_.str("");
    buffer_.clear();
    capturing_ = true;
    return true;
}

std::string UiMessageCapture::end_capture() {
    std::lock_guard<std::mutex> lock(mutex_);
    capturing_ = false;
    std::string out = buffer_.str();
    buffer_.str("");
    buffer_.clear();
    maybe_unhook_locked();
    return out;
}

ssize_t idaapi UiMessageCapture::on_event(ssize_t code, va_list va) {
    if (code != ui_msg) {
        return 0;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!capturing_) {
            return 0;
        }
    }

    const char* format = va_arg(va, const char*);
    va_list format_args = va_arg(va, va_list);
    if (format == nullptr) {
        return 0;
    }

    va_list copy;
    va_copy(copy, format_args);
    qstring formatted;
    formatted.vsprnt(format, copy);
    va_end(copy);

    std::lock_guard<std::mutex> lock(mutex_);
    if (!capturing_) {
        return 0;
    }

    buffer_ << formatted.c_str();
    return 1;
}

bool UiMessageCapture::ensure_hook_locked(std::string* error) {
    if (hooked_) {
        return true;
    }
    if (!::hook_event_listener(HT_UI, this, nullptr)) {
        if (error != nullptr) {
            *error = "Failed to install UI message capture hook";
        }
        return false;
    }
    hooked_ = true;
    return true;
}

void UiMessageCapture::maybe_unhook_locked() {
    if (hooked_ && runtime_refcount_ == 0 && !capturing_) {
        (void)::unhook_event_listener(HT_UI, this);
        hooked_ = false;
    }
}

bool runtime_acquire(std::string* error) {
    return UiMessageCapture::instance().acquire_runtime(error);
}

void runtime_release() {
    UiMessageCapture::instance().release_runtime();
}

ScopedCapture::ScopedCapture() : active_(UiMessageCapture::instance().begin_capture(&error_)) {}

ScopedCapture::~ScopedCapture() {
    if (active_ && !finished_) {
        output_ = UiMessageCapture::instance().end_capture();
        finished_ = true;
    }
}

std::string ScopedCapture::finish() {
    if (active_ && !finished_) {
        output_ = UiMessageCapture::instance().end_capture();
        finished_ = true;
    }
    return output_;
}

extlang_t* get_python_extlang() {
    static std::mutex mutex;
    static extlang_t* cached = nullptr;
    static bool tried = false;

    std::lock_guard<std::mutex> lock(mutex);
    if (!tried) {
        tried = true;
        extlang_object_t obj = find_extlang_by_name("Python");
        cached = obj;
    }
    return cached;
}

std::string build_namespace_preamble(const std::string& sandbox) {
    const std::string sandbox_hex = hex_encode(sandbox);
    std::ostringstream wrapped;
    wrapped << "import builtins\n"
            << "__idasql_sandbox = bytes.fromhex('" << sandbox_hex << "').decode('utf-8')\n"
            << "if not hasattr(builtins, '__idasql_namespaces__'):\n"
            << "    builtins.__idasql_namespaces__ = {}\n"
            << "if __idasql_sandbox not in builtins.__idasql_namespaces__:\n"
            << "    builtins.__idasql_namespaces__[__idasql_sandbox] = globals().copy()\n";
    return wrapped.str();
}

std::string build_namespaced_snippet(const std::string& code, const std::string& sandbox) {
    const std::string code_hex = hex_encode(code);
    std::ostringstream wrapped;
    wrapped << build_namespace_preamble(sandbox)
            << "__idasql_code = bytes.fromhex('" << code_hex << "').decode('utf-8')\n"
            << "exec(__idasql_code, builtins.__idasql_namespaces__[__idasql_sandbox])\n"
            << "del __idasql_code\n"
            << "del __idasql_sandbox\n";
    return wrapped.str();
}

std::string build_namespaced_file_snippet(const std::string& path, const std::string& sandbox) {
    const std::string path_hex = hex_encode(path);
    std::ostringstream wrapped;
    wrapped << "__idasql_path = bytes.fromhex('" << path_hex << "').decode('utf-8')\n"
            << "with open(__idasql_path, 'r', encoding='utf-8') as __idasql_file:\n"
            << "    __idasql_code = __idasql_file.read()\n"
            << build_namespace_preamble(sandbox)
            << "exec(__idasql_code, builtins.__idasql_namespaces__[__idasql_sandbox])\n"
            << "del __idasql_path\n"
            << "del __idasql_code\n"
            << "del __idasql_sandbox\n";
    return wrapped.str();
}

ExecutionResult execute_snippet(const std::string& code, const std::string& sandbox) {
    ExecutionResult result;
    extlang_t* py = get_python_extlang();
    if (py == nullptr || py->eval_snippet == nullptr) {
        result.error = "Python interpreter not available";
        return result;
    }

    ScopedCapture capture;
    if (!capture.ok()) {
        result.error = capture.error();
        return result;
    }

    qstring errbuf;
    const bool ok = sandbox.empty()
                        ? py->eval_snippet(code.c_str(), &errbuf)
                        : py->eval_snippet(build_namespaced_snippet(code, sandbox).c_str(), &errbuf);

    result.output = capture.finish();
    result.success = ok;
    if (!ok) {
        result.error = errbuf.c_str();
    }
    return result;
}

ExecutionResult execute_file(const std::string& path, const std::string& sandbox) {
    ExecutionResult result;
    extlang_t* py = get_python_extlang();
    if (py == nullptr) {
        result.error = "Python interpreter not available";
        return result;
    }

    if (sandbox.empty()) {
        if (py->compile_file == nullptr) {
            result.error = "Python file execution is not available";
            return result;
        }
    } else if (py->eval_snippet == nullptr) {
        result.error = "Python snippet execution is not available";
        return result;
    }

    ScopedCapture capture;
    if (!capture.ok()) {
        result.error = capture.error();
        return result;
    }

    qstring errbuf;
    bool ok = false;
    if (sandbox.empty()) {
        ok = py->compile_file(path.c_str(), nullptr, &errbuf);
    } else {
        ok = py->eval_snippet(build_namespaced_file_snippet(path, sandbox).c_str(), &errbuf);
    }

    result.output = capture.finish();
    result.success = ok;
    if (!ok) {
        result.error = errbuf.c_str();
    }
    return result;
}

} // namespace idapython
} // namespace idasql
