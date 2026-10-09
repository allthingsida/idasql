// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * deep_link.cpp - IDA 9.4 ida:// deep links, natively (see deep_link.hpp).
 *
 * Credit: the out-of-process half of this file — discovering IDA's ida_ipc_<pid>
 * endpoints, the JSON commands they accept, matching a link to a running instance,
 * launching IDA and waiting for it, and registering a URL handler per OS — follows
 * the behaviour of Hex-Rays' ida-hcli (https://github.com/HexRaysSA/ida-hcli),
 * reimplemented here in C++ so idasql needs neither Python nor hcli. The link format
 * and parsing rules follow IDA 9.4 itself (its Copy Link output and open_ida_link).
 *
 *   ida-hcli is Copyright (c) 2025 Hex-Rays SA and is distributed under the MIT
 *   License:
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a copy of
 *   this software and associated documentation files (the "Software"), to deal in
 *   the Software without restriction, including without limitation the rights to
 *   use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 *   the Software, and to permit persons to whom the Software is furnished to do so,
 *   subject to the following conditions: The above copyright notice and this
 *   permission notice shall be included in all copies or substantial portions of
 *   the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
 *   EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 *   OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 *
 * Where this deliberately differs from hcli:
 *   - Windows discovery lists \\.\pipe\ instead of opening a pipe per process id, so
 *     finding instances never connects to anything;
 *   - every endpoint is checked to be served by the pid in its name;
 *   - Windows pipe I/O has timeouts;
 *   - several matching instances are an error that names them, not a silent pick;
 *   - after a launch, the wait is for the launched process's own endpoint.
 */

#include "deep_link.hpp"

#include <xsql/json.hpp>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <future>
#include <iostream>
#include <limits>
#include <mutex>
#include <sstream>
#include <thread>
#include <type_traits>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
extern char** environ;
#endif

namespace fs = std::filesystem;

namespace idasql {
namespace deep_link {

namespace {

using json = xsql::json;

// A field that holds a T, else nullopt. Unlike json::value() it never throws:
// value() calls get<T>() on a present key, which throws type_error 302 for a null
// or wrongly typed value -- and these objects come from another process (an IPC
// reply) or a hand-edited file (links.json).
template <typename T>
std::optional<T> field(const json& j, const char* key) {
    if (!j.is_object()) return std::nullopt;
    const auto it = j.find(key);
    if (it == j.end()) return std::nullopt;
    if constexpr (std::is_same_v<T, std::string>) {
        if (it->is_string()) return it->template get<std::string>();
    } else if constexpr (std::is_same_v<T, bool>) {
        if (it->is_boolean()) return it->template get<bool>();
    } else if constexpr (std::is_integral_v<T>) {
        if (it->is_number_unsigned()) {
            const uint64_t u = it->template get<uint64_t>();
            if (u <= static_cast<uint64_t>((std::numeric_limits<T>::max)())) return static_cast<T>(u);
        } else if (it->is_number_integer()) {
            const int64_t s = it->template get<int64_t>();
            if (s >= static_cast<int64_t>((std::numeric_limits<T>::min)()) &&
                s <= static_cast<int64_t>((std::numeric_limits<T>::max)()))
                return static_cast<T>(s);
        }
    }
    return std::nullopt;
}

template <typename T>
T field_or(const json& j, const char* key, T fallback) {
    return field<T>(j, key).value_or(std::move(fallback));
}

// ---------------------------------------------------------------------------
// Small string helpers
// ---------------------------------------------------------------------------

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool ends_with_ci(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() && iequals(s.substr(s.size() - suffix.size()), suffix);
}

std::string basename_of(std::string_view path) {
    const size_t pos = path.find_last_of("/\\");
    return std::string(pos == std::string_view::npos ? path : path.substr(pos + 1));
}

std::string strip_idb_extension(std::string name) {
    if (ends_with_ci(name, ".i64") || ends_with_ci(name, ".idb")) name.resize(name.size() - 4);
    return name;
}

// A decoded link field holding a C0 control byte or DEL: %00 would cut a path short
// at the OS boundary (stat, CreateProcessW), %0A would forge a handler-log line.
bool has_control_byte(std::string_view s) {
    return std::any_of(s.begin(), s.end(), [](unsigned char c) { return c < 0x20 || c == 0x7F; });
}

// Unicode bidirectional overrides and isolates (U+202A..U+202E, U+2066..U+2069):
// in a database path they can make the confirmation dialog show another name.
bool has_bidi_control(std::string_view s) {
    for (size_t i = 0; i + 2 < s.size(); ++i) {
        const auto b0 = static_cast<unsigned char>(s[i]);
        const auto b1 = static_cast<unsigned char>(s[i + 1]);
        const auto b2 = static_cast<unsigned char>(s[i + 2]);
        if (b0 != 0xE2) continue;
        if (b1 == 0x80 && b2 >= 0xAA && b2 <= 0xAE) return true;
        if (b1 == 0x81 && b2 >= 0xA6 && b2 <= 0xA9) return true;
    }
    return false;
}

// Base-0 unsigned parse, like QString::toULongLong(&ok, 0): 0x hex, leading-0 octal,
// else decimal. The whole string must be consumed.
std::optional<uint64_t> parse_number(const std::string& text) {
    if (text.empty()) return std::nullopt;
    for (char c : text) {
        if (std::isspace(static_cast<unsigned char>(c)) || c == '-' || c == '+') return std::nullopt;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long v = std::strtoull(text.c_str(), &end, 0);
    if (errno != 0 || end == text.c_str() || *end != '\0') return std::nullopt;
    return static_cast<uint64_t>(v);
}

constexpr uint64_t kBadAddr = ~uint64_t{0};

#ifdef _WIN32
std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string narrow(std::wstring_view s) {
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0,
                                      nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr,
                        nullptr);
    return out;
}

std::string env_var(const char* name) {
    const std::wstring wname = widen(name);
    const DWORD n = GetEnvironmentVariableW(wname.c_str(), nullptr, 0);
    if (n == 0) return {};
    std::wstring value(n, L'\0');
    const DWORD got = GetEnvironmentVariableW(wname.c_str(), value.data(), n);
    value.resize(got);
    return narrow(value);
}
#else
std::string env_var(const char* name) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string();
}
#endif

fs::path u8path(const std::string& s) {
#ifdef _WIN32
    return fs::path(widen(s));
#else
    return fs::path(s);
#endif
}

std::string path_string(const fs::path& p) {
#ifdef _WIN32
    return narrow(p.native());
#else
    return p.string();
#endif
}

// ---------------------------------------------------------------------------
// The ida:// resources and the views each one opens in IDA 9.4.
// ---------------------------------------------------------------------------

struct ResourceInfo {
    const char* name;
    const char* default_view;
    std::vector<std::string> views;
};

const std::vector<ResourceInfo>& resource_table() {
    static const std::vector<ResourceInfo> table = {
        {"functions", "functions", {"disasm", "graph", "hexdump", "pseudocode", "functions"}},
        {"addresses", "disasm", {"disasm", "hexdump"}},
        {"strings", "strings", {"disasm", "hexdump", "strings"}},
        {"segments", "segments", {"disasm", "hexdump", "segments"}},
        {"names", "names", {"disasm", "hexdump", "names"}},
        {"imports", "imports", {"disasm", "hexdump", "imports"}},
        {"exports", "exports", {"disasm", "hexdump", "exports"}},
        {"types", "types", {"types"}},
        {"bookmarks", "disasm", {"disasm", "graph", "hexdump", "pseudocode", "bookmarks"}},
    };
    return table;
}

const ResourceInfo* find_resource(std::string_view name) {
    for (const auto& r : resource_table()) {
        if (name == r.name) return &r;
    }
    return nullptr;
}

const char* const kAllViews[] = {"disasm",  "pseudocode", "hexdump", "graph",
                                 "functions", "segments", "names",   "imports",
                                 "exports", "strings",    "types",   "bookmarks"};

std::string join(const std::vector<std::string>& items, const char* sep) {
    std::string out;
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) out += sep;
        out += items[i];
    }
    return out;
}

std::string resource_list() {
    std::vector<std::string> names;
    for (const auto& r : resource_table()) names.emplace_back(r.name);
    return join(names, ", ");
}

// Checks shared by build() and parse(). Returns the resolved view or sets `error`.
std::string check_target(const LinkTarget& t, std::string& error) {
    const ResourceInfo* r = find_resource(t.resource);
    if (r == nullptr) {
        error = "Unknown resource: " + t.resource + " (supported: " + resource_list() + ")";
        return {};
    }
    std::string view = t.view.empty() ? std::string(r->default_view) : t.view;
    if (!is_view(view)) {
        std::vector<std::string> all(std::begin(kAllViews), std::end(kAllViews));
        error = "Unknown view type: " + view + " (supported: " + join(all, ", ") + ")";
        return {};
    }
    if (!view_allowed(t.resource, view)) {
        error = "View '" + view + "' is not compatible with entity type '" + t.resource +
                "'. Valid views: " + join(r->views, ", ");
        return {};
    }
    if (t.resource == "types") {
        if (t.name.empty()) {
            error = "Types require 'name' parameter";
            return {};
        }
        // Accept only names build() can hand to IDA, so parse() and build() agree.
        std::string encoded;
        if (!encode_type_name(t.name, encoded, error)) return {};
    } else {
        if (t.rva && t.ea) {
            error = "Parameters 'ea' and 'rva' are mutually exclusive";
            return {};
        }
        if (!t.rva && !t.ea) {
            error = "Missing 'ea' or 'rva' parameter";
            return {};
        }
        if ((t.rva && *t.rva == kBadAddr) || (t.ea && *t.ea == kBadAddr)) {
            error = "Invalid address parameter";
            return {};
        }
    }
    if (!t.source.empty() && t.idb_name.empty()) {
        error = "A link with a source must name the database (ida://<source>/<idb>/<resource>)";
        return {};
    }
    return view;
}

// ---------------------------------------------------------------------------
// IPC override seam
// ---------------------------------------------------------------------------

std::mutex g_override_mutex;
std::optional<IpcOptions> g_override;

}  // namespace

// ===========================================================================
// Link model
// ===========================================================================

const std::vector<std::string>& resources() {
    static const std::vector<std::string> names = [] {
        std::vector<std::string> v;
        for (const auto& r : resource_table()) v.emplace_back(r.name);
        return v;
    }();
    return names;
}

std::string default_view(std::string_view resource) {
    const ResourceInfo* r = find_resource(resource);
    return r ? std::string(r->default_view) : std::string();
}

const std::vector<std::string>& allowed_views(std::string_view resource) {
    static const std::vector<std::string> none;
    const ResourceInfo* r = find_resource(resource);
    return r ? r->views : none;
}

bool is_resource(std::string_view resource) { return find_resource(resource) != nullptr; }

bool is_view(std::string_view view) {
    for (const char* v : kAllViews) {
        if (view == v) return true;
    }
    return false;
}

bool view_allowed(std::string_view resource, std::string_view view) {
    for (const auto& v : allowed_views(resource)) {
        if (v == view) return true;
    }
    return false;
}

std::string percent_encode(std::string_view text) {
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(text.size() * 3);
    for (unsigned char c : text) {
        if (std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

bool encode_type_name(std::string_view name, std::string& out, std::string& error) {
    // IDA reads name= with QUrl's PrettyDecoded, which decodes ordinary escapes but
    // leaves the URL delimiters encoded: a link carrying "tagX%3A%3A%24A" is looked up
    // as that literal text and IDA answers "Type ... not found". Measured over IDA
    // 9.4's IPC for : $ ( ) ' (raw resolves, %XX does not). So delimiters travel
    // raw. '&' and '#' cannot (they end the value) and neither can '%' (its escape
    // is never decoded), so a name holding one of them has no working link.
    static const char hex[] = "0123456789ABCDEF";
    out.clear();
    for (unsigned char c : name) {
        if (std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~' ||
            std::strchr(":/?[]@!$'()*+,;=", c) != nullptr) {
            out.push_back(static_cast<char>(c));
        } else if (c == '&' || c == '#' || c == '%') {
            error = std::string("IDA cannot open a types link whose name contains '") + static_cast<char>(c) + "'";
            return false;
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return true;
}

std::optional<std::string> percent_decode(std::string_view text) {
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] != '%') {
            out.push_back(text[i]);
            continue;
        }
        if (i + 2 >= text.size()) return std::nullopt;
        const int hi = hexval(text[i + 1]);
        const int lo = hexval(text[i + 2]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
    }
    return out;
}

std::string format_hex(uint64_t value) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
    return buf;
}

BuildResult build(const LinkTarget& target) {
    BuildResult result;
    const std::string view = check_target(target, result.diagnostic);
    if (!result.diagnostic.empty()) return result;

    std::string uri = "ida://";
    uri += percent_encode(lower(target.source));
    uri += "/";
    if (!target.idb_name.empty()) uri += percent_encode(target.idb_name) + "/";
    uri += target.resource;
    uri += "?";
    if (target.resource == "types") {
        std::string value;
        if (!encode_type_name(target.name, value, result.diagnostic)) return result;
        uri += "name=" + value;
    } else if (target.rva) {
        uri += "rva=" + format_hex(*target.rva);
    } else {
        uri += "ea=" + format_hex(*target.ea);
    }
    uri += "&view=" + view;
    if (!target.idb_path.empty()) uri += "&idb_path=" + percent_encode(target.idb_path);
    result.valid = true;
    result.uri = std::move(uri);
    result.view = view;
    return result;
}

ParsedLink parse(std::string_view uri) {
    ParsedLink out;
    auto fail = [&](std::string why) {
        out.valid = false;
        out.diagnostic = std::move(why);
        return out;
    };

    const size_t sep = uri.find("://");
    if (sep == std::string_view::npos) return fail("Not an ida:// URI");
    const std::string scheme = lower(std::string(uri.substr(0, sep)));
    if (scheme != "ida") return fail("Unsupported scheme '" + scheme + "' (expected ida)");

    std::string_view rest = uri.substr(sep + 3);
    const size_t hash = rest.find('#');
    if (hash != std::string_view::npos) rest = rest.substr(0, hash);
    std::string_view query;
    const size_t q = rest.find('?');
    if (q != std::string_view::npos) {
        query = rest.substr(q + 1);
        rest = rest.substr(0, q);
    }
    std::string_view authority = rest;
    std::string_view path;
    const size_t slash = rest.find('/');
    if (slash != std::string_view::npos) {
        authority = rest.substr(0, slash);
        path = rest.substr(slash);
    }
    // user@host:port -> host (IDA uses QUrl::host()).
    const size_t at = authority.rfind('@');
    if (at != std::string_view::npos) authority = authority.substr(at + 1);
    const size_t colon = authority.find(':');
    if (colon != std::string_view::npos) authority = authority.substr(0, colon);
    const auto host = percent_decode(authority);
    if (!host) return fail("Malformed percent-encoding in the source");
    if (has_control_byte(*host)) return fail("Control characters are not allowed in the source");
    out.target.source = lower(*host);

    // Query: first value of each key wins, like QUrlQuery::queryItemValue.
    std::map<std::string, std::string> params;
    size_t pos = 0;
    while (pos <= query.size() && !query.empty()) {
        size_t amp = query.find('&', pos);
        if (amp == std::string_view::npos) amp = query.size();
        std::string_view item = query.substr(pos, amp - pos);
        if (!item.empty()) {
            const size_t eq = item.find('=');
            const std::string key(item.substr(0, eq));
            const std::string_view raw = eq == std::string_view::npos ? std::string_view() : item.substr(eq + 1);
            const auto value = percent_decode(raw);
            if (!value) return fail("Malformed percent-encoding in parameter '" + key + "'");
            if (has_control_byte(key) || has_control_byte(*value))
                return fail("Control characters are not allowed in parameter '" + key + "'");
            params.emplace(key, *value);
        }
        if (amp >= query.size()) break;
        pos = amp + 1;
    }

    // Knowledge Exchange links belong to hcli's download flow; recognise, never open.
    if ((out.target.source == "ke" && params.count("url")) ||
        path.find("/api/v1/buckets/") != std::string_view::npos) {
        out.is_ke = true;
        return fail("Knowledge Exchange links are not supported by idasql");
    }

    // Path: fully decoded, then split on '/', empty segments skipped (as IDA does).
    const auto decoded_path = percent_decode(path);
    if (!decoded_path) return fail("Malformed percent-encoding in the path");
    std::vector<std::string> segments;
    {
        std::string current;
        for (char c : *decoded_path) {
            if (c == '/') {
                if (!current.empty()) segments.push_back(current);
                current.clear();
            } else {
                current.push_back(c);
            }
        }
        if (!current.empty()) segments.push_back(current);
    }
    for (const auto& s : segments) {
        if (has_control_byte(s)) return fail("Control characters are not allowed in the path");
    }
    if (!out.target.source.empty()) {
        if (segments.size() != 2) {
            return fail("When source is specified, path must have exactly 2 segments "
                        "(/<idb>/<resource>), got " + std::to_string(segments.size()));
        }
    } else if (segments.size() != 1 && segments.size() != 2) {
        return fail("Invalid path: expected 1 or 2 segments, got " + std::to_string(segments.size()));
    }
    if (segments.size() == 2) {
        out.target.idb_name = segments[0];
        out.target.resource = segments[1];
    } else {
        out.target.resource = segments[0];
    }

    if (auto it = params.find("view"); it != params.end()) out.target.view = it->second;
    if (auto it = params.find("name"); it != params.end()) out.target.name = it->second;
    if (auto it = params.find("idb_path"); it != params.end()) out.target.idb_path = it->second;
    if (out.target.resource != "types") {
        if (auto it = params.find("rva"); it != params.end()) {
            out.target.rva = parse_number(it->second);
            if (!out.target.rva) return fail("Invalid rva parameter: " + it->second);
        }
        if (auto it = params.find("ea"); it != params.end()) {
            out.target.ea = parse_number(it->second);
            if (!out.target.ea) return fail("Invalid address parameter: " + it->second);
        }
    }

    std::string error;
    const std::string view = check_target(out.target, error);
    if (!error.empty()) return fail(error);
    out.target.view = view;
    out.valid = true;
    return out;
}

std::string to_ida_uri(const ParsedLink& link) {
    if (!link.valid) return {};
    LinkTarget t = link.target;
    t.idb_path.clear();
    const BuildResult b = build(t);
    return b.valid ? b.uri : std::string();
}

std::string screen_untrusted_uri(std::string_view uri) {
    if (uri.size() > 4096) return "link is longer than 4096 characters";
    for (unsigned char c : uri) {
        if (c < 0x20 || c == 0x7F) return "link contains control characters";
    }
    const std::string head = lower(std::string(uri.substr(0, std::min<size_t>(uri.size(), 6))));
    if (head != "ida://") return "only ida:// links are accepted";
    return {};
}

// ===========================================================================
// IPC
// ===========================================================================

namespace {
constexpr const char* kPipePrefix = "ida_ipc_";

// IDA's replies are well under 1 KiB; anything near this is not IDA.
constexpr size_t kMaxReplyBytes = size_t{1} << 20;

// A reply is complete once it parses. Only a chunk that brings a '}' can complete
// it, so the whole buffer is not re-parsed after every read.
bool json_complete(const std::string& text, std::string_view chunk) {
    return !text.empty() && chunk.find('}') != std::string_view::npos && json::accept(text);
}
}  // namespace

std::string Instance::idb_name() const { return idb_path.empty() ? std::string() : basename_of(idb_path); }

std::string endpoint_path(uint64_t pid, const IpcOptions& options) {
#ifdef _WIN32
    (void)options;
    return "\\\\.\\pipe\\" + std::string(kPipePrefix) + std::to_string(pid);
#else
    return (fs::path(options.socket_dir) / (std::string(kPipePrefix) + std::to_string(pid))).string();
#endif
}

namespace {
bool pid_wanted(uint64_t pid, const IpcOptions& options) {
    return options.only_pids.empty() ||
           std::find(options.only_pids.begin(), options.only_pids.end(), pid) != options.only_pids.end();
}

std::optional<uint64_t> pid_from_name(std::string_view name) {
    if (!starts_with(name, kPipePrefix)) return std::nullopt;
    const std::string digits(name.substr(std::strlen(kPipePrefix)));
    if (digits.empty() || !std::all_of(digits.begin(), digits.end(),
                                       [](unsigned char c) { return std::isdigit(c) != 0; }))
        return std::nullopt;
    return parse_number(digits);
}
}  // namespace

#ifdef _WIN32

std::vector<Endpoint> discover(const IpcOptions& options) {
    std::vector<Endpoint> out;
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(L"\\\\.\\pipe\\*", &data);
    if (find == INVALID_HANDLE_VALUE) return out;
    do {
        const std::string name = narrow(data.cFileName);
        const auto pid = pid_from_name(name);
        if (pid && pid_wanted(*pid, options)) out.push_back({*pid, endpoint_path(*pid, options)});
    } while (FindNextFileW(find, &data));
    FindClose(find);
    std::sort(out.begin(), out.end(), [](const Endpoint& a, const Endpoint& b) { return a.pid < b.pid; });
    return out;
}

namespace {
std::vector<BYTE> token_user_sid(HANDLE token) {
    DWORD len = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || len == 0) return {};
    std::vector<BYTE> buf(len);
    if (!GetTokenInformation(token, TokenUser, buf.data(), len, &len)) return {};
    const PSID sid = reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid;
    std::vector<BYTE> out(GetLengthSid(sid));
    if (!CopySid(static_cast<DWORD>(out.size()), out.data(), sid)) return {};
    return out;
}

// The pipe's server runs in this logon session as this user. The pid check alone
// would trust any process -- another user's, a service -- that names its own pipe
// ida_ipc_<its pid>. (POSIX checks the peer uid instead.)
bool served_by_same_user(HANDLE pipe, ULONG server_pid, std::string& why) {
    ULONG server_session = 0;
    DWORD my_session = 0;
    if (!GetNamedPipeServerSessionId(pipe, &server_session) ||
        !ProcessIdToSessionId(GetCurrentProcessId(), &my_session) || server_session != my_session) {
        why = "is served from another logon session";
        return false;
    }
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, server_pid);
    if (!proc) {
        why = "is served by a process whose user cannot be verified (elevated?)";
        return false;
    }
    HANDLE tok = nullptr;
    const BOOL opened = OpenProcessToken(proc, TOKEN_QUERY, &tok);
    CloseHandle(proc);
    if (!opened) {
        why = "is served by a process whose user cannot be verified (elevated?)";
        return false;
    }
    const auto theirs = token_user_sid(tok);
    CloseHandle(tok);
    const auto mine = token_user_sid(GetCurrentProcessToken());
    if (theirs.empty() || mine.empty() || !EqualSid(const_cast<BYTE*>(theirs.data()), const_cast<BYTE*>(mine.data()))) {
        why = "is served by another user";
        return false;
    }
    return true;
}

// Wait for an overlapped operation; cancels it on timeout.
bool finish_overlapped(HANDLE h, OVERLAPPED& ov, DWORD& transferred, DWORD timeout_ms, DWORD& err) {
    const DWORD wait = WaitForSingleObject(ov.hEvent, timeout_ms);
    if (wait != WAIT_OBJECT_0) {
        CancelIo(h);
        GetOverlappedResult(h, &ov, &transferred, TRUE);
        err = WAIT_TIMEOUT;
        return false;
    }
    if (!GetOverlappedResult(h, &ov, &transferred, FALSE)) {
        err = GetLastError();
        return false;
    }
    return true;
}
}  // namespace

std::optional<std::string> request(const Endpoint& endpoint, const std::string& json_request,
                                   std::string& error, const IpcOptions& options) {
    const std::wstring path = widen(endpoint.path);
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 2; ++attempt) {
        h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_PIPE_BUSY ||
            !WaitNamedPipeW(path.c_str(), static_cast<DWORD>(options.connect_timeout_ms)))
            break;
    }
    if (h == INVALID_HANDLE_VALUE) {
        error = "cannot connect to " + endpoint.path + " (error " + std::to_string(GetLastError()) + ")";
        return std::nullopt;
    }
    struct Closer {
        HANDLE h;
        ~Closer() { CloseHandle(h); }
    } closer{h};

    ULONG server_pid = 0;
    if (!GetNamedPipeServerProcessId(h, &server_pid) || server_pid != endpoint.pid) {
        error = endpoint.path + " is not served by process " + std::to_string(endpoint.pid);
        return std::nullopt;
    }
    if (std::string why; !served_by_same_user(h, server_pid, why)) {
        error = endpoint.path + " " + why;
        return std::nullopt;
    }

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    struct EventCloser {
        HANDLE e;
        ~EventCloser() { CloseHandle(e); }
    } event_closer{ov.hEvent};
    const DWORD timeout = static_cast<DWORD>(options.io_timeout_ms);

    // One write: IDA parses the first read it gets and replies once.
    DWORD transferred = 0, err = 0;
    if (!WriteFile(h, json_request.data(), static_cast<DWORD>(json_request.size()), nullptr, &ov) &&
        GetLastError() != ERROR_IO_PENDING) {
        error = "write to " + endpoint.path + " failed (error " + std::to_string(GetLastError()) + ")";
        return std::nullopt;
    }
    if (!finish_overlapped(h, ov, transferred, timeout, err) || transferred != json_request.size()) {
        error = err == WAIT_TIMEOUT ? "timed out writing to " + endpoint.path
                                    : "write to " + endpoint.path + " failed";
        return std::nullopt;
    }

    std::string response;
    char buffer[4096];
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            error = "timed out waiting for " + endpoint.path;
            return std::nullopt;
        }
        const DWORD left = static_cast<DWORD>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        ResetEvent(ov.hEvent);
        if (!ReadFile(h, buffer, sizeof(buffer), nullptr, &ov) && GetLastError() != ERROR_IO_PENDING) {
            err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) break;
            if (err != ERROR_MORE_DATA) {
                error = "read from " + endpoint.path + " failed (error " + std::to_string(err) + ")";
                return std::nullopt;
            }
        }
        transferred = 0;
        if (!finish_overlapped(h, ov, transferred, left, err)) {
            if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) break;
            if (err != ERROR_MORE_DATA) {
                error = err == WAIT_TIMEOUT ? "timed out waiting for " + endpoint.path
                                            : "read from " + endpoint.path + " failed";
                return std::nullopt;
            }
        }
        if (transferred == 0) break;
        if (response.size() + transferred > kMaxReplyBytes) {
            error = "reply from " + endpoint.path + " exceeds 1 MiB";
            return std::nullopt;
        }
        response.append(buffer, transferred);
        if (json_complete(response, std::string_view(buffer, transferred))) break;
    }
    if (response.empty()) {
        error = "no reply from " + endpoint.path;
        return std::nullopt;
    }
    return response;
}

#else  // POSIX

std::vector<Endpoint> discover(const IpcOptions& options) {
    std::vector<Endpoint> out;
    std::error_code ec;
    for (fs::directory_iterator it(options.socket_dir, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string name = it->path().filename().string();
        const auto pid = pid_from_name(name);
        if (!pid || !pid_wanted(*pid, options)) continue;
        // A socket whose pid this process cannot see is skipped, never removed: the
        // pid may live in another PID namespace (a container sharing /tmp), and
        // discovery must not change the filesystem.
        if (::kill(static_cast<pid_t>(*pid), 0) == 0 || errno == EPERM) {
            out.push_back({*pid, it->path().string()});
        }
    }
    std::sort(out.begin(), out.end(), [](const Endpoint& a, const Endpoint& b) { return a.pid < b.pid; });
    return out;
}

namespace {
bool wait_fd(int fd, short events, int timeout_ms) {
    pollfd p{fd, events, 0};
    for (;;) {
        const int r = ::poll(&p, 1, timeout_ms);
        if (r < 0 && errno == EINTR) continue;
        return r > 0;
    }
}

bool peer_is_same_user(int fd) {
#if defined(__APPLE__)
    uid_t uid = 0;
    gid_t gid = 0;
    if (getpeereid(fd, &uid, &gid) != 0) return false;
    return uid == ::getuid();
#elif defined(SO_PEERCRED)
    ucred cred{};
    socklen_t len = sizeof(cred);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) return false;
    return cred.uid == ::getuid();
#else
    (void)fd;
    return true;
#endif
}
}  // namespace

std::optional<std::string> request(const Endpoint& endpoint, const std::string& json_request,
                                   std::string& error, const IpcOptions& options) {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        error = "socket() failed";
        return std::nullopt;
    }
    struct Closer {
        int fd;
        ~Closer() { ::close(fd); }
    } closer{fd};

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (endpoint.path.size() >= sizeof(addr.sun_path)) {
        error = "socket path too long: " + endpoint.path;
        return std::nullopt;
    }
    std::memcpy(addr.sun_path, endpoint.path.c_str(), endpoint.path.size() + 1);

    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        if (errno != EINPROGRESS && errno != EAGAIN) {
            error = "cannot connect to " + endpoint.path + ": " + std::strerror(errno);
            return std::nullopt;
        }
        if (!wait_fd(fd, POLLOUT, options.connect_timeout_ms)) {
            error = "timed out connecting to " + endpoint.path;
            return std::nullopt;
        }
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error != 0) {
            error = "cannot connect to " + endpoint.path + ": " + std::strerror(so_error);
            return std::nullopt;
        }
    }
    if (!peer_is_same_user(fd)) {
        error = endpoint.path + " is served by another user";
        return std::nullopt;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(options.io_timeout_ms);
    auto left_ms = [&]() {
        const auto d = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        return static_cast<int>(std::max<long long>(d, 0));
    };

    size_t sent = 0;
    while (sent < json_request.size()) {
        if (!wait_fd(fd, POLLOUT, left_ms())) {
            error = "timed out writing to " + endpoint.path;
            return std::nullopt;
        }
        const ssize_t n = ::send(fd, json_request.data() + sent, json_request.size() - sent,
#ifdef MSG_NOSIGNAL
                                 MSG_NOSIGNAL
#else
                                 0
#endif
        );
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            error = "write to " + endpoint.path + " failed";
            return std::nullopt;
        }
        sent += static_cast<size_t>(n);
    }

    std::string response;
    char buffer[4096];
    for (;;) {
        if (!wait_fd(fd, POLLIN, left_ms())) {
            if (!response.empty() && json::accept(response)) break;
            error = "timed out waiting for " + endpoint.path;
            return std::nullopt;
        }
        const ssize_t n = ::recv(fd, buffer, sizeof(buffer), 0);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (n <= 0) break;
        if (response.size() + static_cast<size_t>(n) > kMaxReplyBytes) {
            error = "reply from " + endpoint.path + " exceeds 1 MiB";
            return std::nullopt;
        }
        response.append(buffer, static_cast<size_t>(n));
        if (json_complete(response, std::string_view(buffer, static_cast<size_t>(n)))) break;
    }
    if (response.empty()) {
        error = "no reply from " + endpoint.path;
        return std::nullopt;
    }
    return response;
}

#endif

namespace {
std::optional<json> command(const Endpoint& endpoint, const json& req, std::string& error,
                            const IpcOptions& options) {
    const auto reply = request(endpoint, req.dump(), error, options);
    if (!reply) return std::nullopt;
    json parsed = json::parse(*reply, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) {
        error = "malformed reply from " + endpoint.path;
        return std::nullopt;
    }
    return parsed;
}

std::string status_of(const json& j) { return field_or<std::string>(j, "status", ""); }
std::string message_of(const json& j) { return field_or<std::string>(j, "message", "Unknown error"); }

Instance query_instance(const Endpoint& ep, const IpcOptions& options) {
    Instance inst;
    inst.pid = ep.pid;
    inst.endpoint = ep.path;
    std::string error;
    if (auto reply = command(ep, json{{"cmd", "get_info"}}, error, options);
        reply && status_of(*reply) == "ok") {
        inst.responsive = true;
        inst.idb_path = field_or<std::string>(*reply, "idb_path", "");
        inst.version = field_or<std::string>(*reply, "version", "");
    }
    return inst;
}
}  // namespace

std::vector<Instance> list_instances(const IpcOptions& options) {
    // Every endpoint is asked at once: an instance whose UI thread is busy costs one
    // timeout, not one per instance. discover() returns them ordered by pid.
    std::vector<std::future<Instance>> pending;
    for (const auto& ep : discover(options))
        pending.push_back(std::async(std::launch::async, query_instance, ep, options));
    std::vector<Instance> out;
    out.reserve(pending.size());
    for (auto& f : pending) out.push_back(f.get());
    return out;
}

bool open_in(const Endpoint& endpoint, const std::string& ida_uri, std::string& message,
             const IpcOptions& options) {
    std::string error;
    auto reply = command(endpoint, json{{"cmd", "open_ida_link"}, {"uri", ida_uri}}, error, options);
    if (!reply) {
        message = error;
        return false;
    }
    if (status_of(*reply) == "ok") {
        message = "OK";
        return true;
    }
    message = message_of(*reply);
    return false;
}

std::optional<bool> analysis_complete(const Endpoint& endpoint, std::string& error,
                                      const IpcOptions& options) {
    auto reply = command(endpoint, json{{"cmd", "is_analysis_complete"}}, error, options);
    if (!reply) return std::nullopt;
    if (status_of(*reply) != "ok") {
        error = message_of(*reply);
        return std::nullopt;
    }
    const auto done = field<bool>(*reply, "analysis_complete");
    if (!done) {
        error = "malformed is_analysis_complete reply from " + endpoint.path;
        return std::nullopt;
    }
    return *done;
}

// ===========================================================================
// Selection
// ===========================================================================

bool same_path(std::string_view a, std::string_view b) {
    auto norm = [](std::string_view p) {
        std::string s(p);
        std::replace(s.begin(), s.end(), '\\', '/');
        while (s.size() > 1 && s.back() == '/') s.pop_back();
#ifdef _WIN32
        s = lower(s);
#endif
        return s;
    };
    return !a.empty() && norm(a) == norm(b);
}

bool same_database(std::string_view a, std::string_view b) {
    if (a.empty() || b.empty()) return false;
    if (same_path(a, b)) return true;
    std::error_code ec_a, ec_b;
    const fs::path ca = fs::weakly_canonical(u8path(std::string(a)), ec_a);
    const fs::path cb = fs::weakly_canonical(u8path(std::string(b)), ec_b);
    if (ec_a || ec_b) return false;
#if defined(_WIN32) || defined(__APPLE__)
    // Case-insensitive file systems (the default on both).
    auto key = [](const fs::path& p) { return lower(path_string(p)); };
#else
    auto key = [](const fs::path& p) { return path_string(p); };
#endif
    if (key(ca) == key(cb)) return true;
    // IDA upgrades a legacy x.idb to x.i64 next to it.
    const std::string name_a = path_string(ca.filename()), name_b = path_string(cb.filename());
    const bool a_idb = ends_with_ci(name_a, ".i64") || ends_with_ci(name_a, ".idb");
    const bool b_idb = ends_with_ci(name_b, ".i64") || ends_with_ci(name_b, ".idb");
    return a_idb && b_idb && key(ca.parent_path()) == key(cb.parent_path()) &&
           iequals(strip_idb_extension(name_a), strip_idb_extension(name_b));
}

Selection select_instance(const std::vector<Instance>& instances, const LinkTarget& target,
                          std::optional<uint64_t> pid, bool allow_name_fallback) {
    Selection sel;
    std::vector<Instance> with_db;
    for (const auto& i : instances) {
        if (i.responsive && !i.idb_path.empty()) with_db.push_back(i);
    }
    if (pid) {
        for (const auto& i : instances) {
            if (i.pid == *pid) {
                if (!i.responsive) {
                    sel.error = "IDA process " + std::to_string(*pid) + " does not answer";
                } else {
                    sel.chosen = i;
                }
                return sel;
            }
        }
        sel.error = "no IDA 9.4 instance with process id " + std::to_string(*pid);
        return sel;
    }

    std::vector<Instance> matches;
    if (!target.idb_path.empty()) {
        for (const auto& i : with_db) {
            if (same_path(i.idb_path, target.idb_path)) matches.push_back(i);
        }
    }
    if (matches.empty() && !target.idb_name.empty() &&
        (allow_name_fallback || target.idb_path.empty())) {
        // No instance has that exact file (or the link names none): a copy of the
        // database opened elsewhere still counts, by its basename.
        const std::string want = lower(strip_idb_extension(target.idb_name));
        for (const auto& i : with_db) {
            if (lower(strip_idb_extension(i.idb_name())) == want) matches.push_back(i);
        }
        sel.by_name = !target.idb_path.empty() && !matches.empty();
    } else if (target.idb_path.empty() && target.idb_name.empty()) {
        matches = with_db;
        if (matches.empty()) {
            sel.error = "no running IDA 9.4 instance has a database open";
            return sel;
        }
    }

    if (matches.size() == 1) {
        sel.chosen = matches.front();
    } else if (matches.empty()) {
        const std::string what = !target.idb_path.empty() ? target.idb_path : target.idb_name;
        sel.error = "no running IDA 9.4 instance has " + what + " open";
    } else {
        sel.candidates = matches;
        sel.error = target.idb_name.empty() && target.idb_path.empty()
                        ? "several IDA instances are running; the link names no database"
                        : "several IDA instances have a matching database open";
    }
    return sel;
}

SessionChoice choose_from_session(const std::vector<Instance>& others, const LinkTarget& target,
                                  std::string_view current_idb_path, bool allow_name_fallback) {
    SessionChoice choice;
    if (target.idb_path.empty() && target.idb_name.empty()) {
        choice.here = true;
        return choice;
    }
    if (!target.idb_path.empty() && same_path(target.idb_path, current_idb_path)) {
        choice.here = true;
        return choice;
    }
    if (!target.idb_path.empty()) {
        std::vector<Instance> exact;
        for (const auto& i : others) {
            if (i.responsive && same_path(i.idb_path, target.idb_path)) exact.push_back(i);
        }
        if (exact.size() == 1) {
            choice.other.chosen = exact.front();
            return choice;
        }
        if (exact.size() > 1) {
            choice.other.candidates = exact;
            choice.other.error = "several IDA instances have a matching database open";
            return choice;
        }
    }
    if (!target.idb_name.empty() && !current_idb_path.empty() &&
        iequals(strip_idb_extension(target.idb_name),
                strip_idb_extension(basename_of(current_idb_path)))) {
        choice.here = true;
        return choice;
    }
    choice.other = select_instance(others, target, std::nullopt, allow_name_fallback);
    return choice;
}

// ===========================================================================
// Config
// ===========================================================================

fs::path default_config_path() {
#ifdef _WIN32
    std::string base = env_var("APPDATA");
    if (base.empty()) base = env_var("USERPROFILE");
    return u8path(base) / "idasql" / "links.json";
#elif defined(__APPLE__)
    return fs::path(env_var("HOME")) / "Library" / "Application Support" / "idasql" / "links.json";
#else
    std::string base = env_var("XDG_CONFIG_HOME");
    if (base.empty()) base = env_var("HOME") + "/.config";
    return fs::path(base) / "idasql" / "links.json";
#endif
}

Config load_config(const fs::path& path, std::string* error) {
    Config cfg;
    std::ifstream in(path, std::ios::binary);
    if (!in) return cfg;  // no file = defaults
    std::stringstream ss;
    ss << in.rdbuf();
    json j = json::parse(ss.str(), nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        if (error) *error = path_string(path) + " is not a JSON object; using defaults";
        return cfg;
    }
    if (j.contains("sources") && j["sources"].is_object()) {
        for (auto it = j["sources"].begin(); it != j["sources"].end(); ++it) {
            if (it.value().is_string()) cfg.sources[it.key()] = it.value().get<std::string>();
        }
    }
    const bool bad_sources = j.contains("sources") && !j["sources"].is_object();
    // A hand-edited file may hold any JSON type: a wrong one is reported and the
    // default kept, never thrown.
    auto warn = [&](const std::string& w) {
        if (error) *error += (error->empty() ? "" : "\n") + path_string(path) + ": " + w;
    };
    cfg.ida = field_or<std::string>(j, "ida", "");
    if (j.contains("ida") && !field<std::string>(j, "ida")) warn("'ida' must be a string; ignored");
    if (j.contains("ida_args")) {
        if (!j["ida_args"].is_array()) warn("'ida_args' must be an array of strings; ignored");
        else {
            for (const auto& a : j["ida_args"]) {
                if (a.is_string()) cfg.ida_args.push_back(a.get<std::string>());
                else warn("'ida_args' holds a non-string; ignored");
            }
        }
    }
    if (j.contains("launch_timeout")) {
        const auto t = field<int>(j, "launch_timeout");
        if (t && *t >= 1 && *t <= 3600) {
            cfg.launch_timeout_s = *t;
        } else {
            warn("'launch_timeout' must be an integer 1..3600; using " + std::to_string(cfg.launch_timeout_s));
        }
    }
    if (bad_sources) warn("'sources' must be an object of name -> directory; ignored");
    if (const auto w = field<bool>(j, "wait_analysis")) {
        cfg.wait_analysis = *w;
    } else if (j.contains("wait_analysis")) {
        warn("'wait_analysis' must be true or false; ignored");
    }
    return cfg;
}

bool save_config(const fs::path& path, const Config& cfg, std::string& error) {
    json j = json::object();
    j["sources"] = json::object();
    for (const auto& [name, dir] : cfg.sources) j["sources"][name] = dir;
    j["ida"] = cfg.ida;
    j["ida_args"] = cfg.ida_args;
    j["launch_timeout"] = cfg.launch_timeout_s;
    j["wait_analysis"] = cfg.wait_analysis;
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "cannot write " + path_string(path);
        return false;
    }
    out << j.dump(2) << "\n";
    return static_cast<bool>(out);
}

bool valid_source_name(std::string_view name) {
    if (name.empty() || name == "localhost") return false;
    auto ok = [](unsigned char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); };
    if (!ok(static_cast<unsigned char>(name[0]))) return false;
    return std::all_of(name.begin(), name.end(),
                       [&](unsigned char c) { return ok(c) || c == '-'; });
}

// ===========================================================================
// Launch
// ===========================================================================

fs::path self_executable() {
#ifdef _WIN32
    std::wstring buf(32768, L'\0');
    const DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    buf.resize(n);
    return fs::path(buf);
#elif defined(__APPLE__)
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    std::string buf(size, '\0');
    if (_NSGetExecutablePath(buf.data(), &size) != 0) return {};
    buf.resize(std::strlen(buf.c_str()));
    std::error_code ec;
    auto p = fs::weakly_canonical(fs::path(buf), ec);
    return ec ? fs::path(buf) : p;
#else
    std::error_code ec;
    return fs::read_symlink("/proc/self/exe", ec);
#endif
}

uint64_t current_pid() {
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return static_cast<uint64_t>(::getpid());
#endif
}

namespace {
#ifdef _WIN32
constexpr const char* kIdaExe = "ida.exe";
#else
constexpr const char* kIdaExe = "ida";
#endif

bool is_file(const fs::path& p) {
    std::error_code ec;
    return fs::is_regular_file(p, ec);
}

bool is_remote_path(std::string_view p) {
    return starts_with(p, "\\\\") || starts_with(p, "//") || p.find("://") != std::string_view::npos;
}

bool path_within(const fs::path& child, const fs::path& dir) {
    std::error_code ec;
    const fs::path c = fs::weakly_canonical(child, ec);
    if (ec) return false;
    const fs::path d = fs::weakly_canonical(dir, ec);
    if (ec) return false;
    auto ci = c.begin();
    for (auto di = d.begin(); di != d.end(); ++di, ++ci) {
        if (di->empty()) continue;
        if (ci == c.end()) return false;
#ifdef _WIN32
        if (!iequals(path_string(*ci), path_string(*di))) return false;
#else
        if (*ci != *di) return false;
#endif
    }
    return true;
}
}  // namespace

std::optional<fs::path> resolve_ida(const Config& config, const fs::path& self, std::string& error) {
    std::vector<fs::path> candidates;
    if (!config.ida.empty()) {
        candidates.push_back(u8path(config.ida));
    } else {
        const std::string idadir = env_var("IDADIR");
        if (!idadir.empty()) candidates.push_back(u8path(idadir) / kIdaExe);
        if (!self.empty()) candidates.push_back(self.parent_path() / kIdaExe);
    }
    for (const auto& c : candidates) {
        if (is_file(c)) return c;
    }
    error = "cannot find the IDA executable (tried";
    for (const auto& c : candidates) error += " " + path_string(c);
    error += "); set it with `idasql link config ida <path>`";
    return std::nullopt;
}

IdbResolution resolve_idb(const LinkTarget& target, const Config& config) {
    IdbResolution res;
    // parse() already refuses these; resolve_idb is also reached with targets
    // built in code, and must never hand such a name to the file system or IDA.
    if (has_control_byte(target.idb_path) || has_control_byte(target.idb_name)) {
        res.error = "database path contains control characters";
        return res;
    }
    if (has_bidi_control(target.idb_path) || has_bidi_control(target.idb_name)) {
        res.error = "database path contains Unicode direction controls";
        return res;
    }
    if (!target.idb_path.empty()) {
        if (is_remote_path(target.idb_path)) {
            res.error = "refusing a remote database path: " + target.idb_path;
            return res;
        }
        const fs::path p = u8path(target.idb_path);
        if (!p.is_absolute()) {
            res.error = "database path is not absolute: " + target.idb_path;
            return res;
        }
        if (!ends_with_ci(target.idb_path, ".i64") && !ends_with_ci(target.idb_path, ".idb")) {
            res.error = "not an IDA database (.i64/.idb): " + target.idb_path;
            return res;
        }
        if (is_file(p)) {
            res.path = p;
            for (const auto& [name, dir] : config.sources) {
                if (path_within(p, u8path(dir))) res.under_source = true;
            }
            return res;
        }
        // Fall through to the sources: the file may have moved.
    }
    if (target.idb_name.empty()) {
        res.error = "the link names no database, so there is nothing to launch";
        return res;
    }
    if (!ends_with_ci(target.idb_name, ".i64") && !ends_with_ci(target.idb_name, ".idb")) {
        res.error = "not an IDA database (.i64/.idb): " + target.idb_name;
        return res;
    }
    std::vector<std::pair<std::string, std::string>> roots;
    if (!target.source.empty() && target.source != "localhost") {
        auto it = config.sources.find(target.source);
        if (it == config.sources.end()) {
            res.error = "unknown source '" + target.source + "' (add it with `idasql link source add`)";
            return res;
        }
        roots.emplace_back(*it);
    } else {
        roots.assign(config.sources.begin(), config.sources.end());
    }
    // Every match, never the first one the directory order happens to give; bounded
    // so a click never walks a whole disk.
    constexpr int kMaxDepth = 16;
    constexpr size_t kMaxEntries = 200000;
    std::vector<fs::path> found;
    for (const auto& [name, dir] : roots) {
        std::error_code ec;
        size_t entries = 0;
        for (fs::recursive_directory_iterator it(u8path(dir), fs::directory_options::skip_permission_denied, ec), end;
             !ec && it != end; it.increment(ec)) {
            if (++entries > kMaxEntries) {
                res.error = "source " + name + " is too large to search (more than " +
                            std::to_string(kMaxEntries) + " entries)";
                return res;
            }
            if (it.depth() >= kMaxDepth) it.disable_recursion_pending();
            // A separate error code: one dangling link must not end the whole walk.
            std::error_code entry_ec;
            if (!it->is_regular_file(entry_ec)) continue;
            const std::string file = path_string(it->path().filename());
#ifdef _WIN32
            const bool same = iequals(file, target.idb_name);
#else
            const bool same = file == target.idb_name;
#endif
            if (same) found.push_back(it->path());
        }
    }
    if (found.size() == 1) {
        res.path = found.front();
        res.under_source = true;
        return res;
    }
    if (found.size() > 1) {
        res.error = "database " + target.idb_name + " was found more than once:";
        for (const auto& p : found) res.error += "\n  " + path_string(p);
        return res;
    }
    res.error = "database " + target.idb_name + " was not found" +
                (roots.empty() ? std::string(" (no sources are configured)") : std::string(" in any source"));
    return res;
}

#ifdef _WIN32
namespace {
// Quote one argument by the CommandLineToArgvW rules.
std::wstring quote_arg(const std::wstring& arg) {
    if (!arg.empty() && arg.find_first_of(L" \t\"") == std::wstring::npos) return arg;
    std::wstring out = L"\"";
    size_t backslashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') {
            ++backslashes;
        } else if (c == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
            backslashes = 0;
        } else {
            out.append(backslashes, L'\\');
            out.push_back(c);
            backslashes = 0;
        }
    }
    out.append(backslashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}
}  // namespace
#else
namespace {
std::optional<pid_t> posix_spawn_detached(const std::vector<std::string>& argv, std::string& error) {
    std::vector<char*> args;
    for (const auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
    args.push_back(nullptr);
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
#ifdef POSIX_SPAWN_SETSID
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSID);
#endif
    pid_t pid = 0;
    const int rc = ::posix_spawnp(&pid, args[0], nullptr, &attr, args.data(), environ);
    posix_spawnattr_destroy(&attr);
    if (rc != 0) {
        error = "cannot start " + argv[0] + ": " + std::strerror(rc);
        return std::nullopt;
    }
    return pid;
}
}  // namespace
#endif

std::optional<uint64_t> spawn_ida(const fs::path& ida, const std::vector<std::string>& extra_args,
                                  const fs::path& idb, std::string& error) {
    // An argument with an embedded NUL would reach IDA cut short (argv and
    // CreateProcessW both end a string there).
    auto has_nul = [](const auto& s) { return std::find(s.begin(), s.end(), 0) != s.end(); };
    if (has_nul(ida.native()) || has_nul(idb.native()) ||
        std::any_of(extra_args.begin(), extra_args.end(), has_nul)) {
        error = "refusing to start IDA: an argument contains a NUL byte";
        return std::nullopt;
    }
#ifdef _WIN32
    std::wstring cmd = quote_arg(ida.native());
    for (const auto& a : extra_args) cmd += L" " + quote_arg(widen(a));
    cmd += L" " + quote_arg(idb.native());
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    const std::wstring cwd = idb.parent_path().native();
    if (!CreateProcessW(ida.native().c_str(), cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NEW_PROCESS_GROUP, nullptr, cwd.empty() ? nullptr : cwd.c_str(), &si, &pi)) {
        error = "cannot start " + path_string(ida) + " (error " + std::to_string(GetLastError()) + ")";
        return std::nullopt;
    }
    const uint64_t pid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return pid;
#else
#if defined(__APPLE__)
    // A bundle binary (X.app/Contents/MacOS/ida) is started through Launch Services so
    // it gets a proper application activation; that path does not report a pid.
    const std::string s = ida.string();
    const size_t app = s.find(".app/Contents/MacOS/");
    if (app != std::string::npos) {
        std::vector<std::string> argv = {"/usr/bin/open", "-n", "-a", s.substr(0, app + 4), "--args"};
        argv.insert(argv.end(), extra_args.begin(), extra_args.end());
        argv.push_back(idb.string());
        if (!posix_spawn_detached(argv, error)) return std::nullopt;
        return uint64_t{0};
    }
#endif
    std::vector<std::string> argv = {ida.string()};
    argv.insert(argv.end(), extra_args.begin(), extra_args.end());
    argv.push_back(idb.string());
    const auto pid = posix_spawn_detached(argv, error);
    if (!pid) return std::nullopt;
    return static_cast<uint64_t>(*pid);
#endif
}

// ===========================================================================
// OS handler registration
// ===========================================================================

const char* owner_name(HandlerOwner owner) {
    switch (owner) {
        case HandlerOwner::none: return "none";
        case HandlerOwner::idasql: return "idasql";
        case HandlerOwner::hcli: return "hcli";
        case HandlerOwner::other: return "other";
    }
    return "other";
}

namespace {
#ifdef _WIN32
// The registered handler command is read and written only on Windows (registry);
// macOS registers an app bundle and Linux a .desktop entry instead.
HandlerOwner classify_command(const std::string& command) {
    if (command.empty()) return HandlerOwner::none;
    const std::string c = lower(command);
    if (c.find("idasql") != std::string::npos && c.find("link open") != std::string::npos)
        return HandlerOwner::idasql;
    if (c.find("hcli") != std::string::npos) return HandlerOwner::hcli;
    return HandlerOwner::other;
}

std::string handler_command_line(const fs::path& exe) {
    // No `cmd /c` (it would mangle %XX escapes) and `--` so a crafted link can never
    // be read as an option.
    return "\"" + path_string(exe) + "\" link open --from-handler -- \"%1\"";
}
#endif

#ifndef _WIN32
int run_default(const std::vector<std::string>& argv) {
    std::string error;
    std::vector<char*> args;
    for (const auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
    args.push_back(nullptr);
    pid_t pid = 0;
    if (::posix_spawnp(&pid, args[0], nullptr, nullptr, args.data(), environ) != 0) return 127;
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

fs::path home_of(const RegistrationEnv& env) {
    return env.home.empty() ? fs::path(env_var("HOME")) : env.home;
}
#endif

#if !defined(_WIN32) && !defined(__APPLE__)
fs::path desktop_file(const RegistrationEnv& env) {
    return home_of(env) / ".local" / "share" / "applications" / "idasql-ida-handler.desktop";
}

// Our .desktop file remembers the handler it replaced, so unregister can restore it.
constexpr const char* kPreviousKey = "X-Idasql-Previous-Handler=";

std::string saved_previous(const RegistrationEnv& env) {
    std::ifstream in(desktop_file(env));
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind(kPreviousKey, 0) == 0) return line.substr(std::string(kPreviousKey).size());
    }
    return {};
}

// What xdg-mime recorded as the default handler for x-scheme-handler/ida.
std::string mimeapps_default(const RegistrationEnv& env) {
    const std::string key = "x-scheme-handler/ida=";
    for (const fs::path& file : {home_of(env) / ".config" / "mimeapps.list",
                                 home_of(env) / ".local" / "share" / "applications" / "mimeapps.list"}) {
        std::ifstream in(file);
        std::string line;
        bool in_defaults = false;
        while (std::getline(in, line)) {
            if (!line.empty() && line[0] == '[') {
                in_defaults = line.rfind("[Default Applications]", 0) == 0;
                continue;
            }
            if (in_defaults && line.rfind(key, 0) == 0) {
                std::string value = line.substr(key.size());
                const size_t semi = value.find(';');
                return semi == std::string::npos ? value : value.substr(0, semi);
            }
        }
    }
    return {};
}
#endif

#if defined(__APPLE__)
fs::path app_bundle(const RegistrationEnv& env) { return home_of(env) / "Applications" / "IDASQL Link Handler.app"; }

fs::path hcli_bundle(const RegistrationEnv& env) { return home_of(env) / "Applications" / "HCLIHandler.app"; }

const char* kLsregister =
    "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/"
    "Versions/A/Support/lsregister";
#endif
}  // namespace

#ifdef _WIN32
namespace {
bool reg_set(HKEY root, const std::wstring& subkey, const wchar_t* name, const std::wstring& value) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(root, subkey.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return false;
    const LONG rc = RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                                   static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

std::string reg_get(HKEY root, const std::wstring& subkey, const wchar_t* name = nullptr) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return {};
    DWORD type = 0, size = 0;
    std::string out;
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &size) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ) && size > 0) {
        std::wstring value(size / sizeof(wchar_t), L'\0');
        if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(value.data()), &size) ==
            ERROR_SUCCESS) {
            value.resize(std::wcslen(value.c_str()));
            out = narrow(value);
        }
    }
    RegCloseKey(key);
    return out;
}

// Our ida key remembers the handler it replaced (its HKCU command and icon), so
// unregister can put it back. A per-machine handler needs no copy: it applies again
// by itself once our per-user key is gone.
constexpr const wchar_t* kPreviousCommand = L"IdasqlPreviousCommand";
constexpr const wchar_t* kPreviousIcon = L"IdasqlPreviousIcon";

std::wstring ida_key(const RegistrationEnv& env) { return widen(env.windows_classes_key + "\\ida"); }
}  // namespace
#endif

HandlerStatus handler_status(const RegistrationEnv& env) {
    HandlerStatus st;
#ifdef _WIN32
    const std::wstring sub = ida_key(env) + L"\\shell\\open\\command";
    st.command = reg_get(HKEY_CURRENT_USER, sub);
    // A per-machine registration applies when the user has none of their own.
    if (st.command.empty() && env.windows_classes_key == "Software\\Classes")
        st.command = reg_get(HKEY_LOCAL_MACHINE, sub);
    st.owner = classify_command(st.command);
    if (st.owner == HandlerOwner::idasql) st.previous = reg_get(HKEY_CURRENT_USER, ida_key(env), kPreviousCommand);
#elif defined(__APPLE__)
    if (fs::exists(app_bundle(env))) {
        st.owner = HandlerOwner::idasql;
        st.command = app_bundle(env).string();
        if (fs::exists(hcli_bundle(env))) st.previous = hcli_bundle(env).string();
    } else if (fs::exists(hcli_bundle(env))) {
        st.owner = HandlerOwner::hcli;
        st.command = hcli_bundle(env).string();
    }
#else
    const std::string desktop = mimeapps_default(env);
    st.command = desktop;
    if (desktop.empty()) {
        st.owner = HandlerOwner::none;
    } else if (desktop == desktop_file(env).filename().string()) {
        st.owner = HandlerOwner::idasql;
        st.previous = saved_previous(env);
    } else if (desktop.find("hcli") != std::string::npos) {
        st.owner = HandlerOwner::hcli;
    } else {
        st.owner = HandlerOwner::other;
    }
#endif
    return st;
}

bool register_handler(const fs::path& handler_exe, const RegistrationEnv& env, std::string& error) {
#ifdef _WIN32
    const std::wstring root = ida_key(env);
    const std::wstring exe = handler_exe.native();
    // Remember the handler we replace, unless it is already us (registering twice must
    // not overwrite the saved one with our own command).
    const std::string before = reg_get(HKEY_CURRENT_USER, root + L"\\shell\\open\\command");
    bool ok = true;
    if (!before.empty() && classify_command(before) != HandlerOwner::idasql) {
        ok = reg_set(HKEY_CURRENT_USER, root, kPreviousCommand, widen(before)) &&
             reg_set(HKEY_CURRENT_USER, root, kPreviousIcon,
                     widen(reg_get(HKEY_CURRENT_USER, root + L"\\DefaultIcon")));
    }
    ok = ok && reg_set(HKEY_CURRENT_USER, root, nullptr, L"URL:IDA Protocol") &&
         reg_set(HKEY_CURRENT_USER, root, L"URL Protocol", L"") &&
         reg_set(HKEY_CURRENT_USER, root + L"\\DefaultIcon", nullptr, L"\"" + exe + L"\",0") &&
         reg_set(HKEY_CURRENT_USER, root + L"\\shell\\open\\command", nullptr,
                 widen(handler_command_line(handler_exe)));
    if (!ok) error = "cannot write HKCU\\" + env.windows_classes_key + "\\ida";
    return ok;
#elif defined(__APPLE__)
    auto run = env.run ? env.run : run_default;
    const fs::path app = app_bundle(env);
    std::error_code ec;
    fs::create_directories(app.parent_path(), ec);
    const fs::path script = fs::temp_directory_path(ec) / "idasql-link-ida.applescript";
    {
        std::ofstream out(script);
        out << "on open location this_URL\n"
            << "  do shell script quoted form of \"" << handler_exe.string()
            << "\" & \" link open --from-handler -- \" & quoted form of this_URL\n"
            << "end open location\n"
            << "on run\nend run\n";
    }
    if (run({"/usr/bin/osacompile", "-o", app.string(), script.string()}) != 0) {
        error = "osacompile failed";
        return false;
    }
    fs::remove(script, ec);
    const std::string plist = (app / "Contents" / "Info.plist").string();
    const std::string types =
        "<array><dict><key>CFBundleURLName</key><string>ida link</string><key>CFBundleURLSchemes</key>"
        "<array><string>ida</string></array></dict></array>";
    run({"/usr/bin/plutil", "-remove", "CFBundleURLTypes", plist});
    if (run({"/usr/bin/plutil", "-insert", "CFBundleURLTypes", "-xml", types, plist}) != 0 ||
        run({"/usr/bin/plutil", "-replace", "LSUIElement", "-bool", "YES", plist}) != 0) {
        error = "cannot edit " + plist;
        return false;
    }
    run({kLsregister, "-f", app.string()});
    return true;
#else
    auto run = env.run ? env.run : run_default;
    const fs::path file = desktop_file(env);
    // The handler we replace: the current default, unless that is already us, in
    // which case the one we saved last time.
    const std::string current = mimeapps_default(env);
    const std::string previous = current == file.filename().string() ? saved_previous(env) : current;
    std::error_code ec;
    fs::create_directories(file.parent_path(), ec);
    {
        std::ofstream out(file, std::ios::trunc);
        if (!out) {
            error = "cannot write " + file.string();
            return false;
        }
        out << "[Desktop Entry]\n"
            << "Name=IDASQL ida:// link handler\n"
            << "Exec=\"" << handler_exe.string() << "\" link open --from-handler -- %u\n"
            << "Type=Application\n"
            << "NoDisplay=true\n"
            << "MimeType=x-scheme-handler/ida;\n";
        if (!previous.empty()) out << kPreviousKey << previous << "\n";
    }
    fs::permissions(file, fs::perms::owner_all | fs::perms::group_read | fs::perms::others_read,
                    fs::perm_options::replace, ec);
    if (run({"xdg-mime", "default", file.filename().string(), "x-scheme-handler/ida"}) != 0) {
        error = "xdg-mime failed to set the default handler";
        return false;
    }
    run({"update-desktop-database", file.parent_path().string()});
    return true;
#endif
}

bool unregister_handler(const RegistrationEnv& env, std::string& error) {
    const HandlerStatus st = handler_status(env);
    if (st.owner == HandlerOwner::none) return true;
    if (st.owner != HandlerOwner::idasql) {
        error = std::string("ida:// belongs to ") + owner_name(st.owner) + ", not idasql; leaving it alone";
        return false;
    }
#ifdef _WIN32
    const std::wstring root = ida_key(env);
    if (!st.previous.empty()) {
        // Put the replaced handler back: its command, its icon, and nothing of ours.
        const std::string icon = reg_get(HKEY_CURRENT_USER, root, kPreviousIcon);
        bool ok = reg_set(HKEY_CURRENT_USER, root + L"\\shell\\open\\command", nullptr, widen(st.previous));
        if (icon.empty()) {
            const LONG rc = RegDeleteTreeW(HKEY_CURRENT_USER, (root + L"\\DefaultIcon").c_str());
            ok = ok && (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND);
        } else {
            ok = ok && reg_set(HKEY_CURRENT_USER, root + L"\\DefaultIcon", nullptr, widen(icon));
        }
        for (const wchar_t* name : {kPreviousCommand, kPreviousIcon}) {
            const LONG rc = RegDeleteKeyValueW(HKEY_CURRENT_USER, root.c_str(), name);
            ok = ok && (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND);
        }
        if (!ok) error = "cannot restore the previous handler under HKCU\\" + env.windows_classes_key + "\\ida";
        return ok;
    }
    const LONG rc = RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str());
    if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) {
        error = "cannot delete HKCU\\" + env.windows_classes_key + "\\ida";
        return false;
    }
    return true;
#elif defined(__APPLE__)
    auto run = env.run ? env.run : run_default;
    const fs::path app = app_bundle(env);
    run({kLsregister, "-u", app.string()});
    std::error_code ec;
    fs::remove_all(app, ec);
    // hcli's bundle claims ida:// again once ours is gone.
    if (!st.previous.empty()) run({kLsregister, "-f", st.previous});
    return true;
#else
    auto run = env.run ? env.run : run_default;
    const fs::path file = desktop_file(env);
    std::error_code ec;
    fs::remove(file, ec);
    run({"xdg-mime", "default", st.previous, "x-scheme-handler/ida"});
    run({"update-desktop-database", file.parent_path().string()});
    return true;
#endif
}

// ===========================================================================
// IPC override seam
// ===========================================================================

void set_ipc_options_override(std::optional<IpcOptions> options) {
    std::lock_guard<std::mutex> lock(g_override_mutex);
    g_override = std::move(options);
}

IpcOptions effective_ipc_options() {
    std::lock_guard<std::mutex> lock(g_override_mutex);
    return g_override ? *g_override : IpcOptions{};
}

// ===========================================================================
// `idasql link ...`
// ===========================================================================

namespace {

enum Exit : int {
    kOk = 0,
    kUsage = 1,
    kBadLink = 2,
    kNotFound = 3,
    kAmbiguous = 4,
    kIdaError = 5,
    kLaunchFailed = 6,
    kDeclined = 7,
};

fs::path handler_log_path() {
#ifdef _WIN32
    std::string base = env_var("LOCALAPPDATA");
    if (base.empty()) base = env_var("APPDATA");
    return u8path(base) / "idasql" / "link-handler.log";
#elif defined(__APPLE__)
    return fs::path(env_var("HOME")) / "Library" / "Logs" / "idasql-link.log";
#else
    std::string base = env_var("XDG_STATE_HOME");
    if (base.empty()) base = env_var("HOME") + "/.local/state";
    return fs::path(base) / "idasql" / "link-handler.log";
#endif
}

class Reporter {
public:
    explicit Reporter(bool from_handler) : from_handler_(from_handler) {}

    void info(const std::string& text) {
        std::cout << text << "\n";
        log("info", text);
    }
    void error(const std::string& text) {
        std::cerr << "error: " << text << "\n";
        log("error", text);
        if (from_handler_) notify(text);
    }
    // The user's own "no": record it, but raising a box about it would ask twice.
    void declined(const std::string& text) {
        std::cerr << text << "\n";
        log("info", text);
    }

private:
    void log(const char* level, const std::string& text) {
        if (!from_handler_) return;
        const fs::path path = handler_log_path();
        std::error_code ec;
        fs::create_directories(path.parent_path(), ec);
        std::ofstream out(path, std::ios::app);
        const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm local{};
#ifdef _WIN32
        localtime_s(&local, &now);
#else
        localtime_r(&now, &local);
#endif
        char stamp[32] = {};
        std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &local);
        out << stamp << " " << level << " " << text << "\n";
    }

    static void notify(const std::string& text) {
#ifdef _WIN32
        MessageBoxW(nullptr, widen(text).c_str(), L"idasql link", MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND);
#elif defined(__APPLE__)
        run_default({"/usr/bin/osascript", "-e",
                     "display alert \"idasql link\" message " + applescript_string(text)});
#else
        if (run_default({"zenity", "--error", "--title=idasql link", "--text=" + text}) != 0)
            run_default({"notify-send", "idasql link", text});
#endif
    }

public:
#ifdef __APPLE__
    static std::string applescript_string(const std::string& s) {
        std::string out = "\"";
        for (char c : s) {
            if (c == '"' || c == '\\') out.push_back('\\');
            out.push_back(c);
        }
        return out + "\"";
    }
#endif

private:
    bool from_handler_;
};

// A yes/no question on the desktop; false when no dialog can be shown.
bool confirm_on_desktop(const std::string& question) {
#ifdef _WIN32
    return MessageBoxW(nullptr, widen(question).c_str(), L"idasql link",
                       MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_TOPMOST | MB_SETFOREGROUND) == IDYES;
#elif defined(__APPLE__)
    return run_default({"/usr/bin/osascript", "-e",
                        "display dialog " + Reporter::applescript_string(question) +
                            " with title \"idasql link\" buttons {\"Cancel\", \"Open\"} default button "
                            "\"Cancel\" cancel button \"Cancel\""}) == 0;
#else
    const int rc = run_default({"zenity", "--question", "--title=idasql link", "--text=" + question});
    if (rc == 0) return true;
    if (rc == 1) return false;
    return run_default({"kdialog", "--title", "idasql link", "--yesno", question}) == 0;
#endif
}

void print_usage() {
    std::cerr <<
        "usage: idasql link <verb> ...\n"
        "\n"
        "  open [--pid N] [--no-launch] [--launch-anyway] [--skip-analysis] [--timeout S]\n"
        "       [--ida-arg A]... [--from-handler] [--] <uri>\n"
        "                       open an ida:// link in a running IDA 9.4,\n"
        "                       launching IDA on the database when none has it open\n"
        "                       (--timeout: 1..3600 seconds; --launch-anyway: launch even\n"
        "                       when an IDA that does not answer may have it open)\n"
        "  list [--json]        running IDA 9.4 instances and their databases\n"
        "  status [--json]      who handles ida:// links on this machine\n"
        "  register             make idasql the ida:// handler; a handler it replaces\n"
        "                       (hcli's, say) is saved\n"
        "  unregister           remove idasql's registration, restoring the saved handler\n"
        "  source add <name> <dir> | source list | source remove <name>\n"
        "  config show | config ida <path|--clear> | config ida-args [arg...]\n"
        "  config launch-timeout <seconds> | config wait-analysis on|off\n"
        "\n"
        "  --config <file>      before the verb: use another links.json\n"
        "                       (default: the user config dir)\n";
}

bool take_value(const std::vector<std::string>& a, size_t& i, std::string& out) {
    if (i + 1 >= a.size()) return false;
    out = a[++i];
    return true;
}

json instance_json(const Instance& i, const IpcOptions& options) {
    json j = {{"pid", i.pid}, {"endpoint", i.endpoint}, {"responsive", i.responsive},
              {"idb_path", i.idb_path}, {"idb_name", i.idb_name()}, {"version", i.version}};
    if (i.responsive && !i.idb_path.empty()) {
        std::string err;
        const auto done = analysis_complete({i.pid, i.endpoint}, err, options);
        j["analysis_complete"] = done ? json(*done) : json(nullptr);
    } else {
        j["analysis_complete"] = nullptr;
    }
    return j;
}

std::string describe(const Instance& i) {
    return "PID " + std::to_string(i.pid) + ": " + (i.idb_path.empty() ? "no database open" : i.idb_path);
}

int verb_list(const std::vector<std::string>& a) {
    bool as_json = std::find(a.begin(), a.end(), "--json") != a.end();
    const IpcOptions options = effective_ipc_options();
    const auto instances = list_instances(options);
    if (as_json) {
        json arr = json::array();
        for (const auto& i : instances) arr.push_back(instance_json(i, options));
        std::cout << arr.dump(2) << "\n";
        return kOk;
    }
    if (instances.empty()) {
        std::cout << "No running IDA 9.4 instances.\n";
        return kOk;
    }
    for (const auto& i : instances) std::cout << describe(i) << (i.responsive ? "" : " (not answering)") << "\n";
    return kOk;
}

int verb_status(const std::vector<std::string>& a) {
    bool as_json = std::find(a.begin(), a.end(), "--json") != a.end();
    const HandlerStatus st = handler_status(RegistrationEnv{});
    if (as_json) {
        std::cout << json{{"scheme", "ida"}, {"owner", owner_name(st.owner)}, {"command", st.command},
                          {"previous", st.previous}}
                         .dump(2)
                  << "\n";
        return kOk;
    }
    std::cout << "ida://  " << owner_name(st.owner);
    if (!st.command.empty()) std::cout << "  (" << st.command << ")";
    std::cout << "\n";
    if (!st.previous.empty()) std::cout << "previous handler, restored by unregister: " << st.previous << "\n";
    return kOk;
}

int verb_register(const std::vector<std::string>& a, bool unregister) {
    if (!a.empty()) {
        std::cerr << "error: unexpected argument '" << a[0] << "'\n";
        return kUsage;
    }
    const RegistrationEnv env;
    std::string error;
    const HandlerStatus before = handler_status(env);
    if (unregister) {
        if (!unregister_handler(env, error)) {
            std::cerr << "error: " << error << "\n";
            return kIdaError;
        }
        if (before.owner == HandlerOwner::idasql && !before.previous.empty()) {
            std::cout << "ida://  handed back to " << before.previous << "\n";
        } else {
            std::cout << "ida://  no longer handled by idasql\n";
        }
        return kOk;
    }
    if (!register_handler(self_executable(), env, error)) {
        std::cerr << "error: " << error << "\n";
        return kIdaError;
    }
    std::cout << "ida://  now handled by " << path_string(self_executable()) << "\n";
    if (before.owner == HandlerOwner::hcli || before.owner == HandlerOwner::other)
        std::cout << "note: this replaced " << owner_name(before.owner)
                  << "'s handler; `idasql link unregister` restores it\n";
    return kOk;
}

int verb_source(const std::vector<std::string>& a, const fs::path& config_path) {
    std::string error;
    Config cfg = load_config(config_path, &error);
    if (a.empty() || a[0] == "list") {
        if (cfg.sources.empty()) std::cout << "No sources.\n";
        for (const auto& [name, dir] : cfg.sources) std::cout << name << "  " << dir << "\n";
        return kOk;
    }
    if (a[0] == "add" && a.size() == 3) {
        if (!valid_source_name(a[1])) {
            std::cerr << "error: source names are lower-case letters, digits and '-', and 'localhost' is reserved\n";
            return kUsage;
        }
        std::error_code ec;
        const fs::path dir = fs::absolute(u8path(a[2]), ec);
        if (ec || !fs::is_directory(dir, ec)) {
            std::cerr << "error: not a directory: " << a[2] << "\n";
            return kUsage;
        }
        cfg.sources[a[1]] = path_string(dir);
    } else if (a[0] == "remove" && a.size() == 2) {
        if (cfg.sources.erase(a[1]) == 0) {
            std::cerr << "error: no source named " << a[1] << "\n";
            return kUsage;
        }
    } else {
        print_usage();
        return kUsage;
    }
    if (!save_config(config_path, cfg, error)) {
        std::cerr << "error: " << error << "\n";
        return kIdaError;
    }
    return kOk;
}

int verb_config(const std::vector<std::string>& a, const fs::path& config_path) {
    std::string error;
    Config cfg = load_config(config_path, &error);
    if (a.empty() || a[0] == "show") {
        std::ifstream in(config_path);
        std::cout << "# " << path_string(config_path) << "\n";
        if (in) {
            std::cout << in.rdbuf();
        } else {
            std::cout << "(no file; defaults apply)\n";
        }
        return kOk;
    }
    if (a[0] == "ida" && a.size() == 2) {
        cfg.ida = a[1] == "--clear" ? std::string() : a[1];
    } else if (a[0] == "ida-args") {
        cfg.ida_args.assign(a.begin() + 1, a.end());
    } else if (a[0] == "launch-timeout" && a.size() == 2) {
        const auto v = parse_number(a[1]);
        if (!v || *v == 0 || *v > 3600) {
            std::cerr << "error: launch-timeout takes 1..3600 seconds\n";
            return kUsage;
        }
        cfg.launch_timeout_s = static_cast<int>(*v);
    } else if (a[0] == "wait-analysis" && a.size() == 2 && (a[1] == "on" || a[1] == "off")) {
        cfg.wait_analysis = a[1] == "on";
    } else {
        print_usage();
        return kUsage;
    }
    if (!save_config(config_path, cfg, error)) {
        std::cerr << "error: " << error << "\n";
        return kIdaError;
    }
    return kOk;
}

// Poll until `probe` returns a value or the deadline passes.
template <typename T, typename F>
std::optional<T> poll_until(std::chrono::steady_clock::time_point deadline, F probe) {
    auto delay = std::chrono::milliseconds(100);
    for (;;) {
        if (auto v = probe()) return v;
        if (std::chrono::steady_clock::now() >= deadline) return std::nullopt;
        std::this_thread::sleep_for(delay);
        delay = std::min(delay * 3 / 2, std::chrono::milliseconds(1000));
    }
}

int verb_open(const std::vector<std::string>& a, const fs::path& config_path) {
    std::optional<uint64_t> pid;
    bool no_launch = false, launch_anyway = false, skip_analysis = false, from_handler = false;
    std::optional<int> timeout_s;
    std::vector<std::string> ida_args;
    std::string uri;
    for (size_t i = 0; i < a.size(); ++i) {
        std::string v;
        if (a[i] == "--") {
            if (i + 1 < a.size()) uri = a[i + 1];
            if (i + 2 < a.size()) {
                std::cerr << "error: one link at a time\n";
                return kUsage;
            }
            break;
        }
        if (a[i] == "--pid" && take_value(a, i, v)) {
            pid = parse_number(v);
            if (!pid) return kUsage;
        } else if (a[i] == "--no-launch") {
            no_launch = true;
        } else if (a[i] == "--launch-anyway") {
            launch_anyway = true;
        } else if (a[i] == "--skip-analysis") {
            skip_analysis = true;
        } else if (a[i] == "--from-handler") {
            from_handler = true;
        } else if (a[i] == "--timeout" && take_value(a, i, v)) {
            const auto t = parse_number(v);
            if (!t || *t == 0 || *t > 3600) {
                std::cerr << "error: --timeout takes 1..3600 seconds\n";
                return kUsage;
            }
            timeout_s = static_cast<int>(*t);
        } else if (a[i] == "--ida-arg" && take_value(a, i, v)) {
            ida_args.push_back(v);
        } else if (uri.empty() && !starts_with(a[i], "--")) {
            uri = a[i];
        } else {
            std::cerr << "error: unexpected argument '" << a[i] << "'\n";
            return kUsage;
        }
    }
    Reporter report(from_handler);
#ifdef _WIN32
    // A click starts this console program in a console window of its own, which
    // would then sit on the desktop for as long as a launch takes. Detaching
    // closes it; the handler reports through its log and native dialogs instead.
    if (from_handler) FreeConsole();
#endif
    if (uri.empty()) {
        print_usage();
        return kUsage;
    }
    if (const std::string why = screen_untrusted_uri(uri); !why.empty()) {
        report.error(why);
        return kBadLink;
    }
    const ParsedLink link = parse(uri);
    if (!link.valid) {
        report.error("invalid link: " + link.diagnostic);
        return kBadLink;
    }
    const std::string ida_uri = to_ida_uri(link);
    if (ida_uri.empty()) {
        report.error("invalid link: cannot be re-encoded for IDA");
        return kBadLink;
    }
    const IpcOptions options = effective_ipc_options();

    auto navigate = [&](const Instance& target) {
        std::string message;
        if (open_in({target.pid, target.endpoint}, ida_uri, message, options)) {
            report.info("opened " + ida_uri + " in IDA (PID " + std::to_string(target.pid) + ")");
            return kOk;
        }
        report.error("IDA (PID " + std::to_string(target.pid) + ") could not open " + ida_uri + ": " + message +
                     " (the reason is in IDA's Output window)");
        return kIdaError;
    };

    const auto instances = list_instances(options);
    // The exact file is on this machine: a same-named database open elsewhere is a
    // different database, so it is launched rather than steered to.
    const bool exact_file_here = !link.target.idb_path.empty() && !is_remote_path(link.target.idb_path) &&
                                 is_file(u8path(link.target.idb_path));
    const Selection sel = select_instance(instances, link.target, pid, !exact_file_here);
    if (sel.chosen) {
        if (sel.by_name)
            report.info("no IDA has " + link.target.idb_path + " open; using PID " + std::to_string(sel.chosen->pid) +
                        ", which has " + sel.chosen->idb_path + " (same name, different path)");
        return navigate(*sel.chosen);
    }
    if (!sel.candidates.empty()) {
        std::string text = sel.error + "; pick one with --pid:";
        for (const auto& c : sel.candidates) text += "\n  " + describe(c);
        report.error(text);
        return kAmbiguous;
    }
    if (pid || no_launch || (link.target.idb_name.empty() && link.target.idb_path.empty())) {
        std::string text = sel.error;
        for (const auto& i : instances) text += "\n  " + describe(i);
        report.error(text);
        return kNotFound;
    }

    // An IDA that does not answer (its UI thread busy: a modal dialog, a script,
    // a long query) may be the one with this database open; a second IDA on the
    // same database would fail on its lock.
    if (!launch_anyway) {
        for (const auto& i : instances) {
            if (!i.responsive) {
                report.error("IDA PID " + std::to_string(i.pid) +
                             " does not answer and may have this database open; retry, pass --pid, or "
                             "--launch-anyway");
                return kNotFound;
            }
        }
    }

    // Nothing has the database open: launch IDA on it.
    std::string error;
    const Config cfg = load_config(config_path, &error);
    const IdbResolution idb = resolve_idb(link.target, cfg);
    if (!idb.path) {
        report.error(sel.error + "; " + idb.error);
        return kNotFound;
    }
    // IDA keeps the unpacked <stem>.id0 next to the database while it is open.
    if (!launch_anyway) {
        fs::path id0 = *idb.path;
        id0.replace_extension(".id0");
        if (is_file(id0)) {
            report.error(path_string(*idb.path) + " looks open in another IDA (" + path_string(id0) +
                         " exists); close it, or pass --launch-anyway");
            return kNotFound;
        }
    }
    if (from_handler && !idb.under_source &&
        !confirm_on_desktop("Open this database in IDA?\n\n" + path_string(*idb.path))) {
        report.declined("launch declined: " + path_string(*idb.path));
        return kDeclined;
    }
    const auto ida = resolve_ida(cfg, self_executable(), error);
    if (!ida) {
        report.error(error);
        return kLaunchFailed;
    }
    std::vector<std::string> args = cfg.ida_args;
    args.insert(args.end(), ida_args.begin(), ida_args.end());
    const auto child = spawn_ida(*ida, args, *idb.path, error);
    if (!child) {
        report.error(error);
        return kLaunchFailed;
    }
    report.info("started " + path_string(*ida) + " on " + path_string(*idb.path) +
                (*child ? " (PID " + std::to_string(*child) + ")" : std::string()));

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(timeout_s.value_or(cfg.launch_timeout_s));
    const std::string db = path_string(*idb.path);
    // Wait for the launched process's own endpoint with the database loaded (IDA
    // starts its IPC server only after the database opens).
    const auto ready = poll_until<Instance>(deadline, [&]() -> std::optional<Instance> {
        IpcOptions o = options;
        if (*child) o.only_pids = {*child};
        for (const auto& i : list_instances(o)) {
            // The launched process opened it, under whatever name IDA reports
            // (a .idb upgraded to .i64, a canonical or differently-cased path).
            if (i.responsive && same_database(i.idb_path, db)) return i;
        }
        return std::nullopt;
    });
    if (!ready) {
        report.error("IDA did not open " + db + " within the launch timeout");
        return kLaunchFailed;
    }
    if (cfg.wait_analysis && !skip_analysis) {
        const auto done = poll_until<bool>(deadline, [&]() -> std::optional<bool> {
            std::string err;
            const auto complete = analysis_complete({ready->pid, ready->endpoint}, err, options);
            return complete && *complete ? std::optional<bool>(true) : std::nullopt;
        });
        if (!done) report.info("auto-analysis still running at the timeout; opening the link anyway");
    }
    return navigate(*ready);
}

int run_cli_impl(const std::vector<std::string>& args_in) {
    // Global options come before the verb only. Nothing after it is read as one: the
    // handler passes `open --from-handler -- "%1"`, and a link must never carry its
    // own --config (and with it the IDA executable to start).
    fs::path config_path = default_config_path();
    size_t i = 0;
    while (i < args_in.size() && args_in[i] == "--config") {
        if (i + 1 >= args_in.size()) {
            std::cerr << "error: --config needs a file\n";
            return kUsage;
        }
        config_path = u8path(args_in[i + 1]);
        i += 2;
    }
    const std::vector<std::string> args(args_in.begin() + static_cast<std::ptrdiff_t>(i), args_in.end());
    if (args.empty() || args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
        print_usage();
        return args.empty() ? kUsage : kOk;
    }
    const std::string verb = args[0];
    const std::vector<std::string> rest(args.begin() + 1, args.end());
    if (verb == "open") return verb_open(rest, config_path);
    if (verb == "list") return verb_list(rest);
    if (verb == "status") return verb_status(rest);
    if (verb == "register") return verb_register(rest, false);
    if (verb == "unregister") return verb_register(rest, true);
    if (verb == "source") return verb_source(rest, config_path);
    if (verb == "config") return verb_config(rest, config_path);
    std::cerr << "error: unknown link verb '" << verb << "'\n";
    print_usage();
    return kUsage;
}

}  // namespace

int run_cli(const std::vector<std::string>& args) {
    // Nothing may escape a link verb: it runs as the OS URL handler.
    const bool handler = std::find(args.begin(), args.end(), "--from-handler") != args.end();
    try {
        return run_cli_impl(args);
    } catch (const std::exception& e) {
        Reporter(handler).error(std::string("internal error: ") + e.what());
    } catch (...) {
        Reporter(handler).error("internal error");
    }
    return kIdaError;
}

}  // namespace deep_link
}  // namespace idasql
