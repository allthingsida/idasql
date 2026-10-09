// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "cfg_parser.hpp"

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace idasql {
namespace cfgparse {
namespace {

std::string read_all(const std::string& path, bool* ok) {
    std::ifstream f(path, std::ios::binary);
    *ok = static_cast<bool>(f);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Strip // and /* */ comments outside "strings" and 'chars'; keep newlines.
std::string strip_comments(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    enum { N, STR, CHR, LINE, BLOCK } st = N;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        const char n = i + 1 < s.size() ? s[i + 1] : '\0';
        switch (st) {
            case N:
                if (c == '/' && n == '/') { st = LINE; ++i; }
                else if (c == '/' && n == '*') { st = BLOCK; ++i; o.push_back(' '); }
                else {
                    if (c == '"') st = STR;
                    else if (c == '\'') st = CHR;
                    o.push_back(c);
                }
                break;
            case STR:
            case CHR:
                o.push_back(c);
                if (c == '\\' && n) { o.push_back(n); ++i; }
                else if ((st == STR && c == '"') || (st == CHR && c == '\'')) st = N;
                else if (c == '\n') st = N;  // unterminated: recover at the line end
                break;
            case LINE:
                if (c == '\n') { st = N; o.push_back('\n'); }
                break;
            case BLOCK:
                if (c == '*' && n == '/') { st = N; ++i; }
                else if (c == '\n') o.push_back('\n');
                break;
        }
    }
    return o;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

// Collapse whitespace runs outside strings to one space.
std::string collapse(const std::string& s) {
    std::string o;
    bool in_str = false, sp = false;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (in_str) {
            o.push_back(c);
            if (c == '\\' && i + 1 < s.size()) o.push_back(s[++i]);
            else if (c == '"') in_str = false;
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(c))) { sp = true; continue; }
        if (sp && !o.empty()) o.push_back(' ');
        sp = false;
        if (c == '"') in_str = true;
        o.push_back(c);
    }
    return o;
}

// Net bracket depth change of a line, ignoring strings.
int bracket_delta(const std::string& s) {
    int d = 0;
    bool in_str = false;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (in_str) {
            if (c == '\\') ++i;
            else if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') in_str = true;
        else if (c == '{' || c == '[' || c == '(') ++d;
        else if (c == '}' || c == ']' || c == ')') --d;
    }
    return d;
}

bool is_ident_start(char c) {
    return std::isalpha(static_cast<unsigned char>(c)) || c == '_';
}
bool is_ident(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

std::string expand(const std::string& v,
                   const std::map<std::string, std::string>& macros,
                   int depth = 0) {
    if (depth > 8) return v;
    std::string o;
    bool in_str = false;
    for (size_t i = 0; i < v.size();) {
        const char c = v[i];
        if (in_str) {
            o.push_back(c);
            if (c == '\\' && i + 1 < v.size()) { o.push_back(v[i + 1]); i += 2; continue; }
            if (c == '"') in_str = false;
            ++i;
            continue;
        }
        if (c == '"') { in_str = true; o.push_back(c); ++i; continue; }
        if (is_ident_start(c) && (i == 0 || !is_ident(v[i - 1]))) {
            size_t j = i;
            while (j < v.size() && is_ident(v[j])) ++j;
            const std::string id = v.substr(i, j - i);
            auto it = macros.find(id);
            if (it != macros.end() && !it->second.empty())
                o += expand(it->second, macros, depth + 1);
            else
                o += id;
            i = j;
            continue;
        }
        o.push_back(c);
        ++i;
    }
    return o;
}

// #if expression: `defined(X)`, `!defined(X)`, `__IDAVER__ <op> N`; else false.
bool eval_if(const std::string& e0, const Context& ctx) {
    std::string e = trim(e0);
    bool neg = false;
    if (!e.empty() && e[0] == '!') { neg = true; e = trim(e.substr(1)); }
    if (e.rfind("defined", 0) == 0) {
        const size_t a = e.find('('), b = e.find(')');
        const std::string name = (a != std::string::npos && b != std::string::npos)
                                     ? trim(e.substr(a + 1, b - a - 1))
                                     : trim(e.substr(7));
        const bool r = ctx.defines.count(name) != 0;
        return neg ? !r : r;
    }
    if (e.rfind("__IDAVER__", 0) == 0) {
        std::string rest = trim(e.substr(10));
        std::string op;
        while (!rest.empty() && (rest[0] == '>' || rest[0] == '<' || rest[0] == '=' || rest[0] == '!')) {
            op.push_back(rest[0]);
            rest.erase(0, 1);
        }
        const long n = std::strtol(trim(rest).c_str(), nullptr, 0);
        const int v = ctx.idaver;
        const bool r = op == ">=" ? v >= n : op == ">" ? v > n : op == "<=" ? v <= n
                     : op == "<" ? v < n : op == "==" ? v == n : op == "!=" ? v != n : false;
        return neg ? !r : r;
    }
    return false;
}

// IDA reads the first file found: the including file's directory, then dirs.
std::string find_include(const std::string& name, const Context& ctx,
                         const std::string& cur_dir) {
    std::vector<std::string> dirs = ctx.dirs;
    dirs.insert(dirs.begin(), cur_dir);
    for (const auto& d : dirs) {
        const std::string p = d + "/" + name;
        std::ifstream f(p);
        if (f) return p;
    }
    return {};
}

// `value` minus trailing ';' (recorded in *terminated).
std::string strip_semicolons(std::string value, bool* terminated) {
    value = trim(value);
    while (!value.empty() && value.back() == ';') {
        *terminated = true;
        value.pop_back();
        value = trim(value);
    }
    return value;
}

}  // namespace

bool parse_file(const std::string& path, const Context& ctx,
                std::vector<Entry>& out,
                std::map<std::string, std::string>& macros, int depth) {
    bool ok = false;
    const std::string raw = read_all(path, &ok);
    if (!ok) return false;
    const std::string text = strip_comments(raw);
    const size_t slash = path.find_last_of("/\\");
    const std::string dir = slash == std::string::npos ? "." : path.substr(0, slash);
    const std::string fname = slash == std::string::npos ? path : path.substr(slash + 1);

    struct Frame { bool parent_active; bool cond; };
    std::vector<Frame> stack;
    auto active = [&]() {
        return stack.empty() || (stack.back().parent_active && stack.back().cond);
    };

    std::istringstream in(text);
    std::string line;
    Entry pending;
    std::string pending_raw;
    bool has_pending = false;
    int pend_depth = 0;
    auto flush = [&]() {
        if (!has_pending) return;
        pending.value = expand(strip_semicolons(collapse(trim(pending_raw)), &pending.terminated),
                               macros);
        out.push_back(pending);
        has_pending = false;
    };

    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const std::string t = trim(line);
        if (has_pending) {
            // A value ends at ';', or at its line end once its brackets balance,
            // unless the next line continues it (a list over several lines,
            // adjacent string literals). A new statement or directive ends it.
            bool new_stmt = false;
            if (!t.empty() && t[0] == '#') {
                new_stmt = pend_depth <= 0;
            } else if (!t.empty() && is_ident_start(t[0])) {
                size_t k = 0;
                while (k < t.size() && is_ident(t[k])) ++k;
                while (k < t.size() && std::isspace(static_cast<unsigned char>(t[k]))) ++k;
                new_stmt = k < t.size() && t[k] == '=' && pend_depth <= 0;
            }
            if (new_stmt) {
                flush();
            } else if (!t.empty() && t[0] == '#') {
                // a directive inside a bracketed value: handled below
            } else {
                if (!t.empty()) {
                    pending_raw += " " + t;
                    pend_depth += bracket_delta(t);
                }
                const std::string v = trim(pending_raw);
                if (pend_depth <= 0 && !v.empty() && v.back() == ';') flush();
                continue;
            }
        }
        if (t.empty()) continue;
        if (t[0] == '#') {
            const std::string d = trim(t.substr(1));
            std::string word;
            size_t k = 0;
            while (k < d.size() && is_ident(d[k])) word.push_back(d[k++]);
            const std::string arg = trim(d.substr(k));
            const bool act = active();
            if (word == "ifdef" || word == "ifndef") {
                std::string name;
                for (char c : arg) {
                    if (!is_ident(c)) break;
                    name.push_back(c);
                }
                const bool def = ctx.defines.count(name) != 0;
                stack.push_back({act, word == "ifdef" ? def : !def});
            } else if (word == "if") {
                stack.push_back({act, eval_if(arg, ctx)});
            } else if (word == "else") {
                if (!stack.empty()) stack.back().cond = !stack.back().cond;
            } else if (word == "endif") {
                if (!stack.empty()) stack.pop_back();
            } else if (word == "define") {
                if (act) {
                    std::string name;
                    size_t j = 0;
                    while (j < arg.size() && is_ident(arg[j])) name.push_back(arg[j++]);
                    macros[name] = collapse(trim(arg.substr(j)));
                }
            } else if (word == "include" || word == "softinclude") {
                if (act && depth < 4) {
                    const size_t a = arg.find_first_of("<\""), b = arg.find_last_of(">\"");
                    if (a != std::string::npos && b != std::string::npos && b > a) {
                        const std::string inc = find_include(arg.substr(a + 1, b - a - 1), ctx, dir);
                        if (!inc.empty()) parse_file(inc, ctx, out, macros, depth + 1);
                    }
                }
            }
            continue;
        }
        // KEY = value at the top level?
        if (is_ident_start(t[0])) {
            size_t k = 0;
            while (k < t.size() && is_ident(t[k])) ++k;
            size_t e = k;
            while (e < t.size() && std::isspace(static_cast<unsigned char>(t[e]))) ++e;
            if (e < t.size() && t[e] == '=' && (e + 1 >= t.size() || t[e + 1] != '=')) {
                pending = Entry{};
                pending.key = t.substr(0, k);
                pending.file = fname;
                pending.active = active();
                pending_raw = trim(t.substr(e + 1));
                pend_depth = bracket_delta(pending_raw);
                has_pending = true;
                if (pend_depth <= 0 && !pending_raw.empty() && pending_raw.back() == ';') flush();
                continue;
            }
        }
    }
    flush();

    // Commented-out directives, `// KEY = value` at the start of a line: the
    // files document a default that way. Upper-case keys only, so prose such
    // as "// x = y" is not taken for a directive.
    std::istringstream rin(raw);
    std::string rl;
    while (std::getline(rin, rl)) {
        std::string t = trim(rl);
        if (t.rfind("//", 0) != 0) continue;
        t = trim(t.substr(2));
        if (t.empty() || !is_ident_start(t[0])) continue;
        size_t k = 0;
        while (k < t.size() && is_ident(t[k])) ++k;
        const std::string key = t.substr(0, k);
        size_t e = k;
        while (e < t.size() && std::isspace(static_cast<unsigned char>(t[e]))) ++e;
        if (e >= t.size() || t[e] != '=' || (e + 1 < t.size() && t[e + 1] == '=')) continue;
        bool upper = key.size() > 2;
        for (char c : key)
            if (std::islower(static_cast<unsigned char>(c))) upper = false;
        if (!upper) continue;
        Entry c;
        c.key = key;
        c.file = fname;
        c.commented = true;
        c.value = expand(strip_semicolons(collapse(trim(strip_comments(t.substr(e + 1)))),
                                          &c.terminated),
                         macros);
        out.push_back(c);
    }
    return true;
}

}  // namespace cfgparse
}  // namespace idasql
