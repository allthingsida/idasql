// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// ida_config — IDA's configuration keys.
//
// IDA offers no API that lists its configuration keys, so the rows come from
// the option files IDA itself reads: ida.cfg (its startup pass and its pass
// for the current processor), hexrays.cfg and idagui.cfg, from IDADIR/cfg then
// IDAUSR/cfg, later files winning, as IDA reads them.
//
// Reading a value (observed on IDA 9.0-9.4):
//   - get_config_value (config.hpp) answers the plain kernel keys: "runtime";
//   - the keys IDA keeps in the database's inf are read through ida.hpp's
//     getinf / getinf_str: "inf" (each mapping below was measured by applying
//     a directive and watching which inf field changed);
//   - every other key cannot be read back: a value this table applied in
//     this session is shown as "session", else the files' value as "file".
//
// Writing a value: process_config_directive("KEY=VALUE") (idacfg.hpp). It
// reports problems only as a warning box, so the table captures the box (and
// keeps it off the screen): "too high" / "too low" means IDA clamped the
// value, which the row's message column then shows; any other warning is a
// refusal, which fails the UPDATE with IDA's text. Only the inf keys are saved
// with the database; the rest last until it is closed. Nothing here writes
// .cfg files (IDA has no API for that).

#include <idasql/platform.hpp>

#include <cstdarg>
#include <cstdlib>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "metadata_config.hpp"

#include "ida_headers.hpp"
// SDK headers outside ida_headers.hpp, with the same warnings off: through 9.3,
// parsejson.hpp's int accessor narrows jvalue_t::num()'s int64 (C4244).
#if defined(_MSC_VER) && !defined(__clang__)
#pragma warning(push)
#pragma warning(disable: 4244)
#endif
#include <config.hpp>
#include <diskio.hpp>
#include <idacfg.hpp>
#include <parsejson.hpp>
#if defined(_MSC_VER) && !defined(__clang__)
#pragma warning(pop)
#endif

#include "cfg_parser.hpp"
#include "decompiler.hpp"

namespace idasql {
namespace metadata {
namespace {

// ---------------------------------------------------------------------------
// Keys kept in the database's inf, measured on IDA 9.0-9.4.

enum class InfKind { Whole, Bit, BitInverted, Pack, String };

struct InfKey {
    const char* key;
    inftag_t tag;
    uint64 mask;
    InfKind kind;
};

const InfKey kInfKeys[] = {
    {"ANALYSIS", INF_AF, 0, InfKind::Whole},
    {"ANALYSIS2", INF_AF2, 0, InfKind::Whole},
    {"COMMENTS_INDENTION", INF_CMT_INDENT, 0, InfKind::Whole},
    {"DEMNAME_FIRST", INF_DEMNAMES, 0x8, InfKind::Bit},
    {"DUMMY_NAMES_TYPE", INF_NAMETYPE, 0, InfKind::Whole},
    {"ENABLE_ANALYSIS", INF_GENFLAGS, 0x1, InfKind::Bit},
    {"FLAT_OFF32", INF_LFLAGS, 0x10, InfKind::Bit},
    {"INDENTION", INF_INDENT, 0, InfKind::Whole},
    {"LIST_NAMES", INF_LISTNAMES, 0, InfKind::Whole},
    {"LongNameForm", INF_LONG_DEMNAMES, 0, InfKind::Whole},
    {"MAX_AUTONAME_LEN", INF_MAX_AUTONAME_LEN, 0, InfKind::Whole},
    {"MAX_DATALINE_LENGTH", INF_MARGIN, 0, InfKind::Whole},
    {"MAX_TAIL", INF_MAXREF, 0, InfKind::Whole},
    {"MAX_XREF_LENGTH", INF_LENXREF, 0, InfKind::Whole},
    {"OPCODE_BYTES", INF_BIN_PREFIX_SIZE, 0, InfKind::Whole},
    {"PACK_DATABASE", INF_LFLAGS, 0, InfKind::Pack},
    {"SHOW_ASSUMES", INF_OUTFLAGS, 0x200, InfKind::Bit},
    {"SHOW_AUTOCOMMENTS", INF_CMTFLG, 0x2, InfKind::Bit},
    {"SHOW_BASIC_BLOCKS", INF_LIMITER, 0x4, InfKind::Bit},
    {"SHOW_BORDERS", INF_LIMITER, 0x1, InfKind::Bit},
    {"SHOW_EMPTYLINES", INF_OUTFLAGS, 0x10, InfKind::Bit},
    {"SHOW_INDICATOR", INF_OUTFLAGS, 0x4, InfKind::Bit},
    {"SHOW_LINEPREFIXES", INF_OUTFLAGS, 0x20, InfKind::Bit},
    {"SHOW_ORIGINS", INF_OUTFLAGS, 0x100, InfKind::Bit},
    {"SHOW_REFCMTS", INF_REFCMTNUM, 0, InfKind::Whole},
    {"SHOW_REPEATABLE_COMMENTS", INF_CMTFLG, 0x1, InfKind::Bit},
    {"SHOW_SEGMENTS", INF_PREFFLAG, 0x1, InfKind::Bit},
    {"SHOW_SEGXREFS", INF_XREFFLAG, 0x1, InfKind::Bit},
    {"SHOW_SOURCE_LINNUM", INF_CMTFLG, 0x8, InfKind::Bit},
    {"SHOW_SP", INF_PREFFLAG, 0x4, InfKind::Bit},
    {"SHOW_SUSPICIOUS", INF_OUTFLAGS, 0x2, InfKind::Bit},
    {"SHOW_TRYBLOCKS", INF_OUTFLAGS, 0x400, InfKind::Bit},
    {"SHOW_XREFS", INF_XREFNUM, 0, InfKind::Whole},
    {"SHOW_XREF_FUNC", INF_XREFFLAG, 0x4, InfKind::Bit},
    {"SHOW_XREF_TYPES", INF_XREFFLAG, 0x2, InfKind::Bit},
    {"SHOW_XREF_VALUES", INF_XREFFLAG, 0x8, InfKind::Bit},
    {"STORE_USER_INFO", INF_GENFLAGS, 0x8, InfKind::BitInverted},
    {"STRLIT_COMMENT", INF_STRLIT_FLAGS, 0x10, InfKind::Bit},
    {"STRLIT_GENNAMES", INF_STRLIT_FLAGS, 0x1, InfKind::Bit},
    {"STRLIT_PREFIX", INF_STRLIT_PREF, 0, InfKind::String},
    {"STRLIT_SAVECASE", INF_STRLIT_FLAGS, 0x20, InfKind::Bit},
    {"STRLIT_SERIAL", INF_STRLIT_FLAGS, 0x4, InfKind::Bit},
    {"STRLIT_SERNUM", INF_STRLIT_SERNUM, 0, InfKind::Whole},
    {"STRLIT_STYLE", INF_STRTYPE, 0, InfKind::Whole},
    {"STRLIT_TYPE_AUTO", INF_STRLIT_FLAGS, 0x2, InfKind::Bit},
    {"STRLIT_ZEROES", INF_STRLIT_ZEROES, 0, InfKind::Whole},
    {"ShortNameForm", INF_SHORT_DEMNAMES, 0, InfKind::Whole},
    {"USE_FPP", INF_LFLAGS, 0x1, InfKind::Bit},
    {"USE_SEGMENT_NAMES", INF_OUTFLAGS, 0x40, InfKind::Bit},
};

int find_inf_key(const std::string& key) {
    for (size_t i = 0; i < std::size(kInfKeys); ++i)
        if (key == kInfKeys[i].key) return static_cast<int>(i);
    return -1;
}

// ---------------------------------------------------------------------------
// Values in directive syntax

std::string quote(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c); break;
        }
    }
    out += "\"";
    return out;
}

std::string number_text(int64 v, bool hex) {
    char buf[32];
    if (hex)
        qsnprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    else
        qsnprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
    return buf;
}

std::string upper(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

bool is_bool_text(const std::string& v) {
    return v == "YES" || v == "NO" || v == "ON" || v == "OFF";
}

// One quoted string literal (a list value has several, or a trailing name).
bool is_single_string(const std::string& v) {
    if (v.size() < 2 || v.front() != '"') return false;
    for (size_t i = 1; i < v.size(); ++i) {
        if (v[i] == '\\') { ++i; continue; }
        if (v[i] == '"') return i == v.size() - 1;
    }
    return false;
}

bool is_number_text(const std::string& v) {
    if (v.empty()) return false;
    char* end = nullptr;
    const char* p = v.c_str();
    if (*p == '-') ++p;
    std::strtoull(p, &end, 0);
    return end != nullptr && *end == '\0' && end != p;
}

std::optional<std::string> read_inf(const InfKey& k, bool hex) {
    switch (k.kind) {
        case InfKind::Whole:
            return number_text(static_cast<int64>(getinf(k.tag)), hex);
        case InfKind::Bit:
            return (getinf(k.tag) & k.mask) != 0 ? std::string("YES") : std::string("NO");
        case InfKind::BitInverted:
            return (getinf(k.tag) & k.mask) != 0 ? std::string("NO") : std::string("YES");
        case InfKind::Pack: {
            const uint64 lflags = getinf(k.tag);
            return std::string((lflags & 0x400) != 0 ? "2" : (lflags & 0x200) != 0 ? "1" : "0");
        }
        case InfKind::String: {
            qstring s;
            if (getinf_str(&s, k.tag) < 0) return quote("");
            return quote(s.c_str());
        }
    }
    return std::nullopt;
}

std::optional<std::string> read_runtime(const std::string& key, bool hex, jtype_t* type) {
    jvalue_t v;
    if (!get_config_value(&v, key.c_str())) return std::nullopt;
    if (type) *type = v.type();
    switch (v.type()) {
        case JT_NUM: return number_text(v.num(), hex);
        case JT_BOOL: return std::string(v.vbool() ? "YES" : "NO");
        case JT_STR: return quote(v.str());
        default: {
            qstring s;
            if (!serialize_json(&s, v)) return std::nullopt;
            return std::string(s.c_str());
        }
    }
}

// ---------------------------------------------------------------------------
// Session state: what this table applied to keys IDA cannot read back, and
// the last warning IDA gave for each key.

std::map<std::string, std::string>& session_values() {
    static std::map<std::string, std::string> values;
    return values;
}

std::map<std::string, std::string>& session_messages() {
    static std::map<std::string, std::string> messages;
    return messages;
}

// Fill value / value_source / persisted / message from the live state.
void refresh(ConfigRow& row) {
    row.persisted = 0;
    row.message.reset();
    if (row.inf_index >= 0) {
        row.value = read_inf(kInfKeys[row.inf_index], row.hex);
        row.value_source = "inf";
        row.persisted = 1;
    } else if (auto v = read_runtime(row.key, row.hex, nullptr)) {
        row.value = std::move(v);
        row.value_source = "runtime";
    } else if (auto it = session_values().find(row.key); it != session_values().end()) {
        row.value = it->second;
        row.value_source = "session";
    } else {
        row.value = row.file_value;
        row.value_source = "file";
    }
    if (auto it = session_messages().find(row.key); it != session_messages().end())
        row.message = it->second;
}

// ---------------------------------------------------------------------------
// The rows

std::vector<std::string> cfg_dirs() {
    std::vector<std::string> dirs;
    if (const char* d = idadir(CFG_SUBDIR); d != nullptr && *d != '\0') dirs.push_back(d);
    if (const char* u = get_user_idadir(); u != nullptr && *u != '\0')
        dirs.push_back(std::string(u) + "/" + CFG_SUBDIR);
    return dirs;
}

std::set<std::string> host_defines() {
    std::set<std::string> defs;
#if defined(_WIN32)
    defs.insert("__NT__");
#elif defined(__APPLE__)
    defs.insert("__MAC__");
#elif defined(__linux__)
    defs.insert("__LINUX__");
#endif
#ifdef __EA64__
    defs.insert("__EA64__");
#endif
#ifdef __X64__
    defs.insert("__X64__");
#endif
    if (is_idaq()) {
        defs.insert("__GUI__");
        defs.insert("__QT__");
    }
    return defs;
}

std::vector<cfgparse::Entry> parse_option_file(const std::string& name,
                                               const std::set<std::string>& defines) {
    cfgparse::Context ctx;
    ctx.defines = defines;
    ctx.idaver = IDA_SDK_VERSION;
    ctx.dirs = cfg_dirs();
    std::vector<cfgparse::Entry> out;
    std::map<std::string, std::string> macros;
    for (const auto& dir : ctx.dirs) {
        const std::string path = dir + "/" + name;
        if (qfileexist(path.c_str())) cfgparse::parse_file(path, ctx, out, macros);
    }
    return out;
}

void collect_config_rows(std::vector<ConfigRow>& rows) {
    rows.clear();

    const std::set<std::string> base = host_defines();
    std::set<std::string> startup = base;  // ida.cfg's first pass
    startup.insert("____");
    std::set<std::string> processor = base;  // its pass for the current processor
    {
        char idp[QMAXFILE] = {0};
        get_idp_name(idp, sizeof(idp));
        processor.insert("__" + upper(idp) + "__");
        processor.insert("__" + upper(inf_get_procname().c_str()) + "__");
    }

    std::vector<cfgparse::Entry> entries;
    for (const auto& [file, defines] :
         std::vector<std::pair<std::string, std::set<std::string>>>{
             {"ida.cfg", startup}, {"ida.cfg", processor},
             {"hexrays.cfg", base}, {"idagui.cfg", base}}) {
        auto parsed = parse_option_file(file, defines);
        entries.insert(entries.end(), parsed.begin(), parsed.end());
    }

    // The keys the files set (the last active assignment wins), in order.
    std::vector<std::string> order;
    std::map<std::string, const cfgparse::Entry*> set_by;
    for (const auto& e : entries) {
        if (!e.active || e.commented) continue;
        if (set_by.find(e.key) == set_by.end()) order.push_back(e.key);
        set_by[e.key] = &e;
    }
    // A key the files mention only in a comment or in another processor's
    // section is listed when IDA reads it back.
    std::map<std::string, const cfgparse::Entry*> mentioned;
    for (const auto& e : entries) {
        if (set_by.count(e.key) != 0 || mentioned.count(e.key) != 0) continue;
        jvalue_t probe;
        if (find_inf_key(e.key) < 0 && !get_config_value(&probe, e.key.c_str())) continue;
        mentioned[e.key] = &e;
        order.push_back(e.key);
    }

    const bool gui = is_idaq();
    const bool hexrays = decompiler::hexrays_available();
    rows.reserve(order.size());
    for (const auto& key : order) {
        auto it = set_by.find(key);
        const cfgparse::Entry& e = it != set_by.end() ? *it->second : *mentioned[key];
        ConfigRow row;
        row.key = key;
        row.file = e.file;
        if (it != set_by.end()) row.file_value = e.value;
        row.inf_index = find_inf_key(key);
        const std::string& sample = e.value;
        row.hex = sample.rfind("0x", 0) == 0 || sample.rfind("0X", 0) == 0;

        jtype_t jt = JT_UNKNOWN;
        (void)read_runtime(key, row.hex, &jt);
        if (row.inf_index >= 0) {
            const InfKind kind = kInfKeys[row.inf_index].kind;
            row.is_bool = kind == InfKind::Bit || kind == InfKind::BitInverted;
            row.is_string = kind == InfKind::String;
        } else if (jt == JT_BOOL) {
            row.is_bool = true;
        } else if (jt == JT_STR) {
            row.is_string = true;
        } else if (jt == JT_UNKNOWN) {
            row.is_bool = is_bool_text(sample);
            row.is_string = is_single_string(sample);
        }
        row.is_list = e.terminated && !row.is_bool && !row.is_string && !is_number_text(sample);

        if (row.file == "idagui.cfg")
            row.writable = gui ? 1 : 0;   // idalib does not take the GUI's keys
        else if (row.file == "hexrays.cfg")
            row.writable = hexrays ? 1 : 0;
        else
            row.writable = 1;

        refresh(row);
        rows.push_back(std::move(row));
    }
}

// ---------------------------------------------------------------------------
// Writing

// IDA's warning boxes, captured and kept off the screen while a directive runs.
struct WarningCapture : public event_listener_t {
    std::vector<std::string> boxes;

    ssize_t idaapi on_event(ssize_t code, va_list va) override {
        if (code != ui_mbox) return 0;
        (void)va_arg(va, int);  // mbox_kind_t
        const char* format = va_arg(va, const char*);
        if (format == nullptr) return 0;
        va_list copy;
#if defined(__x86_64__) && !defined(_MSC_VER)
        va_list* format_args = va_arg(va, va_list*);
        va_copy(copy, *format_args);
#else
        va_list format_args = va_arg(va, va_list);
        va_copy(copy, format_args);
#endif
        qstring text;
        text.vsprnt(format, copy);
        va_end(copy);
        boxes.push_back(text.c_str());
        return 1;
    }
};

// The warning text without its display prefix and the echoed directive.
std::string warning_text(const std::vector<std::string>& boxes, const std::string& directive) {
    std::string out;
    for (const auto& box : boxes) {
        size_t start = 0;
        while (start <= box.size()) {
            size_t end = box.find('\n', start);
            if (end == std::string::npos) end = box.size();
            const std::string line = trim(box.substr(start, end - start));
            if (!line.empty() && line.rfind("AUTOHIDE", 0) != 0 && line != directive) {
                if (!out.empty()) out += " ";
                out += line;
            }
            start = end + 1;
        }
    }
    return out;
}

// The value IDA applied when it clamped a number: its warning names the bound,
// "number 99999 is too high (must be at most 1023)" / "... too low (must be at
// least 32)". Empty when the warning names none.
std::string clamp_bound(const std::string& warning) {
    for (const char* marker : {"must be at most ", "must be at least "}) {
        const size_t at = warning.find(marker);
        if (at == std::string::npos)
            continue;
        size_t i = at + std::strlen(marker);
        size_t j = i;
        if (j < warning.size() && warning[j] == '-')
            ++j;
        while (j < warning.size() && std::isxdigit(static_cast<unsigned char>(warning[j])) != 0)
            ++j;
        if (j < warning.size() && (warning[j] == 'x' || warning[j] == 'X')) {  // 0x...
            ++j;
            while (j < warning.size() && std::isxdigit(static_cast<unsigned char>(warning[j])) != 0)
                ++j;
        }
        return warning.substr(i, j - i);
    }
    return {};
}

// What a value holds outside its string literals. IDA's directive parser stops
// (and, per idacfg.hpp, may exit) on lexical errors, so idasql sends only one
// well-formed directive and leaves type and range judgement to IDA.
struct ValueScan {
    bool open_string = false;  // a '"' without its closing '"' (or a trailing '\')
    int depth = 0;             // {[( minus )]} outside strings
    bool bad_depth = false;    // a closer before its opener
    bool equals = false;
    bool semicolon = false;
    bool comment = false;      // /* or //
};

ValueScan scan_value(const std::string& s) {
    ValueScan r;
    bool in_str = false;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (in_str) {
            if (c == '\\') {
                if (++i >= s.size()) break;  // a trailing backslash escapes nothing
            } else if (c == '"') {
                in_str = false;
            }
            continue;
        }
        if (c == '"') in_str = true;
        else if (c == '=') r.equals = true;
        else if (c == ';') r.semicolon = true;
        else if (c == '/' && i + 1 < s.size() && (s[i + 1] == '*' || s[i + 1] == '/')) r.comment = true;
        else if (c == '{' || c == '[' || c == '(') ++r.depth;
        else if (c == '}' || c == ']' || c == ')') {
            if (--r.depth < 0) r.bad_depth = true;
        }
    }
    r.open_string = in_str;
    return r;
}

// The directive value for `requested`, or an error.
bool directive_value(const ConfigRow& row, const std::string& requested,
                     std::string* out, std::string* error) {
    std::string v = trim(requested);
    if (v.empty()) {
        *error = "a value is required";
        return false;
    }
    if (v.find_first_of(std::string("\r\n\0", 3)) != std::string::npos) {
        *error = "the value must be one line";
        return false;
    }
    if (row.is_bool) {
        const std::string u = upper(v);
        if (u == "YES" || u == "ON" || u == "TRUE" || u == "1") v = "YES";
        else if (u == "NO" || u == "OFF" || u == "FALSE" || u == "0") v = "NO";
        else {
            *error = "expects YES or NO";
            return false;
        }
    } else if (row.is_string && v.front() != '"') {
        v = quote(v);
    }
    const ValueScan sc = scan_value(v);
    if (sc.open_string) {
        *error = "unterminated string (a \" without its closing \")";
        return false;
    }
    if (row.is_string && !is_single_string(v)) {
        *error = "expects one string literal";
        return false;
    }
    if (sc.equals) {
        *error = "an unquoted '=' would start another directive";
        return false;
    }
    if (sc.comment) {
        *error = "a comment is not allowed in a value";
        return false;
    }
    if (!row.is_list && sc.semicolon) {
        *error = "an unquoted ';' would end the directive";
        return false;
    }
    if (sc.bad_depth || sc.depth != 0) {
        *error = "unbalanced brackets";
        return false;
    }
    if (row.is_list && v.back() != ';') v += ";";
    *out = v;
    return true;
}

bool apply_value(ConfigRow& row, xsql::FunctionArg value) {
    if (value.is_nochange()) return true;
    if (value.is_null()) {
        xsql::set_vtab_error("ida_config: " + row.key + " cannot be set to NULL");
        return false;
    }
    if (!row.writable) {
        xsql::set_vtab_error(
            "ida_config: " + row.key + " (" + row.file + ") cannot be changed here: " +
            (row.file == "idagui.cfg" ? std::string("only the IDA GUI takes idagui.cfg keys")
                                      : std::string("the decompiler is not available")));
        return false;
    }
    const char* p = value.as_c_str();
    const std::string requested(p ? p : "", p ? static_cast<size_t>(value.bytes()) : 0);
    std::string v, error;
    if (!directive_value(row, requested, &v, &error)) {
        xsql::set_vtab_error("ida_config: " + row.key + ": " + error);
        return false;
    }

    const std::string directive = row.key + "=" + v;
    WarningCapture capture;
    hook_event_listener(HT_UI, &capture, nullptr);
    process_config_directive(directive.c_str());
    unhook_event_listener(HT_UI, &capture);
    if (row.file == "hexrays.cfg" && decompiler::hexrays_available())
        clear_cached_cfuncs();  // later pseudocode follows the new option

    const std::string warning = warning_text(capture.boxes, directive);
    const bool clamped = warning.find("too high") != std::string::npos ||
                         warning.find("too low") != std::string::npos;
    if (warning.empty()) session_messages().erase(row.key);
    else session_messages()[row.key] = warning;
    if (warning.empty() || clamped) {
        // A value IDA cannot read back is remembered as applied: as written, or
        // for a clamp, the bound IDA's warning names (the message keeps the warning).
        if (row.inf_index < 0 && !read_runtime(row.key, row.hex, nullptr)) {
            const std::string bound = clamped ? clamp_bound(warning) : std::string();
            session_values()[row.key] = !bound.empty() ? bound
                                      : v.back() == ';' && row.is_list ? v.substr(0, v.size() - 1) : v;
        }
        refresh(row);
        return true;
    }

    refresh(row);
    std::string msg = "ida_config: IDA refused " + directive + ": " + warning;
    if (row.value_source == "runtime" || row.value_source == "inf")
        msg += " (the value is now " + row.value.value_or("NULL") + ")";
    xsql::set_vtab_error(msg);
    return false;
}

} // namespace

CachedTableDef<ConfigRow> define_ida_config() {
    return cached_table<ConfigRow>("ida_config")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 200; })
        .cache_builder([](std::vector<ConfigRow>& rows) { collect_config_rows(rows); })
        .column_text("key", [](const ConfigRow& row) -> std::string { return row.key; })
        .column_text("file", [](const ConfigRow& row) -> std::string { return row.file; })
        .column_text_nullable_rw(
            "value",
            [](const ConfigRow& row) -> std::optional<std::string> { return row.value; },
            [](ConfigRow& row, xsql::FunctionArg value) -> bool { return apply_value(row, value); })
        .column_text("value_source", [](const ConfigRow& row) -> std::string { return row.value_source; })
        .column_int("writable", [](const ConfigRow& row) -> int { return row.writable; })
        .column_int("persisted", [](const ConfigRow& row) -> int { return row.persisted; })
        .column_text_nullable("message",
            [](const ConfigRow& row) -> std::optional<std::string> { return row.message; })
        .build();
}

} // namespace metadata
} // namespace idasql
