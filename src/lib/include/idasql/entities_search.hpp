/**
 * entities_search.hpp - Grep-style entity search table
 *
 * Usage:
 *   SELECT name, kind FROM grep WHERE pattern = 'main' LIMIT 20;
 *   SELECT * FROM grep WHERE pattern = 'sub%' AND kind = 'function';
 *
 * Pattern behavior:
 *   - Plain text: case-insensitive contains match (auto '%text%')
 *   - '%' and '_' : SQL LIKE wildcards
 *   - '*' is accepted and normalized to '%'
 */

#pragma once

#include <idasql/platform.hpp>

#include <idasql/vtable.hpp>
#include <xsql/database.hpp>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <memory>
#include <string>

#include <idasql/platform_undef.hpp>

// IDA SDK
#include <ida.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>

namespace idasql {
namespace search {

struct EntityRow {
    std::string name;
    std::string kind;
    ea_t address = BADADDR;
    uint32 ordinal = 0;
    std::string parent_name;
    std::string full_name;
    bool has_address = false;
    bool has_ordinal = false;
};

class NamePattern {
    std::string pattern_;
    bool valid_ = false;

public:
    explicit NamePattern(const std::string& raw) {
        std::string lowered = to_lower(raw);
        std::replace(lowered.begin(), lowered.end(), '*', '%');
        if (lowered.empty()) {
            return;
        }

        if (!has_wildcards(lowered)) {
            // Grep-style default: plain text means "contains".
            lowered = "%" + lowered + "%";
        }

        pattern_ = std::move(lowered);
        valid_ = true;
    }

    bool valid() const { return valid_; }

    bool matches(const std::string& value) const {
        if (!valid_) return false;
        return like_match(to_lower(value), pattern_);
    }

private:
    static std::string to_lower(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        return out;
    }

    static bool has_wildcards(const std::string& s) {
        return s.find('%') != std::string::npos || s.find('_') != std::string::npos;
    }

    // SQL LIKE matcher supporting '%' and '_'
    static bool like_match(const std::string& text, const std::string& pattern) {
        size_t ti = 0;
        size_t pi = 0;
        size_t star = std::string::npos;
        size_t retry = 0;

        while (ti < text.size()) {
            if (pi < pattern.size() && (pattern[pi] == '_' || pattern[pi] == text[ti])) {
                ++ti;
                ++pi;
                continue;
            }
            if (pi < pattern.size() && pattern[pi] == '%') {
                star = pi++;
                retry = ti;
                continue;
            }
            if (star != std::string::npos) {
                pi = star + 1;
                ti = ++retry;
                continue;
            }
            return false;
        }

        while (pi < pattern.size() && pattern[pi] == '%') {
            ++pi;
        }
        return pi == pattern.size();
    }
};

enum class EntitySource {
    Functions = 0,
    Labels,
    Segments,
    Structs,
    Unions,
    Enums,
    Members,
    EnumMembers,
    Done
};

class EntityGenerator {
    NamePattern pattern_;

    EntitySource current_source_ = EntitySource::Functions;
    size_t current_index_ = 0;
    EntityRow current_row_;

    // For type iteration
    uint32 type_ordinal_ = 0;
    size_t member_index_ = 0;
    tinfo_t current_type_;

public:
    explicit EntityGenerator(const std::string& pattern) : pattern_(pattern) {}

    bool next() {
        if (!pattern_.valid()) return false;

        while (current_source_ != EntitySource::Done) {
            if (advance_current_source()) {
                return true;
            }
            current_source_ = static_cast<EntitySource>(static_cast<int>(current_source_) + 1);
            current_index_ = 0;
            type_ordinal_ = 0;
            member_index_ = 0;
        }
        return false;
    }

    const EntityRow& current() const { return current_row_; }

private:
    bool matches(const std::string& name) const {
        return pattern_.matches(name);
    }

    bool advance_current_source() {
        switch (current_source_) {
            case EntitySource::Functions:   return advance_functions();
            case EntitySource::Labels:      return advance_labels();
            case EntitySource::Segments:    return advance_segments();
            case EntitySource::Structs:     return advance_structs();
            case EntitySource::Unions:      return advance_unions();
            case EntitySource::Enums:       return advance_enums();
            case EntitySource::Members:     return advance_members();
            case EntitySource::EnumMembers: return advance_enum_members();
            case EntitySource::Done:        return false;
        }
        return false;
    }

    bool advance_functions() {
        size_t count = get_func_qty();
        while (current_index_ < count) {
            func_t* fn = getn_func(current_index_++);
            if (!fn) continue;

            qstring name;
            if (get_func_name(&name, fn->start_ea) <= 0) continue;

            std::string name_str(name.c_str());
            if (matches(name_str)) {
                current_row_.name = name_str;
                current_row_.kind = "function";
                current_row_.address = fn->start_ea;
                current_row_.has_address = true;
                current_row_.has_ordinal = false;
                current_row_.parent_name.clear();
                current_row_.full_name = name_str;
                return true;
            }
        }
        return false;
    }

    bool advance_labels() {
        size_t count = get_nlist_size();
        while (current_index_ < count) {
            ea_t ea = get_nlist_ea(current_index_);
            const char* name = get_nlist_name(current_index_);
            current_index_++;

            if (!name || !*name) continue;

            func_t* fn = get_func(ea);
            if (fn && fn->start_ea == ea) continue;

            std::string name_str(name);
            if (matches(name_str)) {
                current_row_.name = name_str;
                current_row_.kind = "label";
                current_row_.address = ea;
                current_row_.has_address = true;
                current_row_.has_ordinal = false;
                current_row_.parent_name.clear();
                current_row_.full_name = name_str;
                return true;
            }
        }
        return false;
    }

    bool advance_segments() {
        int count = get_segm_qty();
        while (static_cast<int>(current_index_) < count) {
            segment_t* seg = getnseg(static_cast<int>(current_index_++));
            if (!seg) continue;

            qstring name;
            if (get_segm_name(&name, seg) <= 0) continue;

            std::string name_str(name.c_str());
            if (matches(name_str)) {
                current_row_.name = name_str;
                current_row_.kind = "segment";
                current_row_.address = seg->start_ea;
                current_row_.has_address = true;
                current_row_.has_ordinal = false;
                current_row_.parent_name.clear();
                current_row_.full_name = name_str;
                return true;
            }
        }
        return false;
    }

    bool advance_types_of_kind(const char* kind, bool want_struct, bool want_union, bool want_enum) {
        uint32 count = get_ordinal_count(nullptr);
        while (type_ordinal_ < count) {
            uint32 ord = type_ordinal_++;
            tinfo_t tif;
            if (!tif.get_numbered_type(nullptr, ord)) continue;

            bool is_struct = tif.is_struct();
            bool is_union = tif.is_union();
            bool is_enum = tif.is_enum();

            if (want_struct && !is_struct) continue;
            if (want_union && !is_union) continue;
            if (want_enum && !is_enum) continue;

            qstring name;
            if (!tif.get_type_name(&name)) continue;

            std::string name_str(name.c_str());
            if (matches(name_str)) {
                current_row_.name = name_str;
                current_row_.kind = kind;
                current_row_.has_address = false;
                current_row_.ordinal = ord;
                current_row_.has_ordinal = true;
                current_row_.parent_name.clear();
                current_row_.full_name = name_str;
                return true;
            }
        }
        return false;
    }

    bool advance_structs() { return advance_types_of_kind("struct", true, false, false); }
    bool advance_unions()  { return advance_types_of_kind("union", false, true, false); }
    bool advance_enums()   { return advance_types_of_kind("enum", false, false, true); }

    bool advance_members() {
        uint32 count = get_ordinal_count(nullptr);

        while (type_ordinal_ < count) {
            if (!current_type_.get_numbered_type(nullptr, type_ordinal_)) {
                type_ordinal_++;
                member_index_ = 0;
                continue;
            }

            if (!current_type_.is_struct() && !current_type_.is_union()) {
                type_ordinal_++;
                member_index_ = 0;
                continue;
            }

            udt_type_data_t udt;
            if (!current_type_.get_udt_details(&udt)) {
                type_ordinal_++;
                member_index_ = 0;
                continue;
            }

            while (member_index_ < udt.size()) {
                const udm_t& member = udt[member_index_++];
                std::string member_name(member.name.c_str());

                if (matches(member_name)) {
                    qstring type_name;
                    current_type_.get_type_name(&type_name);

                    current_row_.name = member_name;
                    current_row_.kind = "member";
                    current_row_.has_address = false;
                    current_row_.ordinal = type_ordinal_;
                    current_row_.has_ordinal = true;
                    current_row_.parent_name = type_name.c_str();
                    current_row_.full_name = std::string(type_name.c_str()) + "." + member_name;
                    return true;
                }
            }

            type_ordinal_++;
            member_index_ = 0;
        }
        return false;
    }

    bool advance_enum_members() {
        uint32 count = get_ordinal_count(nullptr);

        while (type_ordinal_ < count) {
            if (!current_type_.get_numbered_type(nullptr, type_ordinal_)) {
                type_ordinal_++;
                member_index_ = 0;
                continue;
            }

            if (!current_type_.is_enum()) {
                type_ordinal_++;
                member_index_ = 0;
                continue;
            }

            enum_type_data_t etd;
            if (!current_type_.get_enum_details(&etd)) {
                type_ordinal_++;
                member_index_ = 0;
                continue;
            }

            while (member_index_ < etd.size()) {
                const edm_t& em = etd[member_index_++];
                std::string value_name(em.name.c_str());

                if (matches(value_name)) {
                    qstring type_name;
                    current_type_.get_type_name(&type_name);

                    current_row_.name = value_name;
                    current_row_.kind = "enum_member";
                    current_row_.has_address = false;
                    current_row_.ordinal = type_ordinal_;
                    current_row_.has_ordinal = true;
                    current_row_.parent_name = type_name.c_str();
                    current_row_.full_name = std::string(type_name.c_str()) + "." + value_name;
                    return true;
                }
            }

            type_ordinal_++;
            member_index_ = 0;
        }
        return false;
    }
};

class GrepIterator : public xsql::RowIterator {
    EntityGenerator generator_;
    bool started_ = false;
    bool valid_ = false;
    int64_t rowid_ = -1;

public:
    explicit GrepIterator(const std::string& pattern)
        : generator_(pattern) {}

    bool next() override {
        started_ = true;
        valid_ = generator_.next();
        if (valid_) {
            ++rowid_;
        }
        return valid_;
    }

    bool eof() const override {
        return started_ && !valid_;
    }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (!valid_) {
            ctx.result_null();
            return;
        }

        const EntityRow& row = generator_.current();
        switch (col) {
            case 0: // pattern (input column)
                ctx.result_null();
                break;
            case 1:
                ctx.result_text(row.name);
                break;
            case 2:
                ctx.result_text(row.kind);
                break;
            case 3:
                if (row.has_address) ctx.result_int64(static_cast<int64_t>(row.address));
                else ctx.result_null();
                break;
            case 4:
                if (row.has_ordinal) ctx.result_int64(row.ordinal);
                else ctx.result_null();
                break;
            case 5:
                if (row.parent_name.empty()) ctx.result_null();
                else ctx.result_text(row.parent_name);
                break;
            case 6:
                ctx.result_text(row.full_name);
                break;
            default:
                ctx.result_null();
                break;
        }
    }

    int64_t rowid() const override {
        return rowid_;
    }
};

inline VTableDef define_grep() {
    return table("grep")
        .count([]() -> size_t {
            // Full scans without a pattern are disabled.
            return 0;
        })
        // Required filter input.
        .column_text("pattern", [](size_t) -> std::string { return ""; })
        // Output columns.
        .column_text("name", [](size_t) -> std::string { return ""; })
        .column_text("kind", [](size_t) -> std::string { return ""; })
        .column_int64("address", [](size_t) -> int64_t { return 0; })
        .column_int64("ordinal", [](size_t) -> int64_t { return 0; })
        .column_text("parent_name", [](size_t) -> std::string { return ""; })
        .column_text("full_name", [](size_t) -> std::string { return ""; })
        .filter_eq_text("pattern", [](const char* pattern) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<GrepIterator>(pattern ? pattern : "");
        }, 25.0, 100.0)
        .build();
}

inline bool register_grep_entities(xsql::Database& db) {
    static VTableDef grep = define_grep();
    return db.register_table("ida_grep", &grep) && db.create_table("grep", "ida_grep");
}

} // namespace search
} // namespace idasql
