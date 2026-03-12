// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

#include "entities.hpp"
#include "entities_search.hpp"

#include "decompiler.hpp"

// entities.hpp already includes ida_headers.hpp

namespace idasql {
namespace entities {

// ============================================================================
// Helper: Safe string extraction from IDA
// ============================================================================

std::string safe_func_name(ea_t ea) {
    qstring name;
    get_func_name(&name, ea);
    return std::string(name.c_str());
}

std::string safe_func_prototype(ea_t ea) {
    qstring out;
    if (print_type(&out, ea, PRTYPE_1LINE | PRTYPE_SEMI)) {
        return std::string(out.c_str());
    }
    return "";
}

std::string safe_segm_name(segment_t* seg) {
    if (!seg) return "";
    qstring name;
    get_segm_name(&name, seg);
    return std::string(name.c_str());
}

std::string safe_segm_class(segment_t* seg) {
    if (!seg) return "";
    qstring cls;
    get_segm_class(&cls, seg);
    return std::string(cls.c_str());
}

std::string safe_name(ea_t ea) {
    qstring name;
    get_name(&name, ea);
    return std::string(name.c_str());
}

std::string safe_entry_name(size_t idx) {
    uval_t ord = get_entry_ordinal(idx);
    qstring name;
    get_entry_name(&name, ord);
    return std::string(name.c_str());
}

// ============================================================================
// Function type helpers
// ============================================================================

bool get_func_tinfo(ea_t ea, tinfo_t& tif) {
    return get_tinfo(&tif, ea);
}

const char* get_cc_name(callcnv_t cc) {
    switch (cc) {
        case CM_CC_CDECL:    return "cdecl";
        case CM_CC_STDCALL:  return "stdcall";
        case CM_CC_FASTCALL: return "fastcall";
        case CM_CC_THISCALL: return "thiscall";
        case CM_CC_PASCAL:   return "pascal";
        case CM_CC_SPECIAL:  return "special";
        case CM_CC_SPECIALE: return "speciale";
        case CM_CC_SPECIALP: return "specialp";
        case CM_CC_ELLIPSIS: return "ellipsis";
        default:             return "unknown";
    }
}

// ============================================================================
// Helper: get function type details (rettype, calling conv, etc.)
// ============================================================================

bool get_func_type_details(ea_t ea, func_type_data_t& fi) {
    tinfo_t tif;
    if (!get_func_tinfo(ea, tif) || !tif.is_func()) return false;
    return tif.get_func_details(&fi);
}

// ============================================================================
// FUNCS Table (with UPDATE/DELETE support)
// ============================================================================

CachedTableDef<FuncRow> define_funcs() {
    return cached_table<FuncRow>("funcs")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return get_func_qty(); })
        .cache_builder([](std::vector<FuncRow>& rows) {
            rows.clear();
            const size_t n = get_func_qty();
            rows.reserve(n);
            for (size_t i = 0; i < n; ++i) {
                func_t* f = getn_func(i);
                if (f) rows.push_back({f->start_ea});
            }
        })
        .row_lookup([](FuncRow& row, int64_t rowid) -> bool {
            func_t* f = getn_func(static_cast<size_t>(rowid));
            if (!f) return false;
            row.start_ea = f->start_ea;
            row.original_name = safe_func_name(row.start_ea);
            row.original_prototype = safe_func_prototype(row.start_ea);
            return true;
        })
        .column_int64("address", [](const FuncRow& row) -> int64_t {
            return static_cast<int64_t>(row.start_ea);
        })
        .column_text_rw("name",
            [](const FuncRow& row) -> std::string {
                return safe_func_name(row.start_ea);
            },
            [](FuncRow& row, const char* new_name) -> bool {
                const std::string requested_name = new_name ? new_name : "";
                if (requested_name == row.original_name) {
                    return true;
                }
                auto_wait();
                bool ok = set_name(row.start_ea, requested_name.c_str(), SN_CHECK) != 0;
                if (ok) decompiler::invalidate_decompiler_cache(row.start_ea);
                auto_wait();
                return ok;
            })
        .column_text_rw("prototype",
            [](const FuncRow& row) -> std::string {
                return safe_func_prototype(row.start_ea);
            },
            [](FuncRow& row, xsql::FunctionArg val) -> bool {
                if (val.is_nochange()) {
                    return true;
                }
                const char* new_decl = val.is_null() ? nullptr : val.as_c_str();
                const std::string requested_decl = new_decl ? new_decl : "";
                // no_shared_cache() can replay the pre-update declaration during
                // rename-only updates; treat that exact replay as a no-op.
                if (requested_decl == row.original_prototype) {
                    return true;
                }
                auto_wait();
                bool ok = false;
                if (new_decl == nullptr || new_decl[0] == '\0') {
                    del_tinfo(row.start_ea);
                    ok = true;
                } else {
                    ok = apply_cdecl(nullptr, row.start_ea, new_decl, 0);
                }
                if (ok) decompiler::invalidate_decompiler_cache(row.start_ea);
                auto_wait();
                return ok;
            })
        .column_int64("size", [](const FuncRow& row) -> int64_t {
            func_t* f = get_func(row.start_ea);
            return f ? static_cast<int64_t>(f->size()) : 0;
        })
        .column_int64("end_ea", [](const FuncRow& row) -> int64_t {
            func_t* f = get_func(row.start_ea);
            return f ? static_cast<int64_t>(f->end_ea) : 0;
        })
        .column_int64_rw("flags",
            [](const FuncRow& row) -> int64_t {
                func_t* f = get_func(row.start_ea);
                return f ? static_cast<int64_t>(f->flags) : 0;
            },
            [](FuncRow& row, int64_t new_flags) -> bool {
                func_t* f = get_func(row.start_ea);
                if (!f) return false;
                f->flags = static_cast<ushort>(new_flags);
                bool ok = update_func(f);
                if (ok) decompiler::invalidate_decompiler_cache(row.start_ea);
                return ok;
            })
        // Prototype columns - return type (lazy-computed, cached per row)
        .column_text("return_type", [](const FuncRow& row) -> std::string {
            if (!row.ensure_fi()) return "";
            qstring ret_str;
            row.fi.rettype.print(&ret_str);
            return ret_str.c_str();
        })
        .column_int("return_is_ptr", [](const FuncRow& row) -> int {
            return row.ensure_fi() && row.fi.rettype.is_ptr() ? 1 : 0;
        })
        .column_int("return_is_int", [](const FuncRow& row) -> int {
            return row.ensure_fi() && row.fi.rettype.is_int() ? 1 : 0;
        })
        .column_int("return_is_integral", [](const FuncRow& row) -> int {
            return row.ensure_fi() && row.fi.rettype.is_integral() ? 1 : 0;
        })
        .column_int("return_is_void", [](const FuncRow& row) -> int {
            return row.ensure_fi() && row.fi.rettype.is_void() ? 1 : 0;
        })
        // Prototype columns - arguments
        .column_int("arg_count", [](const FuncRow& row) -> int {
            if (!row.ensure_fi()) return 0;
            return static_cast<int>(row.fi.size());
        })
        .column_text("calling_conv", [](const FuncRow& row) -> std::string {
            if (!row.ensure_fi()) return "";
            return get_cc_name(row.fi.get_cc());
        })
        .deletable([](FuncRow& row) -> bool {
            auto_wait();
            bool ok = del_func(row.start_ea);
            auto_wait();
            return ok;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            // address (col 0) is required
            if (argc < 1 || argv[0].is_null())
                return false;

            ea_t ea = static_cast<ea_t>(argv[0].as_int64());

            // Check if function already exists at this address
            if (get_func(ea) != nullptr)
                return false;

            auto_wait();
            // end_ea from col 4 if provided, else BADADDR (IDA auto-detects)
            ea_t end = BADADDR;
            if (argc > 4 && !argv[4].is_null())
                end = static_cast<ea_t>(argv[4].as_int64());

            bool ok = add_func(ea, end);
            auto_wait();

            if (!ok) return false;

            // Optional: set name (col 1) after creation
            if (argc > 1 && !argv[1].is_null()) {
                const char* name = argv[1].as_c_str();
                if (name && name[0])
                    set_name(ea, name, SN_CHECK);
            }

            return true;
        })
        .build();
}

// ============================================================================
// SEGMENTS Table
// ============================================================================

VTableDef define_segments() {
    return table("segments")
        .count([]() { return static_cast<size_t>(get_segm_qty()); })
        .column_int64("start_ea", [](size_t i) -> int64_t {
            segment_t* s = getnseg(static_cast<int>(i));
            return s ? static_cast<int64_t>(s->start_ea) : 0;
        })
        .column_int64("end_ea", [](size_t i) -> int64_t {
            segment_t* s = getnseg(static_cast<int>(i));
            return s ? static_cast<int64_t>(s->end_ea) : 0;
        })
        .column_text_rw("name",
            // Getter
            [](size_t i) -> std::string {
                segment_t* s = getnseg(static_cast<int>(i));
                return safe_segm_name(s);
            },
            // Setter - rename segment
            [](size_t i, const char* new_name) -> bool {
                auto_wait();
                segment_t* s = getnseg(static_cast<int>(i));
                if (!s) return false;
                bool ok = set_segm_name(s, new_name) != 0;
                auto_wait();
                return ok;
            })
        .column_text_rw("class",
            // Getter
            [](size_t i) -> std::string {
                segment_t* s = getnseg(static_cast<int>(i));
                return safe_segm_class(s);
            },
            // Setter - change segment class
            [](size_t i, const char* new_class) -> bool {
                auto_wait();
                segment_t* s = getnseg(static_cast<int>(i));
                if (!s) return false;
                bool ok = set_segm_class(s, new_class) != 0;
                auto_wait();
                return ok;
            })
        .column_int_rw("perm",
            // Getter
            [](size_t i) -> int {
                segment_t* s = getnseg(static_cast<int>(i));
                return s ? s->perm : 0;
            },
            // Setter - change segment permissions
            [](size_t i, int new_perm) -> bool {
                auto_wait();
                segment_t* s = getnseg(static_cast<int>(i));
                if (!s) return false;
                s->perm = static_cast<uchar>(new_perm);
                bool ok = s->update();
                auto_wait();
                return ok;
            })
        .deletable([](size_t i) -> bool {
            auto_wait();
            segment_t* s = getnseg(static_cast<int>(i));
            if (!s) return false;
            bool ok = del_segm(s->start_ea, SEGMOD_KILL) != 0;
            auto_wait();
            return ok;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            // start_ea (col 0) and end_ea (col 1) are required
            if (argc < 2 || argv[0].is_null() || argv[1].is_null())
                return false;

            ea_t start = static_cast<ea_t>(argv[0].as_int64());
            ea_t end = static_cast<ea_t>(argv[1].as_int64());
            if (start == BADADDR || end == BADADDR || end <= start)
                return false;

            int perm = 0;
            bool has_perm = false;
            if (argc > 4 && !argv[4].is_null()) {
                perm = argv[4].as_int();
                if (perm < 0 || perm > 7)
                    return false;
                has_perm = true;
            }

            // Avoid destructive overlap behavior from add_segm().
            const int seg_qty = get_segm_qty();
            for (int seg_idx = 0; seg_idx < seg_qty; ++seg_idx) {
                segment_t* seg = getnseg(seg_idx);
                if (!seg) continue;
                if (start < seg->end_ea && end > seg->start_ea) {
                    return false;
                }
            }

            const char* seg_name = nullptr;
            if (argc > 2 && !argv[2].is_null()) {
                seg_name = argv[2].as_c_str();
                if (seg_name && seg_name[0] == '\0') seg_name = nullptr;
            }

            const char* seg_class = nullptr;
            if (argc > 3 && !argv[3].is_null()) {
                seg_class = argv[3].as_c_str();
                if (seg_class && seg_class[0] == '\0') seg_class = nullptr;
            }

            const ea_t para = start >> 4;

            auto_wait();
            bool ok = add_segm(para, start, end, seg_name, seg_class, ADDSEG_QUIET | ADDSEG_NOAA);
            if (ok && has_perm) {
                segment_t* created = getseg(start);
                if (created == nullptr) {
                    ok = false;
                } else {
                    created->perm = static_cast<uchar>(perm);
                    ok = created->update();
                }
            }
            auto_wait();
            return ok;
        })
        .build();
}

// ============================================================================
// NAMES Table (with UPDATE/DELETE support)
// ============================================================================

VTableDef define_names() {
    return table("names")
        .count([]() { return get_nlist_size(); })
        .column_int64("address", [](size_t i) -> int64_t {
            return static_cast<int64_t>(get_nlist_ea(i));
        })
        .column_text_rw("name",
            // Getter
            [](size_t i) -> std::string {
                const char* n = get_nlist_name(i);
                return n ? std::string(n) : "";
            },
            // Setter - rename the address
            [](size_t i, const char* new_name) -> bool {
                auto_wait();
                ea_t ea = get_nlist_ea(i);
                if (ea == BADADDR) return false;
                bool ok = set_name(ea, new_name, SN_CHECK) != 0;
                if (ok) decompiler::invalidate_decompiler_cache(ea);
                auto_wait();
                return ok;
            })
        .column_int("is_public", [](size_t i) -> int {
            return is_public_name(get_nlist_ea(i)) ? 1 : 0;
        })
        .column_int("is_weak", [](size_t i) -> int {
            return is_weak_name(get_nlist_ea(i)) ? 1 : 0;
        })
        // DELETE via set_name(ea, "") - removes the name
        .deletable([](size_t i) -> bool {
            auto_wait();
            ea_t ea = get_nlist_ea(i);
            if (ea == BADADDR) return false;
            bool ok = set_name(ea, "", SN_NOWARN) != 0;
            auto_wait();
            return ok;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            // address (col 0) and name (col 1) are both required
            if (argc < 2
                || argv[0].is_null()
                || argv[1].is_null())
                return false;

            ea_t ea = static_cast<ea_t>(argv[0].as_int64());
            const char* name = argv[1].as_c_str();
            if (!name || !name[0]) return false;

            auto_wait();
            bool ok = set_name(ea, name, SN_CHECK) != 0;
            if (ok) decompiler::invalidate_decompiler_cache(ea);
            auto_wait();
            return ok;
        })
        .build();
}

// ============================================================================
// ENTRIES Table (entry points / exports)
// ============================================================================

VTableDef define_entries() {
    return table("entries")
        .count([]() { return get_entry_qty(); })
        .column_int64("ordinal", [](size_t i) -> int64_t {
            return static_cast<int64_t>(get_entry_ordinal(i));
        })
        .column_int64("address", [](size_t i) -> int64_t {
            uval_t ord = get_entry_ordinal(i);
            return static_cast<int64_t>(get_entry(ord));
        })
        .column_text("name", [](size_t i) -> std::string {
            return safe_entry_name(i);
        })
        .build();
}

// ============================================================================
// COMMENTS Table (with UPDATE/DELETE support)
// ============================================================================

void collect_comment_rows(std::vector<CommentRow>& rows) {
    rows.clear();

    ea_t ea = inf_get_min_ea();
    ea_t max_ea = inf_get_max_ea();

    while (ea < max_ea) {
        qstring cmt;
        qstring rpt;
        bool has_cmt = get_cmt(&cmt, ea, false) > 0;
        bool has_rpt = get_cmt(&rpt, ea, true) > 0;

        if (has_cmt || has_rpt) {
            CommentRow row;
            row.ea = ea;
            row.comment = has_cmt ? std::string(cmt.c_str()) : std::string();
            row.rpt_comment = has_rpt ? std::string(rpt.c_str()) : std::string();
            rows.push_back(std::move(row));
        }

        ea = next_head(ea, max_ea);
        if (ea == BADADDR) break;
    }
}

CachedTableDef<CommentRow> define_comments() {
    return cached_table<CommentRow>("comments")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            return static_cast<size_t>(get_nlist_size());
        })
        .cache_builder([](std::vector<CommentRow>& rows) {
            collect_comment_rows(rows);
        })
        .row_populator([](CommentRow& row, int argc, xsql::FunctionArg* argv) {
            // argv[2]=address, argv[3]=comment, argv[4]=rpt_comment
            if (argc > 2) row.ea = static_cast<ea_t>(argv[2].as_int64());
            if (argc > 3 && !argv[3].is_null()) {
                const char* c = argv[3].as_c_str();
                row.comment = c ? c : "";
            }
            if (argc > 4 && !argv[4].is_null()) {
                const char* c = argv[4].as_c_str();
                row.rpt_comment = c ? c : "";
            }
        })
        .column_int64("address", [](const CommentRow& row) -> int64_t {
            return static_cast<int64_t>(row.ea);
        })
        .column_text_rw("comment",
            [](const CommentRow& row) -> std::string {
                return row.comment;
            },
            [](CommentRow& row, const char* new_cmt) -> bool {
                auto_wait();
                bool ok = set_cmt(row.ea, new_cmt ? new_cmt : "", false);
                if (ok) row.comment = new_cmt ? new_cmt : "";
                auto_wait();
                return ok;
            })
        .column_text_rw("rpt_comment",
            [](const CommentRow& row) -> std::string {
                return row.rpt_comment;
            },
            [](CommentRow& row, const char* new_cmt) -> bool {
                auto_wait();
                bool ok = set_cmt(row.ea, new_cmt ? new_cmt : "", true);
                if (ok) row.rpt_comment = new_cmt ? new_cmt : "";
                auto_wait();
                return ok;
            })
        .deletable([](CommentRow& row) -> bool {
            auto_wait();
            set_cmt(row.ea, "", false);
            set_cmt(row.ea, "", true);
            auto_wait();
            return true;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            if (argc < 1 || argv[0].is_null())
                return false;

            ea_t ea = static_cast<ea_t>(argv[0].as_int64());
            bool did_something = false;
            auto_wait();
            if (argc > 1 && !argv[1].is_null()) {
                const char* cmt = argv[1].as_c_str();
                if (cmt) {
                    set_cmt(ea, cmt, false);
                    did_something = true;
                }
            }
            if (argc > 2 && !argv[2].is_null()) {
                const char* rpt = argv[2].as_c_str();
                if (rpt) {
                    set_cmt(ea, rpt, true);
                    did_something = true;
                }
            }

            auto_wait();
            return did_something;
        })
        .build();
}

// ============================================================================
// IMPORTS Table
// ============================================================================

std::string get_import_module_name_safe(int idx) {
    qstring name;
    get_import_module_name(&name, idx);
    return std::string(name.c_str());
}

// ============================================================================
// STRING helpers
// ============================================================================

int get_string_width(int strtype) {
    return strtype & 0x03;  // 0=ASCII, 1=UTF-16, 2=UTF-32
}

const char* get_string_width_name(int strtype) {
    int width = get_string_width(strtype);
    switch (width) {
        case 0: return "1-byte";
        case 1: return "2-byte";
        case 2: return "4-byte";
        default: return "unknown";
    }
}

const char* get_string_type_name(int strtype) {
    int width = get_string_width(strtype);
    switch (width) {
        case 0: return "ascii";
        case 1: return "utf16";
        case 2: return "utf32";
        default: return "unknown";
    }
}

int get_string_layout(int strtype) {
    return (strtype >> 2) & 0x3F;  // Bits 2-7
}

const char* get_string_layout_name(int strtype) {
    int layout = get_string_layout(strtype);
    switch (layout) {
        case 0: return "termchr";    // Null-terminated (C-style)
        case 1: return "pascal1";    // 1-byte length prefix
        case 2: return "pascal2";    // 2-byte length prefix
        case 3: return "pascal4";    // 4-byte length prefix
        default: return "unknown";
    }
}

int get_string_encoding(int strtype) {
    return (strtype >> 24) & 0xFF;  // Bits 24-31: encoding index
}

std::string get_string_content(const string_info_t& si) {
    qstring content;
    get_strlit_contents(&content, si.ea, si.length, si.type);
    return std::string(content.c_str());
}

// ============================================================================
// Xref Iterators
// ============================================================================

XrefsToIterator::XrefsToIterator(ea_t target) : target_(target) {}

bool XrefsToIterator::next() {
    if (!started_) {
        started_ = true;
        valid_ = xb_.first_to(target_, XREF_ALL);
    } else if (valid_) {
        valid_ = xb_.next_to();
    }
    return valid_;
}

bool XrefsToIterator::eof() const {
    return started_ && !valid_;
}

void XrefsToIterator::column(xsql::FunctionContext& ctx, int col) {
    if (!valid_) {
        ctx.result_null();
        return;
    }
    switch (col) {
        case 0: ctx.result_int64(static_cast<int64_t>(xb_.from)); break;
        case 1: ctx.result_int64(static_cast<int64_t>(target_)); break;
        case 2: ctx.result_int(xb_.type); break;
        case 3: ctx.result_int(xb_.iscode ? 1 : 0); break;
        default: ctx.result_null(); break;
    }
}

int64_t XrefsToIterator::rowid() const {
    return valid_ ? static_cast<int64_t>(xb_.from) : 0;
}

XrefsFromIterator::XrefsFromIterator(ea_t source) : source_(source) {}

bool XrefsFromIterator::next() {
    if (!started_) {
        started_ = true;
        valid_ = xb_.first_from(source_, XREF_ALL);
    } else if (valid_) {
        valid_ = xb_.next_from();
    }
    return valid_;
}

bool XrefsFromIterator::eof() const {
    return started_ && !valid_;
}

void XrefsFromIterator::column(xsql::FunctionContext& ctx, int col) {
    if (!valid_) {
        ctx.result_null();
        return;
    }
    switch (col) {
        case 0: ctx.result_int64(static_cast<int64_t>(source_)); break;
        case 1: ctx.result_int64(static_cast<int64_t>(xb_.to)); break;
        case 2: ctx.result_int(xb_.type); break;
        case 3: ctx.result_int(xb_.iscode ? 1 : 0); break;
        default: ctx.result_null(); break;
    }
}

int64_t XrefsFromIterator::rowid() const {
    return valid_ ? static_cast<int64_t>(xb_.to) : 0;
}

// ============================================================================
// XREFS Table
// ============================================================================

CachedTableDef<XrefInfo> define_xrefs() {
    return cached_table<XrefInfo>("xrefs")
        .no_shared_cache()
        // Estimate row count without building cache
        .estimate_rows([]() -> size_t {
            // Heuristic: ~10 xrefs per function on average
            return get_func_qty() * 10;
        })
        // Cache builder (called lazily, only if pushdown doesn't handle query)
        .cache_builder([](std::vector<XrefInfo>& cache) {
            size_t func_qty = get_func_qty();
            for (size_t i = 0; i < func_qty; i++) {
                func_t* func = getn_func(i);
                if (!func) continue;

                // Xrefs TO this function
                xrefblk_t xb;
                for (bool ok = xb.first_to(func->start_ea, XREF_ALL); ok; ok = xb.next_to()) {
                    XrefInfo xi;
                    xi.from_ea = xb.from;
                    xi.to_ea = func->start_ea;
                    xi.type = xb.type;
                    xi.is_code = xb.iscode;
                    cache.push_back(xi);
                }
            }
        })
        // Column accessors take const XrefInfo& directly
        .column_int64("from_ea", [](const XrefInfo& r) -> int64_t {
            return static_cast<int64_t>(r.from_ea);
        })
        .column_int64("to_ea", [](const XrefInfo& r) -> int64_t {
            return static_cast<int64_t>(r.to_ea);
        })
        .column_int("type", [](const XrefInfo& r) -> int {
            return static_cast<int>(r.type);
        })
        .column_int("is_code", [](const XrefInfo& r) -> int {
            return r.is_code ? 1 : 0;
        })
        // Constraint pushdown filters (same iterators as V1)
        .filter_eq("to_ea", [](int64_t target) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<XrefsToIterator>(static_cast<ea_t>(target));
        }, 10.0, 5.0)
        .filter_eq("from_ea", [](int64_t source) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<XrefsFromIterator>(static_cast<ea_t>(source));
        }, 10.0, 5.0)
        .build();
}

// ============================================================================
// BLOCKS Table (basic blocks)
// ============================================================================

BlocksInFuncIterator::BlocksInFuncIterator(ea_t func_ea) : func_ea_(func_ea) {
    func_t* pfn = get_func(func_ea);
    if (pfn) {
        fc_.create("", pfn, pfn->start_ea, pfn->end_ea, FC_NOEXT);
    }
}

bool BlocksInFuncIterator::next() {
    ++idx_;
    valid_ = (idx_ < fc_.size());
    return valid_;
}

bool BlocksInFuncIterator::eof() const {
    return idx_ >= 0 && !valid_;
}

void BlocksInFuncIterator::column(xsql::FunctionContext& ctx, int col) {
    if (!valid_ || idx_ < 0 || idx_ >= fc_.size()) {
        ctx.result_null();
        return;
    }
    const qbasic_block_t& bb = fc_.blocks[idx_];
    switch (col) {
        case 0: ctx.result_int64(static_cast<int64_t>(func_ea_)); break;
        case 1: ctx.result_int64(static_cast<int64_t>(bb.start_ea)); break;
        case 2: ctx.result_int64(static_cast<int64_t>(bb.end_ea)); break;
        case 3: ctx.result_int64(static_cast<int64_t>(bb.end_ea - bb.start_ea)); break;
        default: ctx.result_null(); break;
    }
}

int64_t BlocksInFuncIterator::rowid() const {
    if (!valid_ || idx_ < 0 || idx_ >= fc_.size()) return 0;
    return static_cast<int64_t>(fc_.blocks[idx_].start_ea);
}

CachedTableDef<BlockInfo> define_blocks() {
    return cached_table<BlockInfo>("blocks")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            // Heuristic: ~10 blocks per function
            return get_func_qty() * 10;
        })
        .cache_builder([](std::vector<BlockInfo>& cache) {
            size_t func_qty = get_func_qty();
            for (size_t i = 0; i < func_qty; i++) {
                func_t* func = getn_func(i);
                if (!func) continue;

                qflow_chart_t fc;
                fc.create("", func, func->start_ea, func->end_ea, FC_NOEXT);

                for (int j = 0; j < fc.size(); j++) {
                    const qbasic_block_t& bb = fc.blocks[j];
                    BlockInfo bi;
                    bi.func_ea = func->start_ea;
                    bi.start_ea = bb.start_ea;
                    bi.end_ea = bb.end_ea;
                    cache.push_back(bi);
                }
            }
        })
        .column_int64("func_ea", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.func_ea);
        })
        .column_int64("start_ea", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.start_ea);
        })
        .column_int64("end_ea", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.end_ea);
        })
        .column_int64("size", [](const BlockInfo& r) -> int64_t {
            return static_cast<int64_t>(r.end_ea - r.start_ea);
        })
        .filter_eq("func_ea", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<BlocksInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 10.0, 10.0)
        .build();
}

// ============================================================================
// IMPORTS Table (query-scoped cache)
// ============================================================================

CachedTableDef<ImportInfo> define_imports() {
    return cached_table<ImportInfo>("imports")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            // Estimate: ~100 imports per module
            return get_import_module_qty() * 100;
        })
        .cache_builder([](std::vector<ImportInfo>& cache) {
            uint mod_qty = get_import_module_qty();
            for (uint m = 0; m < mod_qty; m++) {
                ImportEnumContext ctx;
                ctx.cache = &cache;
                ctx.module_idx = static_cast<int>(m);

                enum_import_names(m, [](ea_t ea, const char* name, uval_t ord, void* param) -> int {
                    auto* ctx = static_cast<ImportEnumContext*>(param);
                    ImportInfo info;
                    info.module_idx = ctx->module_idx;
                    info.ea = ea;
                    info.name = name ? name : "";
                    info.ord = ord;
                    ctx->cache->push_back(info);
                    return 1;  // continue enumeration
                }, &ctx);
            }
        })
        .column_int64("address", [](const ImportInfo& r) -> int64_t {
            return static_cast<int64_t>(r.ea);
        })
        .column_text("name", [](const ImportInfo& r) -> std::string {
            return r.name;
        })
        .column_int64("ordinal", [](const ImportInfo& r) -> int64_t {
            return static_cast<int64_t>(r.ord);
        })
        .column_text("module", [](const ImportInfo& r) -> std::string {
            return get_import_module_name_safe(r.module_idx);
        })
        .column_int("module_idx", [](const ImportInfo& r) -> int {
            return r.module_idx;
        })
        .build();
}

// ============================================================================
// STRINGS Table (query-scoped cache)
// ============================================================================

CachedTableDef<string_info_t> define_strings() {
    return cached_table<string_info_t>("strings")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            return get_strlist_qty();
        })
        .cache_builder([](std::vector<string_info_t>& cache) {
            size_t n = get_strlist_qty();
            for (size_t i = 0; i < n; i++) {
                string_info_t si;
                if (get_strlist_item(&si, i)) {
                    cache.push_back(si);
                }
            }
        })
        .column_int64("address", [](const string_info_t& r) -> int64_t {
            return static_cast<int64_t>(r.ea);
        })
        .column_int("length", [](const string_info_t& r) -> int {
            return static_cast<int>(r.length);
        })
        .column_int("type", [](const string_info_t& r) -> int {
            return static_cast<int>(r.type);
        })
        .column_text("type_name", [](const string_info_t& r) -> std::string {
            return get_string_type_name(r.type);
        })
        .column_int("width", [](const string_info_t& r) -> int {
            return get_string_width(r.type);
        })
        .column_text("width_name", [](const string_info_t& r) -> std::string {
            return get_string_width_name(r.type);
        })
        .column_int("layout", [](const string_info_t& r) -> int {
            return get_string_layout(r.type);
        })
        .column_text("layout_name", [](const string_info_t& r) -> std::string {
            return get_string_layout_name(r.type);
        })
        .column_int("encoding", [](const string_info_t& r) -> int {
            return get_string_encoding(r.type);
        })
        .column_text("content", [](const string_info_t& r) -> std::string {
            return get_string_content(r);
        })
        .build();
}

// ============================================================================
// BOOKMARKS Table (with UPDATE/DELETE support)
// ============================================================================

void collect_bookmark_rows(std::vector<BookmarkRow>& rows) {
    rows.clear();

    idaplace_t idaplace(inf_get_min_ea(), 0);
    renderer_info_t rinfo;
    lochist_entry_t loc(&idaplace, rinfo);
    uint32_t count = bookmarks_t::size(loc, nullptr);

    for (uint32_t idx = 0; idx < count; ++idx) {
        idaplace_t place(0, 0);
        lochist_entry_t entry(&place, rinfo);
        qstring desc;
        uint32_t index = idx;
        if (bookmarks_t::get(&entry, &desc, &index, nullptr)) {
            BookmarkRow row;
            row.index = index;
            row.ea = static_cast<idaplace_t*>(entry.place())->ea;
            row.desc = desc.c_str();
            rows.push_back(std::move(row));
        }
    }
}

CachedTableDef<BookmarkRow> define_bookmarks() {
    return cached_table<BookmarkRow>("bookmarks")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            return 1024;
        })
        .cache_builder([](std::vector<BookmarkRow>& rows) {
            collect_bookmark_rows(rows);
        })
        .row_populator([](BookmarkRow& row, int argc, xsql::FunctionArg* argv) {
            // argv[2]=slot, argv[3]=address, argv[4]=description
            if (argc > 2 && !argv[2].is_null()) row.index = static_cast<uint32_t>(argv[2].as_int());
            if (argc > 3 && !argv[3].is_null()) row.ea = static_cast<ea_t>(argv[3].as_int64());
            if (argc > 4 && !argv[4].is_null()) {
                const char* d = argv[4].as_c_str();
                row.desc = d ? d : "";
            }
        })
        .column_int("slot", [](const BookmarkRow& row) -> int {
            return static_cast<int>(row.index);
        })
        .column_int64("address", [](const BookmarkRow& row) -> int64_t {
            return static_cast<int64_t>(row.ea);
        })
        .column_text_rw("description",
            [](const BookmarkRow& row) -> std::string {
                return row.desc;
            },
            [](BookmarkRow& row, const char* new_desc) -> bool {
                auto_wait();
                idaplace_t place(row.ea, 0);
                renderer_info_t rinfo;
                lochist_entry_t loc(&place, rinfo);
                bool ok = bookmarks_t_set_desc(qstring(new_desc ? new_desc : ""), loc, row.index, nullptr);
                if (ok) row.desc = new_desc ? new_desc : "";
                auto_wait();
                return ok;
            })
        .deletable([](BookmarkRow& row) -> bool {
            auto_wait();
            idaplace_t place(row.ea, 0);
            renderer_info_t rinfo;
            lochist_entry_t loc(&place, rinfo);
            bool ok = bookmarks_t::erase(loc, row.index, nullptr);
            auto_wait();
            return ok;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            if (argc < 2 || argv[1].is_null())
                return false;

            ea_t ea = static_cast<ea_t>(argv[1].as_int64());

            const char* desc = "";
            if (argc > 2 && !argv[2].is_null()) {
                desc = argv[2].as_c_str();
                if (!desc) desc = "";
            }

            auto_wait();

            idaplace_t place(ea, 0);
            renderer_info_t rinfo;
            lochist_entry_t loc(&place, rinfo);

            uint32_t slot = bookmarks_t::size(loc, nullptr);
            if (argc > 0 && !argv[0].is_null())
                slot = static_cast<uint32_t>(argv[0].as_int());

            uint32_t result = bookmarks_t::mark(loc, slot, nullptr, desc, nullptr);
            auto_wait();

            return result != BADADDR32;
        })
        .build();
}

// ============================================================================
// HEADS Table - All defined items in the database
// ============================================================================

void collect_head_rows(std::vector<HeadRow>& rows) {
    rows.clear();

    ea_t ea = inf_get_min_ea();
    ea_t max_ea = inf_get_max_ea();

    while (ea < max_ea && ea != BADADDR) {
        rows.push_back({ea});
        ea = next_head(ea, max_ea);
    }
}

const char* get_item_type_str(ea_t ea) {
    flags64_t f = get_flags(ea);
    if (is_code(f)) return "code";
    if (is_strlit(f)) return "string";
    if (is_struct(f)) return "struct";
    if (is_align(f)) return "align";
    if (is_data(f)) return "data";
    if (is_unknown(f)) return "unknown";
    return "other";
}

CachedTableDef<HeadRow> define_heads() {
    return cached_table<HeadRow>("heads")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            return static_cast<size_t>(get_nlist_size());
        })
        .cache_builder([](std::vector<HeadRow>& rows) {
            collect_head_rows(rows);
        })
        .column_int64("address", [](const HeadRow& row) -> int64_t {
            return static_cast<int64_t>(row.ea);
        })
        .column_int64("size", [](const HeadRow& row) -> int64_t {
            return static_cast<int64_t>(get_item_size(row.ea));
        })
        .column_text("type", [](const HeadRow& row) -> std::string {
            return get_item_type_str(row.ea);
        })
        .column_int64("flags", [](const HeadRow& row) -> int64_t {
            return static_cast<int64_t>(get_flags(row.ea));
        })
        .column_text("disasm", [](const HeadRow& row) -> std::string {
            qstring line;
            generate_disasm_line(&line, row.ea, GENDSM_FORCE_CODE);
            tag_remove(&line);
            return line.c_str();
        })
        .build();
}

// ============================================================================
// BYTES Table - Read/write byte values with patch support
// ============================================================================

BytesAtIterator::BytesAtIterator(ea_t ea) : ea_(ea) {}

bool BytesAtIterator::next() {
    if (yielded_) {
        // Second call - exhausted
        exhausted_ = true;
        return false;
    }
    // First call - yield the single row
    yielded_ = true;
    return true;
}

bool BytesAtIterator::eof() const { return exhausted_; }

void BytesAtIterator::column(xsql::FunctionContext& ctx, int col) {
    switch (col) {
        case 0: // ea
            ctx.result_int64(ea_);
            break;
        case 1: // value
            ctx.result_int(get_byte(ea_));
            break;
        case 2: // original_value
            ctx.result_int(static_cast<int>(get_original_byte(ea_)));
            break;
        case 3: // size
            ctx.result_int(static_cast<int>(get_item_size(ea_)));
            break;
        case 4: // type
            ctx.result_text(get_item_type_str(ea_));
            break;
        case 5: { // is_patched
            int patched = (get_byte(ea_) != static_cast<uchar>(get_original_byte(ea_))) ? 1 : 0;
            ctx.result_int(patched);
            break;
        }
        case 6: { // fpos
            const qoff64_t fpos = get_fileregion_offset(ea_);
            if (fpos < 0) ctx.result_null();
            else ctx.result_int64(static_cast<int64_t>(fpos));
            break;
        }
    }
}

int64_t BytesAtIterator::rowid() const { return static_cast<int64_t>(ea_); }

CachedTableDef<HeadRow> define_bytes() {
    return cached_table<HeadRow>("bytes")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            return static_cast<size_t>(get_nlist_size());
        })
        .cache_builder([](std::vector<HeadRow>& rows) {
            collect_head_rows(rows);
        })
        .row_populator([](HeadRow& row, int argc, xsql::FunctionArg* argv) {
            // argv[2] = ea, argv[3] = value, ...
            if (argc > 2) row.ea = static_cast<ea_t>(argv[2].as_int64());
        })
        .column_int64("ea", [](const HeadRow& row) -> int64_t {
            return static_cast<int64_t>(row.ea);
        })
        .column_int_rw("value",
            [](const HeadRow& row) -> int {
                return get_byte(row.ea);
            },
            [](HeadRow& row, int val) -> bool {
                return patch_byte(row.ea, static_cast<uint64>(val));
            })
        .column_int("original_value", [](const HeadRow& row) -> int {
            return static_cast<int>(get_original_byte(row.ea));
        })
        .column_int("size", [](const HeadRow& row) -> int {
            return static_cast<int>(get_item_size(row.ea));
        })
        .column_text("type", [](const HeadRow& row) -> std::string {
            return get_item_type_str(row.ea);
        })
        .column_int("is_patched", [](const HeadRow& row) -> int {
            return (get_byte(row.ea) != static_cast<uchar>(get_original_byte(row.ea))) ? 1 : 0;
        })
        .column("fpos", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const HeadRow& row) {
                const qoff64_t fpos = get_fileregion_offset(row.ea);
                if (fpos < 0) ctx.result_null();
                else ctx.result_int64(static_cast<int64_t>(fpos));
            })
        .filter_eq("ea", [](int64_t ea_val) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<BytesAtIterator>(static_cast<ea_t>(ea_val));
        }, 1.0)
        .build();
}

// ============================================================================
// PATCHED_BYTES Table - All patched locations via visit_patched_bytes()
// ============================================================================

// Callback for visit_patched_bytes (requires idaapi calling convention)
int idaapi patched_bytes_visitor(ea_t ea, qoff64_t fpos, uint64 o, uint64 v, void* ud) {
    auto* vec = static_cast<std::vector<PatchedByteInfo>*>(ud);
    vec->push_back({ea, fpos, o, v});
    return 0; // continue
}

CachedTableDef<PatchedByteInfo> define_patched_bytes() {
    return cached_table<PatchedByteInfo>("patched_bytes")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            return 1024;
        })
        .cache_builder([](std::vector<PatchedByteInfo>& rows) {
            rows.clear();
            visit_patched_bytes(0, BADADDR, patched_bytes_visitor, &rows);
        })
        .column_int64("ea", [](const PatchedByteInfo& row) -> int64_t {
            return static_cast<int64_t>(row.ea);
        })
        .column_int("original_value", [](const PatchedByteInfo& row) -> int {
            return static_cast<int>(row.original_value);
        })
        .column_int("patched_value", [](const PatchedByteInfo& row) -> int {
            return static_cast<int>(row.patched_value);
        })
        .column_int64("fpos", [](const PatchedByteInfo& row) -> int64_t {
            return static_cast<int64_t>(row.fpos);
        })
        .build();
}

// ============================================================================
// INSTRUCTIONS Table helpers and parsing
// ============================================================================

// trim_copy is now in <idasql/string_utils.hpp>

bool starts_with_ci(const std::string& text, const char* prefix) {
    if (!prefix) return false;
    const size_t prefix_len = std::strlen(prefix);
    if (text.size() < prefix_len) return false;
    for (size_t i = 0; i < prefix_len; ++i) {
        const unsigned char a = static_cast<unsigned char>(text[i]);
        const unsigned char b = static_cast<unsigned char>(prefix[i]);
        if (std::tolower(a) != std::tolower(b)) return false;
    }
    return true;
}

bool equals_ci(const std::string& text, const char* token) {
    if (!token) return false;
    const size_t token_len = std::strlen(token);
    if (text.size() != token_len) return false;
    return starts_with_ci(text, token);
}

bool parse_int64(const std::string& text, int64_t& out_value) {
    const std::string trimmed = trim_copy(text);
    if (trimmed.empty()) return false;
    char* end_ptr = nullptr;
    const long long value = std::strtoll(trimmed.c_str(), &end_ptr, 0);
    if (end_ptr == nullptr || *end_ptr != '\0') return false;
    out_value = static_cast<int64_t>(value);
    return true;
}

bool resolve_named_type_tid(const std::string& name, tid_t& out_tid, tinfo_t* out_tif) {
    if (name.empty()) return false;
    tinfo_t tif;
    if (!tif.get_named_type(nullptr, name.c_str())) {
        return false;
    }
    const tid_t tid = tif.get_tid();
    if (tid == BADNODE) {
        return false;
    }
    if (out_tif) {
        *out_tif = tif;
    }
    out_tid = tid;
    return true;
}

std::string tid_name_or_fallback(tid_t tid) {
    qstring out;
    if (get_tid_name(&out, tid)) {
        return std::string(out.c_str());
    }
    return "";
}

void split_path_names(const std::string& path_spec, std::vector<std::string>& out_names) {
    out_names.clear();
    size_t start = 0;
    while (start <= path_spec.size()) {
        const size_t slash = path_spec.find('/', start);
        const size_t end = (slash == std::string::npos) ? path_spec.size() : slash;
        std::string piece = trim_copy(path_spec.substr(start, end - start));
        if (!piece.empty()) {
            out_names.push_back(piece);
        }
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
}

bool parse_operand_format_spec(const char* spec, OperandApplyRequest& out, std::string* out_error) {
    if (out_error) out_error->clear();
    out = OperandApplyRequest{};
    if (!spec) {
        if (out_error) *out_error = "format spec is required";
        return false;
    }

    const std::string text = trim_copy(spec);
    if (text.empty()) {
        if (out_error) *out_error = "format spec is empty";
        return false;
    }

    if (equals_ci(text, "clear") || equals_ci(text, "plain") || equals_ci(text, "none")) {
        out.kind = OperandApplyKind::Clear;
        return true;
    }

    if (starts_with_ci(text, "enum:")) {
        const std::string rest = trim_copy(text.substr(5));
        if (rest.empty()) {
            if (out_error) *out_error = "enum spec requires a type name";
            return false;
        }

        std::string enum_name = rest;
        std::string member_name;
        uchar serial = 0;
        bool has_serial = false;

        const size_t serial_pos = rest.find(",serial=");
        if (serial_pos != std::string::npos) {
            enum_name = trim_copy(rest.substr(0, serial_pos));
            const std::string serial_text = trim_copy(rest.substr(serial_pos + 8));
            int64_t serial64 = 0;
            if (!parse_int64(serial_text, serial64)) {
                if (out_error) *out_error = "enum serial must be an integer";
                return false;
            }
            if (serial64 < 0 || serial64 > 255) {
                if (out_error) *out_error = "enum serial must be in range [0,255]";
                return false;
            }
            serial = static_cast<uchar>(serial64);
            has_serial = true;
        }

        const size_t member_pos = enum_name.rfind("::");
        if (member_pos != std::string::npos) {
            member_name = trim_copy(enum_name.substr(member_pos + 2));
            enum_name = trim_copy(enum_name.substr(0, member_pos));
            if (member_name.empty()) {
                if (out_error) *out_error = "enum member name is empty";
                return false;
            }
            if (has_serial) {
                if (out_error) *out_error = "enum spec cannot use both member name and serial";
                return false;
            }
        }

        if (enum_name.empty()) {
            if (out_error) *out_error = "enum type name is empty";
            return false;
        }
        out.kind = OperandApplyKind::Enum;
        out.enum_name = enum_name;
        out.enum_member_name = member_name;
        out.enum_serial = serial;
        return true;
    }

    if (starts_with_ci(text, "stroff:")) {
        const std::string rest = trim_copy(text.substr(7));
        if (rest.empty()) {
            if (out_error) *out_error = "stroff spec requires a type path";
            return false;
        }

        std::string path_part = rest;
        adiff_t delta = 0;

        const size_t delta_pos = rest.find(",delta=");
        if (delta_pos != std::string::npos) {
            path_part = trim_copy(rest.substr(0, delta_pos));
            const std::string delta_text = trim_copy(rest.substr(delta_pos + 7));
            int64_t delta64 = 0;
            if (!parse_int64(delta_text, delta64)) {
                if (out_error) *out_error = "stroff delta must be an integer";
                return false;
            }
            delta = static_cast<adiff_t>(delta64);
        }

        std::vector<std::string> path_names;
        split_path_names(path_part, path_names);
        if (path_names.empty()) {
            if (out_error) *out_error = "stroff type path is empty";
            return false;
        }

        out.kind = OperandApplyKind::Stroff;
        out.stroff_path_names = std::move(path_names);
        out.stroff_delta = delta;
        return true;
    }

    if (out_error) *out_error = "unknown format spec mode";
    return false;
}

bool parse_operand_apply_spec(const char* spec, OperandApplyRequest& out) {
    return parse_operand_format_spec(spec, out, nullptr);
}

bool decode_operand(ea_t ea, int opnum, insn_t& out_insn, op_t& out_op, std::string* out_error) {
    if (out_error) out_error->clear();
    if (ea == BADADDR || !is_code(get_flags(ea))) {
        if (out_error) *out_error = "address is not code";
        return false;
    }
    if (opnum < 0 || opnum >= UA_MAXOP) {
        if (out_error) *out_error = "operand index out of range";
        return false;
    }
    if (decode_insn(&out_insn, ea) <= 0) {
        if (out_error) *out_error = "failed to decode instruction";
        return false;
    }
    out_op = out_insn.ops[opnum];
    if (out_op.type == o_void) {
        if (out_error) *out_error = "operand slot is empty";
        return false;
    }
    return true;
}

bool operand_numeric_value(ea_t ea, int opnum, uint64& out_value, std::string* out_error) {
    if (out_error) out_error->clear();
    insn_t insn;
    op_t op;
    if (!decode_operand(ea, opnum, insn, op, out_error)) return false;

    switch (op.type) {
        case o_imm:
            out_value = static_cast<uint64>(op.value);
            return true;
        case o_mem:
        case o_near:
        case o_far:
        case o_displ:
            out_value = static_cast<uint64>(op.addr);
            return true;
        default:
            if (out_error) *out_error = "operand is not numeric";
            return false;
    }
}

bool resolve_enum_member_serial(const tinfo_t& enum_tif, const std::string& member_name, uchar& out_serial, std::string* out_error) {
    if (out_error) out_error->clear();
    edm_t target;
    const ssize_t idx = enum_tif.get_edm(&target, member_name.c_str());
    if (idx < 0) {
        if (out_error) *out_error = "enum member not found";
        return false;
    }

    for (int s = 0; s <= 255; ++s) {
        edm_t candidate;
        const ssize_t by_val = enum_tif.get_edm_by_value(&candidate, target.value, DEFMASK64, static_cast<uchar>(s));
        if (by_val < 0) break;
        if (candidate.name == target.name) {
            out_serial = static_cast<uchar>(s);
            return true;
        }
    }

    if (out_error) *out_error = "failed to resolve enum member serial";
    return false;
}

bool apply_operand_representation(ea_t ea, int opnum, const OperandApplyRequest& req, std::string* out_error) {
    if (out_error) out_error->clear();
    if (ea == BADADDR || !is_code(get_flags(ea))) {
        if (out_error) *out_error = "address is not code";
        return false;
    }
    if (opnum < 0 || opnum >= UA_MAXOP) {
        if (out_error) *out_error = "operand index out of range";
        return false;
    }
    if (req.kind == OperandApplyKind::None) {
        if (out_error) *out_error = "format spec mode is none";
        return false;
    }

    bool ok = false;
    auto_wait();

    switch (req.kind) {
        case OperandApplyKind::Clear:
            ok = clr_op_type(ea, opnum);
            if (!ok) {
                const flags64_t flags = get_flags(ea);
                ok = !is_enum(flags, opnum) && !is_stroff(flags, opnum);
            }
            if (!ok && out_error) *out_error = "failed to clear operand representation";
            break;

        case OperandApplyKind::Enum: {
            insn_t insn;
            op_t op;
            if (!decode_operand(ea, opnum, insn, op, out_error)) {
                auto_wait();
                return false;
            }

            tid_t enum_tid = BADNODE;
            tinfo_t enum_tif;
            if (!resolve_named_type_tid(req.enum_name, enum_tid, &enum_tif) || !enum_tif.is_enum()) {
                if (out_error) *out_error = "enum type not found";
                auto_wait();
                return false;
            }

            uchar serial = req.enum_serial;
            if (!req.enum_member_name.empty()) {
                uint64 operand_value = 0;
                std::string value_err;
                if (!operand_numeric_value(ea, opnum, operand_value, &value_err)) {
                    if (out_error) *out_error = "enum member apply requires numeric operand: " + value_err;
                    auto_wait();
                    return false;
                }

                edm_t member;
                if (enum_tif.get_edm(&member, req.enum_member_name.c_str()) < 0) {
                    if (out_error) *out_error = "enum member not found";
                    auto_wait();
                    return false;
                }
                if (member.value != operand_value) {
                    if (out_error) *out_error = "enum member value does not match operand value";
                    auto_wait();
                    return false;
                }

                std::string serial_err;
                if (!resolve_enum_member_serial(enum_tif, req.enum_member_name, serial, &serial_err)) {
                    if (out_error) *out_error = serial_err;
                    auto_wait();
                    return false;
                }
            }

            ok = op_enum(ea, opnum, enum_tid, serial);
            if (!ok && out_error) *out_error = "op_enum failed";
            break;
        }

        case OperandApplyKind::Stroff: {
            insn_t insn;
            op_t op;
            if (!decode_operand(ea, opnum, insn, op, out_error)) {
                auto_wait();
                return false;
            }

            std::vector<tid_t> path;
            path.reserve(req.stroff_path_names.size());
            for (const std::string& name : req.stroff_path_names) {
                tid_t tid = BADNODE;
                tinfo_t tif;
                if (!resolve_named_type_tid(name, tid, &tif) || !tif.is_udt()) {
                    if (out_error) *out_error = "stroff type path contains unknown or non-udt type";
                    auto_wait();
                    return false;
                }
                path.push_back(tid);
            }

            if (path.empty()) {
                if (out_error) *out_error = "stroff type path is empty";
                auto_wait();
                return false;
            }
            ok = op_stroff(insn, opnum, path.data(), static_cast<int>(path.size()), req.stroff_delta);
            if (!ok && out_error) *out_error = "op_stroff failed";
            break;
        }

        case OperandApplyKind::None:
            ok = false;
            break;
    }

    if (ok) {
        decompiler::invalidate_decompiler_cache(ea);
    }
    auto_wait();
    return ok;
}

const char* operand_class_name(optype_t type) {
    switch (type) {
        case o_void:    return "";
        case o_reg:     return "reg";
        case o_mem:     return "mem";
        case o_phrase:  return "phrase";
        case o_displ:   return "displ";
        case o_imm:     return "imm";
        case o_far:     return "far";
        case o_near:    return "near";
        case o_idpspec0:
        case o_idpspec1:
        case o_idpspec2:
        case o_idpspec3:
        case o_idpspec4:
        case o_idpspec5:
            return "idpspec";
        default:
            return "unknown";
    }
}

std::string operand_class_text(ea_t ea, int opnum) {
    insn_t insn;
    op_t op;
    if (!decode_operand(ea, opnum, insn, op, nullptr)) return "";
    return operand_class_name(op.type);
}

std::string operand_repr_kind_text(ea_t ea, int opnum) {
    const flags64_t flags = get_flags(ea);
    if (is_enum(flags, opnum)) return "enum";
    if (is_stroff(flags, opnum)) return "stroff";
    return "plain";
}

std::string operand_repr_type_name_text(ea_t ea, int opnum) {
    const flags64_t flags = get_flags(ea);
    if (is_enum(flags, opnum)) {
        uchar serial = 0;
        const tid_t enum_tid = get_enum_id(&serial, ea, opnum);
        if (enum_tid != BADNODE) {
            return tid_name_or_fallback(enum_tid);
        }
        return "";
    }

    if (is_stroff(flags, opnum)) {
        std::array<tid_t, MAXSTRUCPATH> path{};
        adiff_t delta = 0;
        int path_len = get_stroff_path(path.data(), &delta, ea, opnum);
        if (path_len <= 0) return "";
        if (path_len > static_cast<int>(path.size())) {
            path_len = static_cast<int>(path.size());
        }

        std::string joined;
        for (int i = 0; i < path_len; ++i) {
            const std::string name = tid_name_or_fallback(path[static_cast<size_t>(i)]);
            if (name.empty()) continue;
            if (!joined.empty()) joined += "/";
            joined += name;
        }
        return joined;
    }

    return "";
}

std::string operand_repr_member_name_text(ea_t ea, int opnum) {
    if (!is_enum(get_flags(ea), opnum)) return "";

    uchar serial = 0;
    const tid_t enum_tid = get_enum_id(&serial, ea, opnum);
    if (enum_tid == BADNODE) return "";

    uint64 value = 0;
    if (!operand_numeric_value(ea, opnum, value, nullptr)) return "";

    tinfo_t enum_tif;
    if (!enum_tif.get_type_by_tid(enum_tid) || !enum_tif.is_enum()) return "";

    qstring expr;
    if (!get_enum_member_expr(&expr, enum_tif, static_cast<int>(serial), value)) {
        return "";
    }
    return expr.c_str();
}

int operand_repr_serial(ea_t ea, int opnum) {
    if (!is_enum(get_flags(ea), opnum)) return 0;
    uchar serial = 0;
    get_enum_id(&serial, ea, opnum);
    return static_cast<int>(serial);
}

int64_t operand_repr_delta(ea_t ea, int opnum) {
    if (!is_stroff(get_flags(ea), opnum)) return 0;
    std::array<tid_t, MAXSTRUCPATH> path{};
    adiff_t delta = 0;
    get_stroff_path(path.data(), &delta, ea, opnum);
    return static_cast<int64_t>(delta);
}

std::string operand_format_spec_text(ea_t ea, int opnum) {
    const std::string kind = operand_repr_kind_text(ea, opnum);
    if (kind == "enum") {
        const std::string type_name = operand_repr_type_name_text(ea, opnum);
        const int serial = operand_repr_serial(ea, opnum);
        if (type_name.empty()) return "enum";
        return "enum:" + type_name + ",serial=" + std::to_string(serial);
    }
    if (kind == "stroff") {
        const std::string type_name = operand_repr_type_name_text(ea, opnum);
        const int64_t delta = operand_repr_delta(ea, opnum);
        if (type_name.empty()) return "stroff";
        return "stroff:" + type_name + ",delta=" + std::to_string(delta);
    }
    return "plain";
}

// Legacy wrappers kept for compatibility with older call sites.
std::string operand_kind_text(ea_t ea, int opnum) { return operand_repr_kind_text(ea, opnum); }
std::string operand_type_text(ea_t ea, int opnum) { return operand_repr_type_name_text(ea, opnum); }
int operand_enum_serial(ea_t ea, int opnum) { return operand_repr_serial(ea, opnum); }
int64_t operand_stroff_delta(ea_t ea, int opnum) { return operand_repr_delta(ea, opnum); }

void instruction_column_common(xsql::FunctionContext& ctx, ea_t ea, ea_t func_addr, int col) {
    if (col == 0) {
        ctx.result_int64(ea);
        return;
    }
    if (col == 1) {
        insn_t insn;
        if (decode_insn(&insn, ea) > 0) ctx.result_int(insn.itype);
        else ctx.result_int(0);
        return;
    }
    if (col == 2) {
        qstring mnem;
        print_insn_mnem(&mnem, ea);
        ctx.result_text(mnem.c_str());
        return;
    }
    if (col == 3) {
        ctx.result_int(static_cast<int>(get_item_size(ea)));
        return;
    }
    if (col >= kInstructionOperandBaseCol && col < (kInstructionOperandBaseCol + kInstructionOperandCount)) {
        const int opnum = col - kInstructionOperandBaseCol;
        qstring op;
        print_operand(&op, ea, opnum);
        tag_remove(&op);
        ctx.result_text(op.c_str());
        return;
    }
    if (col == kInstructionDisasmCol) {
        qstring line;
        generate_disasm_line(&line, ea, 0);
        tag_remove(&line);
        ctx.result_text(line.c_str());
        return;
    }
    if (col == kInstructionFuncAddrCol) {
        ctx.result_int64(func_addr);
        return;
    }
    if (col >= kInstructionClassBaseCol && col < (kInstructionClassBaseCol + kInstructionOperandCount)) {
        ctx.result_text(operand_class_text(ea, col - kInstructionClassBaseCol));
        return;
    }
    if (col >= kInstructionReprKindBaseCol && col < (kInstructionReprKindBaseCol + kInstructionOperandCount)) {
        ctx.result_text(operand_repr_kind_text(ea, col - kInstructionReprKindBaseCol));
        return;
    }
    if (col >= kInstructionReprTypeBaseCol && col < (kInstructionReprTypeBaseCol + kInstructionOperandCount)) {
        ctx.result_text(operand_repr_type_name_text(ea, col - kInstructionReprTypeBaseCol));
        return;
    }
    if (col >= kInstructionReprMemberBaseCol && col < (kInstructionReprMemberBaseCol + kInstructionOperandCount)) {
        ctx.result_text(operand_repr_member_name_text(ea, col - kInstructionReprMemberBaseCol));
        return;
    }
    if (col >= kInstructionReprSerialBaseCol && col < (kInstructionReprSerialBaseCol + kInstructionOperandCount)) {
        ctx.result_int(operand_repr_serial(ea, col - kInstructionReprSerialBaseCol));
        return;
    }
    if (col >= kInstructionReprDeltaBaseCol && col < (kInstructionReprDeltaBaseCol + kInstructionOperandCount)) {
        ctx.result_int64(operand_repr_delta(ea, col - kInstructionReprDeltaBaseCol));
        return;
    }
    if (col >= kInstructionFormatSpecBaseCol && col < (kInstructionFormatSpecBaseCol + kInstructionOperandCount)) {
        ctx.result_text(operand_format_spec_text(ea, col - kInstructionFormatSpecBaseCol));
        return;
    }
    ctx.result_null();
}

// ============================================================================
// INSTRUCTIONS Table - Iterators
// ============================================================================

InstructionsInFuncIterator::InstructionsInFuncIterator(ea_t func_addr)
    : func_addr_(func_addr)
{
    pfn_ = get_func(func_addr_);
}

bool InstructionsInFuncIterator::next() {
    if (!pfn_) return false;

    if (!started_) {
        started_ = true;
        valid_ = fii_.set(pfn_);
        if (valid_) current_ea_ = fii_.current();
    } else if (valid_) {
        valid_ = fii_.next_code();
        if (valid_) current_ea_ = fii_.current();
    }
    return valid_;
}

bool InstructionsInFuncIterator::eof() const {
    return started_ && !valid_;
}

void InstructionsInFuncIterator::column(xsql::FunctionContext& ctx, int col) {
    instruction_column_common(ctx, current_ea_, func_addr_, col);
}

int64_t InstructionsInFuncIterator::rowid() const {
    return static_cast<int64_t>(current_ea_);
}

InstructionAtAddressIterator::InstructionAtAddressIterator(ea_t ea) : ea_(ea) {}

bool InstructionAtAddressIterator::next() {
    if (!started_) {
        started_ = true;
        valid_ = (ea_ != BADADDR) && is_code(get_flags(ea_));
        return valid_;
    }
    valid_ = false;
    return false;
}

bool InstructionAtAddressIterator::eof() const {
    return started_ && !valid_;
}

void InstructionAtAddressIterator::column(xsql::FunctionContext& ctx, int col) {
    func_t* f = get_func(ea_);
    ea_t func_addr = f ? f->start_ea : 0;
    instruction_column_common(ctx, ea_, func_addr, col);
}

int64_t InstructionAtAddressIterator::rowid() const {
    return static_cast<int64_t>(ea_);
}

// ============================================================================
// INSTRUCTIONS Table - Definition
// ============================================================================

void collect_instruction_rows(std::vector<InstructionRow>& rows) {
    rows.clear();

    ea_t ea = inf_get_min_ea();
    ea_t max_ea = inf_get_max_ea();
    while (ea < max_ea && ea != BADADDR) {
        if (is_code(get_flags(ea))) {
            rows.push_back({ea});
        }
        ea = next_head(ea, max_ea);
    }
}

CachedTableDef<InstructionRow> define_instructions() {
    auto builder = cached_table<InstructionRow>("instructions")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            return static_cast<size_t>(get_nlist_size());
        })
        .cache_builder([](std::vector<InstructionRow>& rows) {
            collect_instruction_rows(rows);
        })
        .row_lookup([](InstructionRow& row, int64_t rowid) -> bool {
            if (rowid < 0) return false;
            const ea_t ea = static_cast<ea_t>(rowid);
            if (ea != BADADDR && is_code(get_flags(ea))) {
                row.ea = ea;
                return true;
            }
            // Full scans use positional rowids; resolve through the instruction snapshot.
            std::vector<InstructionRow> rows;
            collect_instruction_rows(rows);
            const size_t pos = static_cast<size_t>(rowid);
            if (pos < rows.size() && rows[pos].ea != BADADDR && is_code(get_flags(rows[pos].ea))) {
                row.ea = rows[pos].ea;
                return true;
            }
            return false;
        })
        .column_int64("address", [](const InstructionRow& row) -> int64_t {
            return static_cast<int64_t>(row.ea);
        })
        .column_int("itype", [](const InstructionRow& row) -> int {
            insn_t insn;
            if (decode_insn(&insn, row.ea) > 0) return insn.itype;
            return 0;
        })
        .column_text("mnemonic", [](const InstructionRow& row) -> std::string {
            qstring mnem;
            print_insn_mnem(&mnem, row.ea);
            return mnem.c_str();
        })
        .column_int("size", [](const InstructionRow& row) -> int {
            return static_cast<int>(get_item_size(row.ea));
        });

    for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
        const std::string op_col = "operand" + std::to_string(opnum);
        builder.column_text(op_col.c_str(), [opnum](const InstructionRow& row) -> std::string {
            qstring op;
            print_operand(&op, row.ea, opnum);
            tag_remove(&op);
            return op.c_str();
        });
    }

    builder
        .column_text("disasm", [](const InstructionRow& row) -> std::string {
            qstring line;
            generate_disasm_line(&line, row.ea, 0);
            tag_remove(&line);
            return line.c_str();
        })
        .column_int64("func_addr", [](const InstructionRow& row) -> int64_t {
            func_t* f = get_func(row.ea);
            return f ? f->start_ea : 0;
        });

    for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
        const std::string class_col = "operand" + std::to_string(opnum) + "_class";
        builder.column_text(class_col.c_str(), [opnum](const InstructionRow& row) -> std::string {
            return operand_class_text(row.ea, opnum);
        });
    }
    for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
        const std::string repr_kind_col = "operand" + std::to_string(opnum) + "_repr_kind";
        builder.column_text(repr_kind_col.c_str(), [opnum](const InstructionRow& row) -> std::string {
            return operand_repr_kind_text(row.ea, opnum);
        });
    }
    for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
        const std::string repr_type_col = "operand" + std::to_string(opnum) + "_repr_type_name";
        builder.column_text(repr_type_col.c_str(), [opnum](const InstructionRow& row) -> std::string {
            return operand_repr_type_name_text(row.ea, opnum);
        });
    }
    for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
        const std::string repr_member_col = "operand" + std::to_string(opnum) + "_repr_member_name";
        builder.column_text(repr_member_col.c_str(), [opnum](const InstructionRow& row) -> std::string {
            return operand_repr_member_name_text(row.ea, opnum);
        });
    }
    for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
        const std::string repr_serial_col = "operand" + std::to_string(opnum) + "_repr_serial";
        builder.column_int(repr_serial_col.c_str(), [opnum](const InstructionRow& row) -> int {
            return operand_repr_serial(row.ea, opnum);
        });
    }
    for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
        const std::string repr_delta_col = "operand" + std::to_string(opnum) + "_repr_delta";
        builder.column_int64(repr_delta_col.c_str(), [opnum](const InstructionRow& row) -> int64_t {
            return operand_repr_delta(row.ea, opnum);
        });
    }
    for (int opnum = 0; opnum < kInstructionOperandCount; ++opnum) {
        const std::string format_col = "operand" + std::to_string(opnum) + "_format_spec";
        builder.column_text_rw(format_col.c_str(),
            [opnum](const InstructionRow& row) -> std::string {
                return operand_format_spec_text(row.ea, opnum);
            },
            [opnum](InstructionRow& row, xsql::FunctionArg val) -> bool {
                if (val.is_nochange() || val.is_null()) {
                    return true;
                }
                const std::string spec = val.as_text();
                if (spec.empty()) {
                    return true;
                }
                OperandApplyRequest req;
                std::string parse_error;
                if (!parse_operand_format_spec(spec.c_str(), req, &parse_error)) {
                    xsql::set_vtab_error("invalid operand format spec '" + spec + "': " + parse_error);
                    return false;
                }

                std::string apply_error;
                if (!apply_operand_representation(row.ea, opnum, req, &apply_error)) {
                    const std::string err = apply_error.empty() ? "apply failed" : apply_error;
                    xsql::set_vtab_error("operand" + std::to_string(opnum) + " format apply failed at " +
                                         std::to_string(static_cast<uint64_t>(row.ea)) + ": " + err);
                    return false;
                }

                const std::string actual_kind = operand_repr_kind_text(row.ea, opnum);
                if (req.kind == OperandApplyKind::Clear) {
                    if (actual_kind != "plain") {
                        xsql::set_vtab_error("post-apply verification failed: expected plain representation");
                        return false;
                    }
                    return true;
                }

                if (req.kind == OperandApplyKind::Enum) {
                    if (actual_kind != "enum") {
                        xsql::set_vtab_error("post-apply verification failed: expected enum representation");
                        return false;
                    }
                    const std::string actual_type = operand_repr_type_name_text(row.ea, opnum);
                    if (!req.enum_name.empty() && actual_type != req.enum_name) {
                        xsql::set_vtab_error("post-apply verification failed: enum type mismatch");
                        return false;
                    }
                    if (!req.enum_member_name.empty()) {
                        const std::string actual_member = operand_repr_member_name_text(row.ea, opnum);
                        if (actual_member.find(req.enum_member_name) == std::string::npos) {
                            xsql::set_vtab_error("post-apply verification failed: enum member mismatch");
                            return false;
                        }
                    }
                    return true;
                }

                if (req.kind == OperandApplyKind::Stroff) {
                    if (actual_kind != "stroff") {
                        xsql::set_vtab_error("post-apply verification failed: expected stroff representation");
                        return false;
                    }
                    const std::string actual_type = operand_repr_type_name_text(row.ea, opnum);
                    if (!req.stroff_path_names.empty()) {
                        const std::string& expected_root = req.stroff_path_names.front();
                        if (!(actual_type == expected_root || actual_type.rfind(expected_root + "/", 0) == 0)) {
                            xsql::set_vtab_error("post-apply verification failed: stroff type mismatch");
                            return false;
                        }
                    }
                    if (operand_repr_delta(row.ea, opnum) != static_cast<int64_t>(req.stroff_delta)) {
                        xsql::set_vtab_error("post-apply verification failed: stroff delta mismatch");
                        return false;
                    }
                    return true;
                }

                return true;
            });
    }

    builder
        .deletable([](InstructionRow& row) -> bool {
            auto_wait();
            asize_t sz = get_item_size(row.ea);
            bool ok = del_items(row.ea, DELIT_SIMPLE, sz);
            auto_wait();
            return ok;
        })
        .filter_eq("address", [](int64_t address) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<InstructionAtAddressIterator>(static_cast<ea_t>(address));
        }, 1.0, 1.0)
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<InstructionsInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 100.0);

    return builder.build();
}

// ============================================================================
// USERDATA Table - netnode-backed key-value store
// ============================================================================

static constexpr const char* NETNODE_KV_MASTER_NAME = "$ idasql netnode_kv";

static netnode get_netnode_kv_master(bool create) {
    netnode master(NETNODE_KV_MASTER_NAME, 0, create);
    return master;
}

// Iterator for single-key lookup via filter_eq_text("key").
// Uses entry_id as rowid for O(1) DELETE/UPDATE via row_lookup.
class NetnodeKvKeyIterator : public xsql::RowIterator {
    std::string key_;
    std::string value_;
    nodeidx_t entry_id_ = 0;
    bool started_ = false;
    bool valid_ = false;

public:
    explicit NetnodeKvKeyIterator(const char* key) : key_(key ? key : "") {}

    bool next() override {
        if (started_) { valid_ = false; return false; }
        started_ = true;

        if (key_.empty()) { valid_ = false; return false; }
        netnode master = get_netnode_kv_master(false);
        if (master == BADNODE) { valid_ = false; return false; }

        entry_id_ = master.hashval_long(key_.c_str());
        if (entry_id_ == 0) { valid_ = false; return false; }

        netnode entry(entry_id_);
        qstring blob;
        if (entry.getblob(&blob, 0, stag) < 0) {
            value_.clear();
        } else {
            value_ = blob.c_str();
        }

        valid_ = true;
        return true;
    }

    bool eof() const override { return started_ && !valid_; }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (!valid_) { ctx.result_null(); return; }
        switch (col) {
            case 0: ctx.result_text(key_.c_str()); break;
            case 1: ctx.result_text(value_.c_str()); break;
            default: ctx.result_null(); break;
        }
    }

    int64_t rowid() const override { return static_cast<int64_t>(entry_id_); }
};

CachedTableDef<NetnodeKvRow> define_netnode_kv() {
    return cached_table<NetnodeKvRow>("netnode_kv")
        .no_shared_cache()
        .estimate_rows([]() -> size_t {
            return 64;
        })
        .cache_builder([](std::vector<NetnodeKvRow>& rows) {
            rows.clear();
            netnode master = get_netnode_kv_master(false);
            if (master == BADNODE) return;

            qstring key_buf;
            for (ssize_t r = master.hashfirst(&key_buf); r >= 0;
                 r = master.hashnext(&key_buf, key_buf.c_str())) {
                nodeidx_t entry_id = master.hashval_long(key_buf.c_str());
                if (entry_id == 0) continue;

                NetnodeKvRow row;
                row.key = key_buf.c_str();

                netnode entry(entry_id);
                qstring blob;
                if (entry.getblob(&blob, 0, stag) >= 0) {
                    row.value = blob.c_str();
                }
                rows.push_back(std::move(row));
            }
        })
        .row_populator([](NetnodeKvRow& row, int argc, xsql::FunctionArg* argv) {
            // argv[2]=key, argv[3]=value
            if (argc > 2 && !argv[2].is_null()) {
                const char* k = argv[2].as_c_str();
                row.key = k ? k : "";
            }
            if (argc > 3 && !argv[3].is_null()) {
                const char* v = argv[3].as_c_str();
                row.value = v ? v : "";
            }
        })
        .column_text("key", [](const NetnodeKvRow& row) -> std::string {
            return row.key;
        })
        .column_text_rw("value",
            [](const NetnodeKvRow& row) -> std::string {
                return row.value;
            },
            [](NetnodeKvRow& row, const char* new_value) -> bool {
                netnode master = get_netnode_kv_master(false);
                if (master == BADNODE) return false;

                nodeidx_t entry_id = master.hashval_long(row.key.c_str());
                if (entry_id == 0) return false;

                netnode entry(entry_id);
                const char* val = new_value ? new_value : "";
                size_t len = strlen(val);
                bool ok = entry.setblob(val, len, 0, stag);
                if (ok) row.value = val;
                return ok;
            })
        .row_lookup([](NetnodeKvRow& row, int64_t raw_rowid) -> bool {
            netnode master = get_netnode_kv_master(false);
            if (master == BADNODE) return false;
            nodeidx_t entry_id = static_cast<nodeidx_t>(raw_rowid);
            qstring key_buf;
            if (master.supstr(&key_buf, entry_id) <= 0) return false;
            row.key = key_buf.c_str();
            netnode entry(entry_id);
            qstring blob;
            if (entry.getblob(&blob, 0, stag) >= 0)
                row.value = blob.c_str();
            return true;
        })
        .deletable([](NetnodeKvRow& row) -> bool {
            netnode master = get_netnode_kv_master(false);
            if (master == BADNODE) return false;

            nodeidx_t entry_id = master.hashval_long(row.key.c_str());
            if (entry_id == 0) return false;

            netnode entry(entry_id);
            entry.kill();
            master.hashdel(row.key.c_str());
            master.supdel(entry_id);  // clean reverse index
            return true;
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            // argv[0]=key, argv[1]=value
            if (argc < 1 || argv[0].is_null()) return false;

            const char* key = argv[0].as_c_str();
            if (!key || !key[0]) return false;

            netnode master = get_netnode_kv_master(true);
            if (master == BADNODE) return false;

            // Check if key already exists
            nodeidx_t existing = master.hashval_long(key);
            if (existing != 0) return false;

            // Create entry netnode
            netnode entry;
            if (!entry.create()) return false;

            const char* val = "";
            if (argc > 1 && !argv[1].is_null()) {
                val = argv[1].as_c_str();
                if (!val) val = "";
            }

            size_t len = strlen(val);
            entry.setblob(val, len, 0, stag);
            nodeidx_t entry_id = static_cast<nodeidx_t>(entry);
            master.hashset(key, entry_id);
            master.supset(entry_id, key);  // reverse index for O(1) row_lookup
            return true;
        })
        .filter_eq_text("key", [](const char* key) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<NetnodeKvKeyIterator>(key);
        }, 1.0, 1.0)
        .build();
}

// ============================================================================
// Registry: All tables in one place
// ============================================================================

TableRegistry::TableRegistry()
    : funcs(define_funcs())
    , segments(define_segments())
    , names(define_names())
    , entries(define_entries())
    , comments(define_comments())
    , bookmarks(define_bookmarks())
    , heads(define_heads())
    , bytes(define_bytes())
    , patched_bytes(define_patched_bytes())
    , instructions(define_instructions())
    , xrefs(define_xrefs())
    , blocks(define_blocks())
    , imports(define_imports())
    , strings(define_strings())
    , netnode_kv(define_netnode_kv())
{
    g_instance = this;
}

TableRegistry::~TableRegistry() {
    if (g_instance == this) g_instance = nullptr;
}

void TableRegistry::invalidate_strings_cache() {
    strings.invalidate_cache();
}

void TableRegistry::invalidate_strings_cache_global() {
    if (g_instance) g_instance->invalidate_strings_cache();
}

void TableRegistry::register_all(xsql::Database& db) {
    // Cached tables with write support
    register_cached_table(db, "funcs", &funcs);

    // Index-based tables (use IDA's indexed access)
    register_index_table(db, "segments", &segments);
    register_index_table(db, "names", &names);
    register_index_table(db, "entries", &entries);

    // Cached tables (query-scoped cache)
    register_cached_table(db, "comments", &comments);
    register_cached_table(db, "bookmarks", &bookmarks);
    register_cached_table(db, "heads", &heads);
    register_cached_table(db, "bytes", &bytes);
    register_cached_table(db, "patched_bytes", &patched_bytes);
    register_cached_table(db, "instructions", &instructions);
    register_cached_table(db, "xrefs", &xrefs);
    register_cached_table(db, "blocks", &blocks);
    register_cached_table(db, "imports", &imports);
    register_cached_table(db, "strings", &strings);
    register_cached_table(db, "netnode_kv", &netnode_kv);

    // Grep-style entity search table
    search::register_grep_entities(db);

    // Create convenience views for common queries
    create_helper_views(db);
}

void TableRegistry::create_helper_views(xsql::Database& db) {
    // callers view - who calls a function
    db.exec(R"(
        CREATE VIEW IF NOT EXISTS callers AS
        SELECT
            x.to_ea as func_addr,
            x.from_ea as caller_addr,
            f.name as caller_name,
            f.address as caller_func_addr
        FROM xrefs x
        LEFT JOIN funcs f ON x.from_ea >= f.address
            AND x.from_ea < f.end_ea
        WHERE x.is_code = 1
    )");

    // callees view - what does a function call
    db.exec(R"(
        CREATE VIEW IF NOT EXISTS callees AS
        SELECT
            f.address as func_addr,
            f.name as func_name,
            x.to_ea as callee_addr,
            COALESCE(f2.name, n.name, printf('sub_%X', x.to_ea)) as callee_name
        FROM funcs f
        JOIN xrefs x ON x.from_ea >= f.address
            AND x.from_ea < f.end_ea
        LEFT JOIN funcs f2 ON x.to_ea = f2.address
        LEFT JOIN names n ON x.to_ea = n.address
        WHERE x.is_code = 1
    )");

}

void TableRegistry::register_index_table(xsql::Database& db, const char* name, const VTableDef* def) {
    std::string module_name = std::string("ida_") + name;
    db.register_table(module_name.c_str(), def);
    db.create_table(name, module_name.c_str());
}

} // namespace entities
} // namespace idasql
