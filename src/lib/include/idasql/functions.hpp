/**
 * functions.hpp - Custom SQL functions for IDA operations
 *
 * Disassembly:
 *   - disasm_at(address)           - Canonical listing line at address head (code or data)
 *   - disasm_at(address, context)  - Canonical listing line with +/- context heads
 *   - disasm(address)              - Single disassembly line
 *   - disasm(address, count)       - Next N instructions from address
 *   - disasm_range(start, end)     - All instructions in [start, end)
 *   - disasm_func(address)         - Full function disassembly
 *   - bytes(address, count)        - Bytes as hex string
 *   - bytes_raw(address, count)    - Bytes as blob
 *   - mnemonic(address)            - Instruction mnemonic only
 *   - operand(address, n)          - Operand text (n=0-7)
 *
 * Binary Search:
 *   - search_bytes(pattern)        - Find all byte pattern matches (JSON array)
 *   - search_bytes(pattern, start, end) - Search within range
 *   - search_first(pattern)        - First match address (or NULL)
 *   - search_first(pattern, start, end) - First match in range
 *
 * Names & Navigation:
 *   - name_at(address)             - Name at address
 *   - func_at(address)             - Function name containing address
 *   - func_start(address)          - Start of containing function
 *   - func_end(address)            - End of containing function
 *   - segment_at(address)          - Segment name containing address
 *
 * Comments & Naming:
 *   - comment_at(address)          - Get comment at address
 *   - set_comment(address, text)   - Set comment at address
 *   - set_name(address, name)      - Set name at address
 *   - type_at(address)             - Get type declaration at address
 *   - set_type(address, decl)      - Apply C declaration/type at address
 *   - parse_decls(text)            - Import C declarations into local types
 *
 * Cross-References:
 *   - xrefs_to(address)            - Xrefs to address (JSON array)
 *   - xrefs_from(address)          - Xrefs from address (JSON array)
 *
 * Decompiler:
 *   - decompile(address)           - Decompiled pseudocode for function
 *   - decompile(address, refresh)  - Decompiled pseudocode with refresh option
 *   - list_lvars(address)          - Local variables as JSON
 *   - rename_lvar(func, idx, new)  - Rename local by index
 *   - rename_lvar_by_name(func, old, new) - Rename local by name
 *   - set_lvar_comment(func, idx, comment) - Set local variable comment by index
 *   - set_union_selection(func, ea, path) - Set/clear user union selection by ea
 *   - set_union_selection_item(func, item, path) - Set/clear selection by ctree item id
 *   - set_union_selection_ea_arg(func, ea, arg_idx, path[, callee]) - Set/clear by call arg coordinate
 *   - call_arg_item(func, ea, arg_idx[, callee]) - Resolve call arg coordinate to ctree item id
 *   - ctree_item_at(func, ea[, op_name[, nth]]) - Resolve generic expression coordinate to ctree item id
 *   - set_union_selection_ea_expr(func, ea, path[, op_name[, nth]]) - Set/clear by expression coordinate
 *   - get_union_selection(func, ea) - Get union path JSON by ea
 *   - get_union_selection_item(func, item) - Get union path JSON by ctree item id
 *   - get_union_selection_ea_arg(func, ea, arg_idx[, callee]) - Get union path JSON by call arg coordinate
 *   - get_union_selection_ea_expr(func, ea[, op_name[, nth]]) - Get union path JSON by expression coordinate
 *   - set_numform(func, ea, opnum, spec) - Set/clear decompiler numform by ea/opnum
 *   - set_numform_item(func, item, opnum, spec) - Set/clear decompiler numform by ctree item
 *   - set_numform_ea_arg(func, ea, arg_idx, opnum, spec[, callee]) - Set/clear numform by call arg coordinate
 *   - set_numform_ea_expr(func, ea, opnum, spec[, op_name[, nth]]) - Set/clear numform by expression coordinate
 *   - get_numform(func, ea, opnum) - Get decompiler numform JSON by ea/opnum
 *   - get_numform_item(func, item, opnum) - Get decompiler numform JSON by ctree item
 *   - get_numform_ea_arg(func, ea, arg_idx, opnum[, callee]) - Get numform JSON by call arg coordinate
 *   - get_numform_ea_expr(func, ea, opnum[, op_name[, nth]]) - Get numform JSON by expression coordinate
 *
 * Byte Patching:
 *   - patch_byte(addr, val)        - Patch single byte
 *   - patch_word(addr, val)        - Patch word (2 bytes)
 *   - patch_dword(addr, val)       - Patch dword (4 bytes)
 *   - patch_qword(addr, val)       - Patch qword (8 bytes)
 *   - revert_byte(addr)            - Revert patched byte
 *   - get_original_byte(addr)      - Get pre-patch byte value
 *
 * Function Index (O(1)):
 *   - func_qty()                   - Total function count
 *   - func_at_index(n)             - Function address at index n
 *
 * Instruction Decoding:
 *   - itype(address)               - Instruction type code
 *   - decode_insn(address)         - Full instruction info (JSON)
 *   - operand_type(address, n)     - Operand type (0-5)
 *   - operand_value(address, n)    - Operand value/address
 *
 * Entity Search:
 *   - grep(pattern)                - Search entities (JSON, default limit=50)
 *   - grep(pattern, limit)         - Search entities with custom limit
 *   - grep(pattern, limit, offset) - Search entities with pagination
 *
 * String List:
 *   - rebuild_strings()            - Rebuild string cache
 *   - string_count()               - Get cached string count
 *
 * File Generation:
 *   - gen_asm_file(ea1, ea2, path) - Generate assembly file
 *   - gen_lst_file(ea1, ea2, path) - Generate listing file
 *   - gen_map_file(path)           - Generate MAP file
 *   - gen_idc_file(ea1, ea2, path) - Generate IDC script
 *   - gen_html_file(ea1, ea2, path)- Generate HTML listing
 *   - gen_cfg_dot(address)         - CFG as DOT string
 *   - gen_cfg_dot_file(addr, path) - CFG DOT to file
 *   - gen_schema_dot()             - Schema diagram as DOT
 *
 * Database:
 *   - save_database()              - Persist changes to .i64 file
 */

#pragma once

#include <idasql/platform.hpp>

#include <xsql/database.hpp>
#include <xsql/json.hpp>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <cctype>
#include <cstring>

#include <idasql/platform_undef.hpp>

// IDA SDK headers (order matters)
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>  // Must come early
#include <ua.hpp>       // insn_t, decode_insn for instruction decoding
#include <bytes.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <lines.hpp>
#include <xref.hpp>
#include <loader.hpp>   // gen_file
#include <fpro.h>       // qfile_t for file operations
#include <gdl.hpp>      // FlowChart for CFG generation
#include <strlist.hpp>  // String list functions
#include <nalt.hpp>     // String type constants
#include <typeinf.hpp>  // parse_decls/apply_cdecl/print_type

// Hex-Rays decompiler - always included, runtime detection
#include <hexrays.hpp>
#include <idasql/decompiler.hpp>  // For hexrays_available()
#include <idasql/entities.hpp>    // Operand apply spec parser/helpers

namespace idasql {
namespace functions {

// ============================================================================
// Disassembly Functions
// ============================================================================

// Helper: render a generated listing line (with address prefix) for one head.
static bool render_disasm_line(ea_t addr, int gflags, std::string& out) {
    qstring line;
    if (!generate_disasm_line(&line, addr, gflags)) {
        return false;
    }

    tag_remove(&line);
    std::ostringstream rendered;
    rendered << std::hex << addr << ": " << line.c_str();
    out = rendered.str();
    return true;
}

// Helper: disassemble all heads in [start, end)
static std::string disasm_range_impl(ea_t start, ea_t end) {
    std::ostringstream result;
    ea_t addr = start;
    bool first = true;
    while (addr < end && addr != BADADDR) {
        std::string rendered;
        if (render_disasm_line(addr, GENDSM_FORCE_CODE, rendered)) {
            if (!first) result << "\n";
            result << rendered;
            first = false;
        }
        addr = next_head(addr, end);
    }
    return result.str();
}

// disasm(address) - Get single disassembly line
// disasm(address, count) - Get multiple lines
static void sql_disasm(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("disasm requires at least 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    int count = (argc >= 2) ? argv[1].as_int() : 1;
    if (count < 1) count = 1;
    if (count > 1000) count = 1000;  // Safety limit

    std::ostringstream result;
    for (int i = 0; i < count && ea != BADADDR; i++) {
        std::string rendered;
        if (render_disasm_line(ea, GENDSM_FORCE_CODE, rendered)) {
            if (i > 0) result << "\n";
            result << rendered;
        }
        ea = next_head(ea, BADADDR);
    }

    std::string str = result.str();
    ctx.result_text(str);
}

// disasm_at(address) - Canonical listing line for containing head (code or data)
// disasm_at(address, context) - Listing line with +/- context heads
static void sql_disasm_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1 || argc > 2) {
        ctx.result_error("disasm_at requires 1-2 arguments (address, [context])");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    int context = (argc >= 2) ? argv[1].as_int() : 0;
    if (context < 0) context = 0;
    if (context > 64) context = 64;  // Safety cap

    if (ea == BADADDR || ea == 0) {
        ctx.result_null();
        return;
    }

    ea_t head = get_item_head(ea);
    if (head == BADADDR || head == 0) {
        ctx.result_null();
        return;
    }

    std::string center;
    if (!render_disasm_line(head, 0, center)) {
        ctx.result_null();
        return;
    }
    if (context == 0) {
        ctx.result_text(center);
        return;
    }

    std::vector<ea_t> before;
    ea_t cur = head;
    for (int i = 0; i < context; ++i) {
        ea_t prev = prev_head(cur, 0);
        if (prev == BADADDR || prev == cur) {
            break;
        }
        before.push_back(prev);
        cur = prev;
    }
    std::reverse(before.begin(), before.end());

    std::vector<ea_t> after;
    cur = head;
    for (int i = 0; i < context; ++i) {
        ea_t next = next_head(cur, BADADDR);
        if (next == BADADDR || next == cur) {
            break;
        }
        after.push_back(next);
        cur = next;
    }

    std::ostringstream result;
    bool first = true;
    auto append_line = [&](ea_t addr) {
        std::string line;
        if (!render_disasm_line(addr, 0, line)) {
            return;
        }
        if (!first) result << "\n";
        result << line;
        first = false;
    };

    for (ea_t addr : before) append_line(addr);
    append_line(head);
    for (ea_t addr : after) append_line(addr);

    std::string text = result.str();
    text.empty() ? ctx.result_null() : ctx.result_text(text);
}

// disasm_range(start, end) - Disassemble all heads in address range [start, end)
static void sql_disasm_range(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("disasm_range requires 2 arguments (start, end)");
        return;
    }
    ea_t start = static_cast<ea_t>(argv[0].as_int64());
    ea_t end   = static_cast<ea_t>(argv[1].as_int64());
    auto str = disasm_range_impl(start, end);
    str.empty() ? ctx.result_null() : ctx.result_text(str);
}

// disasm_func(address) - Disassemble entire function containing address
static void sql_disasm_func(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("disasm_func requires 1 argument (address)");
        return;
    }
    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    func_t* func = get_func(ea);
    if (!func) {
        ctx.result_null();
        return;
    }
    auto str = disasm_range_impl(func->start_ea, func->end_ea);
    str.empty() ? ctx.result_null() : ctx.result_text(str);
}

// ============================================================================
// Bytes Functions
// ============================================================================

// bytes(address, count) - Get bytes as hex string
static void sql_bytes_hex(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("bytes requires 2 arguments (address, count)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    size_t count = static_cast<size_t>(argv[1].as_int());
    if (count > 4096) count = 4096;  // Safety limit

    std::ostringstream result;
    result << std::hex << std::setfill('0');
    for (size_t i = 0; i < count; i++) {
        if (i > 0) result << " ";
        uchar byte = get_byte(ea + i);
        result << std::setw(2) << static_cast<int>(byte);
    }

    std::string str = result.str();
    ctx.result_text(str);
}

// bytes_raw(address, count) - Get bytes as blob
static void sql_bytes_raw(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("bytes_raw requires 2 arguments (address, count)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    size_t count = static_cast<size_t>(argv[1].as_int());
    if (count > 4096) count = 4096;  // Safety limit

    std::vector<uchar> data(count);
    for (size_t i = 0; i < count; i++) {
        data[i] = get_byte(ea + i);
    }

    ctx.result_blob(data.data(), static_cast<size_t>(data.size()));
}

// patch_byte(ea, value) - Patch a single byte (preserves original)
static void sql_patch_byte(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("patch_byte requires 2 arguments (address, value)");
        return;
    }
    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    uint64 val = static_cast<uint64>(argv[1].as_int64());
    bool ok = patch_byte(ea, val);
    ctx.result_int(ok ? 1 : 0);
}

// patch_word(ea, value) - Patch a word (2 bytes, preserves original)
static void sql_patch_word(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("patch_word requires 2 arguments (address, value)");
        return;
    }
    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    uint64 val = static_cast<uint64>(argv[1].as_int64());
    bool ok = patch_word(ea, val);
    ctx.result_int(ok ? 1 : 0);
}

// patch_dword(ea, value) - Patch a dword (4 bytes, preserves original)
static void sql_patch_dword(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("patch_dword requires 2 arguments (address, value)");
        return;
    }
    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    uint64 val = static_cast<uint64>(argv[1].as_int64());
    bool ok = patch_dword(ea, val);
    ctx.result_int(ok ? 1 : 0);
}

// patch_qword(ea, value) - Patch a qword (8 bytes, preserves original)
static void sql_patch_qword(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("patch_qword requires 2 arguments (address, value)");
        return;
    }
    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    uint64 val = static_cast<uint64>(argv[1].as_int64());
    bool ok = patch_qword(ea, val);
    ctx.result_int(ok ? 1 : 0);
}

// revert_byte(ea) - Revert a patched byte to original
static void sql_revert_byte(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("revert_byte requires 1 argument (address)");
        return;
    }
    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    bool ok = revert_byte(ea);
    ctx.result_int(ok ? 1 : 0);
}

// get_original_byte(ea) - Get the original byte value before patching
static void sql_get_original_byte(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("get_original_byte requires 1 argument (address)");
        return;
    }
    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    ctx.result_int(static_cast<int>(get_original_byte(ea)));
}

// ============================================================================
// Name Functions
// ============================================================================

// name_at(address) - Get name at address
static void sql_name_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("name_at requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    qstring name;
    if (get_name(&name, ea) > 0 && !name.empty()) {
        ctx.result_text(name.c_str());
    } else {
        ctx.result_null();
    }
}

// func_at(address) - Get function name containing address
static void sql_func_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("func_at requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    func_t* func = get_func(ea);
    if (func) {
        qstring name;
        if (get_func_name(&name, func->start_ea) > 0) {
            ctx.result_text(name.c_str());
            return;
        }
    }
    ctx.result_null();
}

// func_start(address) - Get start address of function containing address
static void sql_func_start(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("func_start requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    func_t* func = get_func(ea);
    if (func) {
        ctx.result_int64(func->start_ea);
    } else {
        ctx.result_null();
    }
}

// func_end(address) - Get end address of function containing address
static void sql_func_end(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("func_end requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    func_t* func = get_func(ea);
    if (func) {
        ctx.result_int64(func->end_ea);
    } else {
        ctx.result_null();
    }
}

// ============================================================================
// Function Index Functions (O(1) access)
// ============================================================================

// func_qty() - Get total function count
static void sql_func_qty(xsql::FunctionContext& ctx, int, xsql::FunctionArg*) {
    ctx.result_int64(get_func_qty());
}

// func_at_index(n) - Get function address at index n
static void sql_func_at_index(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("func_at_index requires 1 argument (index)");
        return;
    }

    size_t idx = static_cast<size_t>(argv[0].as_int64());
    size_t qty = get_func_qty();

    if (idx >= qty) {
        ctx.result_null();
        return;
    }

    func_t* f = getn_func(idx);
    if (f) {
        ctx.result_int64(f->start_ea);
    } else {
        ctx.result_null();
    }
}

// ============================================================================
// Name Modification Functions
// ============================================================================

// set_name(address, name) - Set name at address
static void sql_set_name(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("set_name requires 2 arguments (address, name)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    const char* name = argv[1].as_c_str();

    bool success = set_name(ea, name, SN_CHECK) != 0;
    if (success) decompiler::invalidate_decompiler_cache(ea);
    ctx.result_int(success ? 1 : 0);
}

// type_at(address) - Get type declaration at address
static void sql_type_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("type_at requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    qstring out;
    if (print_type(&out, ea, PRTYPE_1LINE | PRTYPE_SEMI)) {
        ctx.result_text(out.c_str());
        return;
    }
    ctx.result_null();
}

// set_type(address, decl) - Apply C declaration/type at address
// Returns: 1 on success, 0 on parse/apply failure
static void sql_set_type(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("set_type requires 2 arguments (address, declaration)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    const char* decl = argv[1].as_c_str();
    if (decl == nullptr || *decl == '\0') {
        // Empty declaration clears user-provided type.
        del_tinfo(ea);
        decompiler::invalidate_decompiler_cache(ea);
        ctx.result_int(1);
        return;
    }

    bool ok = apply_cdecl(nullptr, ea, decl, 0);
    if (ok) {
        decompiler::invalidate_decompiler_cache(ea);
    }
    ctx.result_int(ok ? 1 : 0);
}

// parse_decls(text) - Import C declarations into local types
// Returns: 1 on success, 0 on parse errors
static void sql_parse_decls(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("parse_decls requires 1 argument (declarations)");
        return;
    }

    const char* decls = argv[0].as_c_str();
    if (decls == nullptr || *decls == '\0') {
        ctx.result_error("parse_decls requires non-empty declaration text");
        return;
    }

    // Allow redeclarations; keep parser strict enough for agent feedback.
    const int errors = parse_decls(nullptr, decls, nullptr, HTI_DCL | HTI_HIGH | HTI_SEMICOLON);
    ctx.result_int(errors == 0 ? 1 : 0);
}

// ============================================================================
// Segment Functions
// ============================================================================

// segment_at(address) - Get segment name containing address
static void sql_segment_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("segment_at requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    segment_t* seg = getseg(ea);
    if (seg) {
        qstring name;
        if (get_segm_name(&name, seg) > 0) {
            ctx.result_text(name.c_str());
            return;
        }
    }
    ctx.result_null();
}

// ============================================================================
// Comment Functions
// ============================================================================

// comment_at(address) - Get comment at address
static void sql_comment_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("comment_at requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    qstring cmt;
    if (get_cmt(&cmt, ea, false) > 0) {
        ctx.result_text(cmt.c_str());
    } else if (get_cmt(&cmt, ea, true) > 0) {
        // Try repeatable comment
        ctx.result_text(cmt.c_str());
    } else {
        ctx.result_null();
    }
}

// set_comment(address, text) - Set comment at address
// set_comment(address, text, repeatable) - Set comment with type
static void sql_set_comment(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("set_comment requires 2-3 arguments (address, text, [repeatable])");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    const char* cmt = argv[1].as_c_str();
    bool repeatable = (argc >= 3) ? argv[2].as_int() != 0 : false;

    bool success = set_cmt(ea, cmt ? cmt : "", repeatable);
    ctx.result_int(success ? 1 : 0);
}

// ============================================================================
// Cross-Reference Functions
// ============================================================================

// xrefs_to(address) - Get xrefs to address as JSON array
static void sql_xrefs_to(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("xrefs_to requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());

    xsql::json arr = xsql::json::array();
    xrefblk_t xb;
    for (bool ok = xb.first_to(ea, XREF_ALL); ok; ok = xb.next_to()) {
        arr.push_back({{"from", xb.from}, {"type", static_cast<int>(xb.type)}});
    }

    std::string str = arr.dump();
    ctx.result_text(str);
}

// xrefs_from(address) - Get xrefs from address as JSON array
static void sql_xrefs_from(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("xrefs_from requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());

    xsql::json arr = xsql::json::array();
    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
        arr.push_back({{"to", xb.to}, {"type", static_cast<int>(xb.type)}});
    }

    std::string str = arr.dump();
    ctx.result_text(str);
}

// ============================================================================
// Decompiler Functions (Optional - requires Hex-Rays)
// ============================================================================

inline bool is_ident_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

inline bool starts_with_keyword(const std::string& s, const char* kw) {
    const size_t n = std::strlen(kw);
    if (s.size() < n) return false;
    if (s.compare(0, n, kw) != 0) return false;
    if (s.size() == n) return true;
    return std::isspace(static_cast<unsigned char>(s[n])) != 0;
}

// Extract declaration variable name candidate from a pseudocode line.
// This is intentionally conservative: it only marks declaration-like lines.
inline int find_decl_lvar_index(const std::string& line,
                                const std::unordered_map<std::string, int>& lvar_name_to_idx) {
    size_t semi = line.find(';');
    if (semi == std::string::npos) return -1;

    size_t open_paren = line.find('(');
    if (open_paren != std::string::npos && open_paren < semi) return -1;  // for/if/function sig

    size_t eq = line.find('=');
    if (eq != std::string::npos && eq < semi) return -1;  // assignment

    std::string prefix = line.substr(0, semi);
    size_t sl_comment = prefix.find("//");
    if (sl_comment != std::string::npos) {
        prefix = prefix.substr(0, sl_comment);
    }

    size_t first = prefix.find_first_not_of(" \t");
    if (first == std::string::npos) return -1;
    std::string trimmed = prefix.substr(first);

    if (starts_with_keyword(trimmed, "return") ||
        starts_with_keyword(trimmed, "if") ||
        starts_with_keyword(trimmed, "while") ||
        starts_with_keyword(trimmed, "switch") ||
        starts_with_keyword(trimmed, "for") ||
        starts_with_keyword(trimmed, "goto") ||
        starts_with_keyword(trimmed, "break") ||
        starts_with_keyword(trimmed, "continue")) {
        return -1;
    }

    size_t end = prefix.find_last_not_of(" \t");
    if (end == std::string::npos) return -1;

    // Skip trailing array suffixes.
    while (end > 0 && prefix[end] == ']') {
        size_t lb = prefix.find_last_of('[', end);
        if (lb == std::string::npos || lb == 0) break;
        end = prefix.find_last_not_of(" \t", lb - 1);
        if (end == std::string::npos) return -1;
    }

    if (!is_ident_char(prefix[end])) return -1;
    size_t start = end;
    while (start > 0 && is_ident_char(prefix[start - 1])) {
        --start;
    }
    std::string candidate = prefix.substr(start, end - start + 1);
    if (candidate.empty()) return -1;

    auto it = lvar_name_to_idx.find(candidate);
    if (it == lvar_name_to_idx.end()) return -1;
    return it->second;
}

// Render pseudocode lines with ea prefixes and declaration-only lvar idx hints.
static std::string render_pseudocode(cfuncptr_t& cfunc) {
    const strvec_t& sv = cfunc->get_pseudocode();
    std::ostringstream result;

    std::unordered_map<std::string, int> lvar_name_to_idx;
    std::unordered_set<std::string> ambiguous_names;
    lvars_t* lvars = cfunc->get_lvars();
    if (lvars) {
        for (int i = 0; i < lvars->size(); i++) {
            const lvar_t& lv = (*lvars)[i];
            std::string name = lv.name.c_str();
            if (name.empty()) continue;
            auto [it, inserted] = lvar_name_to_idx.emplace(name, i);
            if (!inserted) {
                ambiguous_names.insert(name);
            }
        }
    }
    for (const auto& n : ambiguous_names) {
        lvar_name_to_idx.erase(n);
    }

    for (size_t i = 0; i < sv.size(); i++) {
        ea_t line_ea = decompiler::extract_line_ea(&*cfunc, sv[i].line);
        qstring line = sv[i].line;
        tag_remove(&line);

        std::string rendered_line = line.c_str();
        int decl_idx = find_decl_lvar_index(rendered_line, lvar_name_to_idx);
        if (decl_idx >= 0 && rendered_line.find("[lv:") == std::string::npos) {
            if (rendered_line.find("//") != std::string::npos) {
                rendered_line += " [lv:" + std::to_string(decl_idx) + "]";
            } else {
                rendered_line += " // [lv:" + std::to_string(decl_idx) + "]";
            }
        }

        if (i > 0) result << "\n";
        char prefix[48];
        if (line_ea != 0 && line_ea != BADADDR)
            qsnprintf(prefix, sizeof(prefix), "/* %a */ ", line_ea);
        else
            qsnprintf(prefix, sizeof(prefix), "/*          */ ");
        result << prefix << rendered_line;
    }
    return result.str();
}

// decompile(address) - Get decompiled pseudocode (runtime Hex-Rays detection)
// Uses decompiler::hexrays_available() set during DecompilerRegistry::register_all()
static void sql_decompile(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("decompile requires 1 argument (address)");
        return;
    }

    // Check cached Hex-Rays availability (set during DecompilerRegistry::register_all)
    if (!decompiler::hexrays_available()) {
        ctx.result_error("Decompiler not available (requires Hex-Rays license)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());

    func_t* func = get_func(ea);
    if (!func) {
        ctx.result_error("No function at address");
        return;
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf);
    if (!cfunc) {
        std::string err = "Decompilation failed: " + std::string(hf.desc().c_str());
        ctx.result_error(err);
        return;
    }

    std::string str = render_pseudocode(cfunc);
    ctx.result_text(str);
}

// decompile(address, refresh) - Get decompiled pseudocode with optional cache invalidation
// When refresh=1, invalidates the cached decompilation before decompiling.
// Use after renaming functions or local variables to get fresh pseudocode.
static void sql_decompile_2(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("decompile requires 2 arguments (address, refresh)");
        return;
    }

    if (!decompiler::hexrays_available()) {
        ctx.result_error("Decompiler not available (requires Hex-Rays license)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    int refresh = argv[1].as_int();

    func_t* func = get_func(ea);
    if (!func) {
        ctx.result_error("No function at address");
        return;
    }

    if (refresh) {
        mark_cfunc_dirty(func->start_ea, false);
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf);
    if (!cfunc) {
        std::string err = "Decompilation failed: " + std::string(hf.desc().c_str());
        ctx.result_error(err);
        return;
    }

    std::string str = render_pseudocode(cfunc);
    ctx.result_text(str);
}

// ============================================================================
// Address Utility Functions
// ============================================================================

// next_head(address) - Get next defined head
static void sql_next_head(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("next_head requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    ea_t next = next_head(ea, BADADDR);
    if (next != BADADDR) {
        ctx.result_int64(next);
    } else {
        ctx.result_null();
    }
}

// prev_head(address) - Get previous defined head
static void sql_prev_head(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("prev_head requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    ea_t prev = prev_head(ea, 0);
    if (prev != BADADDR) {
        ctx.result_int64(prev);
    } else {
        ctx.result_null();
    }
}

// hex(value) - Format integer as hex string
static void sql_hex(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("hex requires 1 argument (value)");
        return;
    }

    int64_t val = argv[0].as_int64();
    std::ostringstream result;
    result << "0x" << std::hex << val;
    std::string str = result.str();
    ctx.result_text(str);
}

// ============================================================================
// Item Query Functions
// ============================================================================

// item_type(address) - Get type of item at address
static void sql_item_type(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("item_type requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    flags64_t f = get_flags(ea);

    const char* type = "unknown";
    if (is_code(f)) type = "code";
    else if (is_strlit(f)) type = "string";
    else if (is_struct(f)) type = "struct";
    else if (is_align(f)) type = "align";
    else if (is_data(f)) type = "data";

    ctx.result_text_static(type);
}

// item_size(address) - Get size of item at address
static void sql_item_size(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("item_size requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    asize_t size = get_item_size(ea);
    ctx.result_int64(size);
}

// is_code(address) - Check if address is code
static void sql_is_code(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("is_code requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    ctx.result_int(is_code(get_flags(ea)) ? 1 : 0);
}

// is_data(address) - Check if address is data
static void sql_is_data(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("is_data requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    ctx.result_int(is_data(get_flags(ea)) ? 1 : 0);
}

// mnemonic(address) - Get instruction mnemonic
static void sql_mnemonic(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("mnemonic requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    if (!is_code(get_flags(ea))) {
        ctx.result_null();
        return;
    }

    qstring mnem;
    print_insn_mnem(&mnem, ea);
    ctx.result_text(mnem.c_str());
}

// operand(address, n) - Get operand text
static void sql_operand(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("operand requires 2 arguments (address, operand_num)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    int n = argv[1].as_int();

    if (!is_code(get_flags(ea)) || n < 0 || n > 5) {
        ctx.result_null();
        return;
    }

    qstring op;
    print_operand(&op, ea, n);
    tag_remove(&op);
    if (op.empty()) {
        ctx.result_null();
    } else {
        ctx.result_text(op.c_str());
    }
}

// flags_at(address) - Get raw flags at address
static void sql_flags_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("flags_at requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    ctx.result_int64(get_flags(ea));
}

// ============================================================================
// Instruction Decoding Functions
// ============================================================================

// Operand type names
static const char* get_optype_name(optype_t type) {
    switch (type) {
        case o_void:    return "void";
        case o_reg:     return "reg";
        case o_mem:     return "mem";
        case o_phrase:  return "phrase";
        case o_displ:   return "displ";
        case o_imm:     return "imm";
        case o_far:     return "far";
        case o_near:    return "near";
        default:        return "idpspec";
    }
}

// itype(address) - Get instruction type code
static void sql_itype(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("itype requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());

    if (!is_code(get_flags(ea))) {
        ctx.result_null();
        return;
    }

    insn_t insn;
    if (decode_insn(&insn, ea) > 0) {
        ctx.result_int(insn.itype);
    } else {
        ctx.result_null();
    }
}

// decode_insn(address) - Get full instruction info as JSON
static void sql_decode_insn(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("decode_insn requires 1 argument (address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());

    if (!is_code(get_flags(ea))) {
        ctx.result_null();
        return;
    }

    insn_t insn;
    int len = decode_insn(&insn, ea);
    if (len <= 0) {
        ctx.result_null();
        return;
    }

    // Get mnemonic
    qstring mnem;
    print_insn_mnem(&mnem, ea);

    // Build JSON using xsql::json
    xsql::json result = {
        {"ea", insn.ea},
        {"itype", insn.itype},
        {"size", insn.size},
        {"mnemonic", mnem.c_str()}
    };

    // Operands array
    xsql::json ops = xsql::json::array();
    for (int i = 0; i < UA_MAXOP; i++) {
        const op_t& op = insn.ops[i];
        if (op.type == o_void) break;

        // Get operand text
        qstring op_text;
        print_operand(&op_text, ea, i);
        tag_remove(&op_text);

        ops.push_back({
            {"n", i},
            {"type", static_cast<int>(op.type)},
            {"type_name", get_optype_name(op.type)},
            {"dtype", static_cast<int>(op.dtype)},
            {"reg", op.reg},
            {"addr", op.addr},
            {"value", op.value},
            {"text", op_text.c_str()}  // nlohmann auto-escapes
        });
    }
    result["operands"] = ops;

    std::string str = result.dump();
    ctx.result_text(str);
}

// operand_type(address, n) - Get operand type
static void sql_operand_type(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("operand_type requires 2 arguments (address, operand_num)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    int n = argv[1].as_int();

    if (!is_code(get_flags(ea)) || n < 0 || n >= UA_MAXOP) {
        ctx.result_null();
        return;
    }

    insn_t insn;
    if (decode_insn(&insn, ea) <= 0) {
        ctx.result_null();
        return;
    }

    const op_t& op = insn.ops[n];
    if (op.type == o_void) {
        ctx.result_null();
    } else {
        ctx.result_text_static(get_optype_name(op.type));
    }
}

// operand_value(address, n) - Get operand value (immediate or address)
static void sql_operand_value(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("operand_value requires 2 arguments (address, operand_num)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    int n = argv[1].as_int();

    if (!is_code(get_flags(ea)) || n < 0 || n >= UA_MAXOP) {
        ctx.result_null();
        return;
    }

    insn_t insn;
    if (decode_insn(&insn, ea) <= 0) {
        ctx.result_null();
        return;
    }

    const op_t& op = insn.ops[n];
    switch (op.type) {
        case o_void:
            ctx.result_null();
            break;
        case o_imm:
            ctx.result_int64(op.value);
            break;
        case o_mem:
        case o_near:
        case o_far:
        case o_displ:
            ctx.result_int64(op.addr);
            break;
        case o_reg:
            ctx.result_int(op.reg);
            break;
        default:
            ctx.result_int64(op.value);
            break;
    }
}

// ============================================================================
// File Generation Functions
// ============================================================================

// Helper: Generate file using ida_loader.gen_file
static int gen_file_helper(ofile_type_t ofile_type, const char* filepath, ea_t ea1, ea_t ea2, int flags) {
    qstring path(filepath);
    FILE* fp = qfopen(path.c_str(), "w");
    if (!fp) return -1;

    int result = gen_file(ofile_type, fp, ea1, ea2, flags);
    qfclose(fp);
    return result;
}

// gen_asm_file(ea1, ea2, path) - Generate assembly file
static void sql_gen_asm_file(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("gen_asm_file requires 3 arguments (ea1, ea2, path)");
        return;
    }

    ea_t ea1 = static_cast<ea_t>(argv[0].as_int64());
    ea_t ea2 = static_cast<ea_t>(argv[1].as_int64());
    const char* path = argv[2].as_c_str();
    if (!path) {
        ctx.result_error("Invalid path");
        return;
    }

    int result = gen_file_helper(OFILE_ASM, path, ea1, ea2, 0);
    ctx.result_int(result);
}

// gen_lst_file(ea1, ea2, path) - Generate listing file with addresses
static void sql_gen_lst_file(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("gen_lst_file requires 3 arguments (ea1, ea2, path)");
        return;
    }

    ea_t ea1 = static_cast<ea_t>(argv[0].as_int64());
    ea_t ea2 = static_cast<ea_t>(argv[1].as_int64());
    const char* path = argv[2].as_c_str();
    if (!path) {
        ctx.result_error("Invalid path");
        return;
    }

    int result = gen_file_helper(OFILE_LST, path, ea1, ea2, 0);
    ctx.result_int(result);
}

// gen_map_file(path) - Generate MAP file
static void sql_gen_map_file(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("gen_map_file requires 1 argument (path)");
        return;
    }

    const char* path = argv[0].as_c_str();
    if (!path) {
        ctx.result_error("Invalid path");
        return;
    }

    // MAP files ignore ea1/ea2, use GENFLG_MAPSEG | GENFLG_MAPNAME
    int flags = GENFLG_MAPSEG | GENFLG_MAPNAME | GENFLG_MAPDMNG;
    int result = gen_file_helper(OFILE_MAP, path, 0, BADADDR, flags);
    ctx.result_int(result);
}

// gen_idc_file(ea1, ea2, path) - Generate IDC script
static void sql_gen_idc_file(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("gen_idc_file requires 3 arguments (ea1, ea2, path)");
        return;
    }

    ea_t ea1 = static_cast<ea_t>(argv[0].as_int64());
    ea_t ea2 = static_cast<ea_t>(argv[1].as_int64());
    const char* path = argv[2].as_c_str();
    if (!path) {
        ctx.result_error("Invalid path");
        return;
    }

    int result = gen_file_helper(OFILE_IDC, path, ea1, ea2, 0);
    ctx.result_int(result);
}

// gen_html_file(ea1, ea2, path) - Generate HTML listing
static void sql_gen_html_file(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("gen_html_file requires 3 arguments (ea1, ea2, path)");
        return;
    }

    ea_t ea1 = static_cast<ea_t>(argv[0].as_int64());
    ea_t ea2 = static_cast<ea_t>(argv[1].as_int64());
    const char* path = argv[2].as_c_str();
    if (!path) {
        ctx.result_error("Invalid path");
        return;
    }

    int result = gen_file_helper(OFILE_LST, path, ea1, ea2, GENFLG_GENHTML);
    ctx.result_int(result);
}

// gen_cfg_dot(address) - Generate CFG as DOT string
static void sql_gen_cfg_dot(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("gen_cfg_dot requires 1 argument (func_address)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    func_t* func = get_func(ea);
    if (!func) {
        ctx.result_error("No function at address");
        return;
    }

    // Build DOT representation using FlowChart
    qflow_chart_t fc;
    fc.create("", func, func->start_ea, func->end_ea, FC_NOEXT);

    qstring func_name;
    get_func_name(&func_name, func->start_ea);
    if (func_name.empty()) {
        func_name.sprnt("sub_%llX", (uint64)func->start_ea);
    }

    std::ostringstream dot;
    dot << "digraph CFG {\n";
    dot << "  node [shape=box, fontname=\"Courier\"];\n";
    dot << "  label=\"" << func_name.c_str() << "\";\n\n";

    // Emit nodes
    for (int i = 0; i < fc.size(); i++) {
        const qbasic_block_t& bb = fc.blocks[i];
        dot << "  n" << i << " [label=\"";
        dot << std::hex << "0x" << bb.start_ea << " - 0x" << bb.end_ea;
        dot << "\"];\n";
    }

    dot << "\n";

    // Emit edges
    for (int i = 0; i < fc.size(); i++) {
        const qbasic_block_t& bb = fc.blocks[i];
        for (int j = 0; j < bb.succ.size(); j++) {
            dot << "  n" << i << " -> n" << bb.succ[j] << ";\n";
        }
    }

    dot << "}\n";

    std::string str = dot.str();
    ctx.result_text(str);
}

// gen_cfg_dot_file(address, path) - Generate CFG DOT to file
static void sql_gen_cfg_dot_file(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("gen_cfg_dot_file requires 2 arguments (func_address, path)");
        return;
    }

    ea_t ea = static_cast<ea_t>(argv[0].as_int64());
    const char* path = argv[1].as_c_str();
    if (!path) {
        ctx.result_error("Invalid path");
        return;
    }

    func_t* func = get_func(ea);
    if (!func) {
        ctx.result_error("No function at address");
        return;
    }

    // Build DOT using FlowChart
    qflow_chart_t fc;
    fc.create("", func, func->start_ea, func->end_ea, FC_NOEXT);

    qstring func_name;
    get_func_name(&func_name, func->start_ea);
    if (func_name.empty()) {
        func_name.sprnt("sub_%llX", (uint64)func->start_ea);
    }

    FILE* fp = qfopen(path, "w");
    if (!fp) {
        ctx.result_error("Failed to open file");
        return;
    }

    qfprintf(fp, "digraph CFG {\n");
    qfprintf(fp, "  node [shape=box, fontname=\"Courier\"];\n");
    qfprintf(fp, "  label=\"%s\";\n\n", func_name.c_str());

    // Emit nodes
    for (int i = 0; i < fc.size(); i++) {
        const qbasic_block_t& bb = fc.blocks[i];
        qfprintf(fp, "  n%d [label=\"0x%llX - 0x%llX\"];\n",
                 i, (uint64)bb.start_ea, (uint64)bb.end_ea);
    }

    qfprintf(fp, "\n");

    // Emit edges
    for (int i = 0; i < fc.size(); i++) {
        const qbasic_block_t& bb = fc.blocks[i];
        for (int j = 0; j < bb.succ.size(); j++) {
            qfprintf(fp, "  n%d -> n%d;\n", i, bb.succ[j]);
        }
    }

    qfprintf(fp, "}\n");
    qfclose(fp);

    ctx.result_int(1);  // Success
}

inline std::string escape_sql_text(const char* in);

// gen_schema_dot(db) - Generate DOT diagram of all tables
// This uses SQLite introspection to build the schema
static void sql_gen_schema_dot(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    std::ostringstream dot;
    dot << "digraph IDASQL_Schema {\n";
    dot << "  rankdir=TB;\n";
    dot << "  node [shape=record, fontname=\"Helvetica\", fontsize=10];\n";
    dot << "  edge [fontname=\"Helvetica\", fontsize=8];\n\n";

    // Query all tables from sqlite_master
    std::vector<std::string> tables;
    std::string schema_err;
    if (!ctx.query_each(
            "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY name",
            [&](const xsql::QueryRow& row) {
                const char* name = row.text(0);
                const char* type = row.text(1);
                if (!name) return;

                tables.push_back(name);

                // Get column info for this table
                std::string pragma = "PRAGMA table_info('" + escape_sql_text(name) + "')";
                bool emitted = false;
                bool first = true;
                ctx.query_each(pragma, [&](const xsql::QueryRow& col_row) {
                    if (!emitted) {
                        dot << "  " << name << " [label=\"{" << name;
                        if (type && strcmp(type, "view") == 0) dot << " (view)";
                        dot << "|";
                        emitted = true;
                    }

                    const char* col_name = col_row.text(1);
                    const char* col_type = col_row.text(2);
                    if (!first) dot << "\\l";
                    first = false;
                    dot << (col_name ? col_name : "?");
                    if (col_type && strlen(col_type) > 0) {
                        dot << " : " << col_type;
                    }
                });

                if (emitted) {
                    dot << "\\l}\"];\n";
                }
            },
            &schema_err)) {
        ctx.result_error("Failed to query schema: " + schema_err);
        return;
    }

    // Add relationships based on naming conventions
    dot << "\n  // Relationships (inferred from naming)\n";

    // Common relationships in IDA
    for (const auto& t : tables) {
        if (t == "funcs" || t == "funcs_live") {
            dot << "  segments -> " << t << " [label=\"contains\"];\n";
        }
        if (t == "names" || t == "names_live") {
            dot << "  segments -> " << t << " [label=\"contains\"];\n";
        }
        if (t == "strings") {
            dot << "  segments -> strings [label=\"contains\"];\n";
        }
        if (t == "xrefs") {
            dot << "  funcs -> xrefs [label=\"has\"];\n";
            dot << "  xrefs -> names [label=\"references\"];\n";
        }
        if (t == "blocks") {
            dot << "  funcs -> blocks [label=\"contains\"];\n";
        }
        if (t == "comments_live") {
            dot << "  funcs -> comments_live [label=\"has\"];\n";
        }
    }

    dot << "}\n";

    std::string str = dot.str();
    ctx.result_text(str);
}

// ============================================================================
// Decompiler Lvar Functions (requires Hex-Rays)
// ============================================================================

inline xsql::json lvar_rename_result_json(const decompiler::LvarRenameResult& r) {
    xsql::json j = {
        {"success", r.success},
        {"applied", r.applied},
        {"func_addr", r.func_addr},
        {"lvar_idx", r.lvar_idx},
        {"target_name", r.target_name},
        {"requested_name", r.requested_name},
        {"before_name", r.before_name},
        {"after_name", r.after_name},
        {"reason", r.reason.empty() ? xsql::json(nullptr) : xsql::json(r.reason)}
    };
    j["warnings"] = r.warnings;
    return j;
}

// rename_lvar(func_addr, lvar_idx, new_name) - Rename a local variable
// Uses locator-based rename_lvar_at() for precise identification by index.
// Returns JSON with result details.
static void sql_rename_lvar(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("rename_lvar requires 3 arguments (func_addr, lvar_idx, new_name)");
        return;
    }

    ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    int lvar_idx = argv[1].as_int();
    const char* new_name = argv[2].as_c_str();

    if (!new_name) {
        ctx.result_error("Invalid name");
        return;
    }

    decompiler::LvarRenameResult result = decompiler::rename_lvar_at_ex(func_addr, lvar_idx, new_name);
    std::string out = lvar_rename_result_json(result).dump();
    ctx.result_text(out);
}

// rename_lvar_by_name(func_addr, old_name, new_name) - Rename local variable by current name.
// Returns JSON with success/applied details, explicit reasons, and warnings.
static void sql_rename_lvar_by_name(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("rename_lvar_by_name requires 3 arguments (func_addr, old_name, new_name)");
        return;
    }

    ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    const char* old_name = argv[1].as_c_str();
    const char* new_name = argv[2].as_c_str();

    if (!old_name || !new_name) {
        ctx.result_error("Invalid name");
        return;
    }

    decompiler::LvarRenameResult result = decompiler::rename_lvar_by_name_ex(func_addr, old_name, new_name);
    std::string out = lvar_rename_result_json(result).dump();
    ctx.result_text(out);
}

// set_lvar_comment(func_addr, lvar_idx, comment) - Set local variable comment by index.
// Returns 1 on success, 0 on failure.
static void sql_set_lvar_comment(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("set_lvar_comment requires 3 arguments (func_addr, lvar_idx, comment)");
        return;
    }

    ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    int lvar_idx = argv[1].as_int();
    const char* comment = argv[2].is_null() ? "" : argv[2].as_c_str();

    bool ok = decompiler::set_lvar_comment_at(func_addr, lvar_idx, comment ? comment : "");
    ctx.result_int(ok ? 1 : 0);
}

static std::string trim_copy(const std::string& text) {
    size_t begin = 0;
    size_t end = text.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
        ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1])) != 0) {
        --end;
    }
    return text.substr(begin, end - begin);
}

static bool parse_int_token(const std::string& token, int& out_value) {
    const std::string t = trim_copy(token);
    if (t.empty()) return false;
    char* end_ptr = nullptr;
    const long value = std::strtol(t.c_str(), &end_ptr, 10);
    if (end_ptr == nullptr || *end_ptr != '\0') return false;
    out_value = static_cast<int>(value);
    return true;
}

static bool parse_union_path_spec(const char* spec, intvec_t& out_path, std::string& error) {
    error.clear();
    out_path.clear();

    if (!spec) {
        return true;  // Empty path clears selection.
    }

    const std::string text = trim_copy(spec);
    if (text.empty()) {
        return true;  // Empty path clears selection.
    }

    if (!text.empty() && text[0] == '[') {
        try {
            xsql::json j = xsql::json::parse(text);
            if (!j.is_array()) {
                error = "path must be a JSON array";
                return false;
            }
            for (const auto& v : j) {
                if (!v.is_number_integer()) {
                    error = "path JSON array must contain integers";
                    return false;
                }
                out_path.push_back(v.get<int>());
            }
            return true;
        } catch (const std::exception& ex) {
            error = std::string("invalid path JSON: ") + ex.what();
            return false;
        }
    }

    size_t start = 0;
    while (start <= text.size()) {
        const size_t comma = text.find(',', start);
        const size_t end = (comma == std::string::npos) ? text.size() : comma;
        const std::string token = text.substr(start, end - start);
        int value = 0;
        if (!parse_int_token(token, value)) {
            error = "path must be comma-separated integers or JSON array";
            return false;
        }
        out_path.push_back(value);
        if (comma == std::string::npos) break;
        start = comma + 1;
    }

    return true;
}

static std::string union_path_to_json(const intvec_t& path) {
    xsql::json arr = xsql::json::array();
    for (int value : path) {
        arr.push_back(value);
    }
    return arr.dump();
}

struct CallArgResolution {
    bool ok = false;
    ea_t func_addr = BADADDR;
    ea_t ea = BADADDR;
    int arg_idx = -1;
    int call_item_id = -1;
    int arg_item_id = -1;
    std::string callee;
    int candidate_count = 0;
    std::string diagnostic;
};

static bool equals_ci(const std::string& lhs, const std::string& rhs) {
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i) {
        const unsigned char a = static_cast<unsigned char>(lhs[i]);
        const unsigned char b = static_cast<unsigned char>(rhs[i]);
        if (std::tolower(a) != std::tolower(b)) return false;
    }
    return true;
}

static std::string sql_single_quote_escape(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 4);
    for (char ch : text) {
        if (ch == '\'') out += "''";
        else out.push_back(ch);
    }
    return out;
}

static std::string call_arg_resolution_hint_sql(ea_t func_addr, ea_t ea, int arg_idx) {
    std::ostringstream oss;
    oss
        << "SELECT a.call_item_id, a.arg_idx, a.arg_item_id, a.call_ea AS ea, "
        << "COALESCE(NULLIF(a.call_obj_name,''), a.call_helper_name, '') AS callee "
        << "FROM ctree_call_args a "
        << "WHERE a.func_addr = " << static_cast<uint64_t>(func_addr)
        << " AND a.call_ea = " << static_cast<uint64_t>(ea)
        << " AND a.arg_idx = " << arg_idx
        << " ORDER BY a.call_item_id, a.arg_idx";
    return oss.str();
}

static CallArgResolution resolve_call_arg_item(
        ea_t requested_func_addr,
        ea_t target_ea,
        int arg_idx,
        const char* callee_filter_raw) {
    CallArgResolution out;
    out.ea = target_ea;
    out.arg_idx = arg_idx;

    if (!decompiler::hexrays_available()) {
        out.diagnostic = "Hex-Rays not available";
        return out;
    }
    if (target_ea == BADADDR || target_ea == 0) {
        out.diagnostic = "ea must be a valid non-zero address";
        return out;
    }
    if (arg_idx < 0) {
        out.diagnostic = "arg_idx must be >= 0";
        return out;
    }

    func_t* f = get_func(target_ea);
    if (!f) {
        out.diagnostic = "ea is not inside a function";
        return out;
    }

    const ea_t inferred_func_addr = f->start_ea;
    if (requested_func_addr != 0 && requested_func_addr != inferred_func_addr) {
        out.diagnostic = "func_addr does not match the function that contains ea";
        return out;
    }
    out.func_addr = inferred_func_addr;

    const std::string callee_filter = trim_copy(callee_filter_raw ? callee_filter_raw : "");
    std::vector<decompiler::CallArgInfo> args;
    if (!decompiler::collect_call_args(args, out.func_addr)) {
        out.diagnostic = "failed to collect ctree call args";
        return out;
    }

    struct Candidate {
        int call_item_id = -1;
        int arg_item_id = -1;
        std::string callee;
    };
    std::vector<Candidate> matches;
    matches.reserve(8);

    for (const auto& ai : args) {
        if (ai.arg_idx != arg_idx) continue;
        if (ai.call_ea != target_ea) continue;

        std::string callee_name;
        if (!ai.call_obj_name.empty()) {
            callee_name = ai.call_obj_name;
        } else if (!ai.call_helper_name.empty()) {
            callee_name = ai.call_helper_name;
        }

        if (!callee_filter.empty() && !equals_ci(callee_name, callee_filter)) {
            continue;
        }

        matches.push_back(Candidate{ai.call_item_id, ai.arg_item_id, callee_name});
    }

    out.candidate_count = static_cast<int>(matches.size());
    if (matches.empty()) {
        std::ostringstream msg;
        msg << "no matching call argument for func_addr=" << static_cast<uint64_t>(out.func_addr)
            << ", ea=" << static_cast<uint64_t>(target_ea)
            << ", arg_idx=" << arg_idx;
        if (!callee_filter.empty()) {
            msg << ", callee='" << callee_filter << "'";
        }
        msg << ". hint: " << call_arg_resolution_hint_sql(out.func_addr, target_ea, arg_idx);
        out.diagnostic = msg.str();
        return out;
    }

    if (matches.size() > 1) {
        std::ostringstream msg;
        msg << "ambiguous call argument resolution (" << matches.size()
            << " matches) for func_addr=" << static_cast<uint64_t>(out.func_addr)
            << ", ea=" << static_cast<uint64_t>(target_ea)
            << ", arg_idx=" << arg_idx;
        if (!callee_filter.empty()) {
            msg << ", callee='" << callee_filter << "'";
        }
        msg << ". hint: pass callee or use *_item() with arg_item_id from: "
            << call_arg_resolution_hint_sql(out.func_addr, target_ea, arg_idx);
        out.diagnostic = msg.str();
        return out;
    }

    out.ok = true;
    out.call_item_id = matches[0].call_item_id;
    out.arg_item_id = matches[0].arg_item_id;
    out.callee = matches[0].callee;
    return out;
}

struct CtreeExprResolution {
    bool ok = false;
    ea_t func_addr = BADADDR;
    ea_t ea = BADADDR;
    std::string op_name;
    int nth = 0;
    bool nth_explicit = false;
    int item_id = -1;
    int candidate_count = 0;
    std::string diagnostic;
};

static std::string ctree_expr_resolution_hint_sql(
        ea_t func_addr,
        ea_t ea,
        const std::string& op_name_filter) {
    std::ostringstream oss;
    oss
        << "SELECT item_id, is_expr, op_name, depth, var_idx, var_name, obj_ea, obj_name, num_value, member_offset "
        << "FROM ctree "
        << "WHERE func_addr = " << static_cast<uint64_t>(func_addr)
        << " AND ea = " << static_cast<uint64_t>(ea)
        << " AND is_expr = 1";
    if (!op_name_filter.empty()) {
        oss << " AND op_name = '" << sql_single_quote_escape(op_name_filter) << "'";
    }
    oss << " ORDER BY depth, item_id";
    return oss.str();
}

static CtreeExprResolution resolve_ctree_expr_item(
        ea_t requested_func_addr,
        ea_t target_ea,
        const char* op_name_filter_raw,
        bool nth_explicit,
        int nth) {
    CtreeExprResolution out;
    out.ea = target_ea;
    out.nth = nth;
    out.nth_explicit = nth_explicit;

    if (!decompiler::hexrays_available()) {
        out.diagnostic = "Hex-Rays not available";
        return out;
    }
    if (target_ea == BADADDR || target_ea == 0) {
        out.diagnostic = "ea must be a valid non-zero address";
        return out;
    }
    if (nth_explicit && nth < 0) {
        out.diagnostic = "nth must be >= 0";
        return out;
    }

    func_t* f = get_func(target_ea);
    if (!f) {
        out.diagnostic = "ea is not inside a function";
        return out;
    }

    const ea_t inferred_func_addr = f->start_ea;
    if (requested_func_addr != 0 && requested_func_addr != inferred_func_addr) {
        out.diagnostic = "func_addr does not match the function that contains ea";
        return out;
    }
    out.func_addr = inferred_func_addr;

    const std::string op_name_filter = trim_copy(op_name_filter_raw ? op_name_filter_raw : "");
    out.op_name = op_name_filter;

    std::vector<decompiler::CtreeItem> items;
    if (!decompiler::collect_ctree(items, out.func_addr)) {
        out.diagnostic = "failed to collect ctree items";
        return out;
    }

    struct Candidate {
        int item_id = -1;
        int depth = 0;
    };
    std::vector<Candidate> matches;
    matches.reserve(16);

    for (const auto& item : items) {
        if (!item.is_expr) continue;
        if (item.ea != target_ea) continue;
        if (!op_name_filter.empty() && !equals_ci(item.op_name, op_name_filter)) continue;
        matches.push_back(Candidate{item.item_id, item.depth});
    }

    std::sort(matches.begin(), matches.end(),
        [](const Candidate& a, const Candidate& b) {
            if (a.depth != b.depth) return a.depth < b.depth;
            return a.item_id < b.item_id;
        });

    out.candidate_count = static_cast<int>(matches.size());
    if (matches.empty()) {
        std::ostringstream msg;
        msg << "no matching expression for func_addr=" << static_cast<uint64_t>(out.func_addr)
            << ", ea=" << static_cast<uint64_t>(target_ea);
        if (!op_name_filter.empty()) {
            msg << ", op_name='" << op_name_filter << "'";
        }
        msg << ". hint: " << ctree_expr_resolution_hint_sql(out.func_addr, target_ea, op_name_filter);
        out.diagnostic = msg.str();
        return out;
    }

    if (!nth_explicit && matches.size() > 1) {
        std::ostringstream msg;
        msg << "ambiguous expression resolution (" << matches.size()
            << " matches) for func_addr=" << static_cast<uint64_t>(out.func_addr)
            << ", ea=" << static_cast<uint64_t>(target_ea);
        if (!op_name_filter.empty()) {
            msg << ", op_name='" << op_name_filter << "'";
        }
        msg << ". hint: pass nth or use item_id from: "
            << ctree_expr_resolution_hint_sql(out.func_addr, target_ea, op_name_filter);
        out.diagnostic = msg.str();
        return out;
    }

    const int index = nth_explicit ? nth : 0;
    if (index < 0 || index >= static_cast<int>(matches.size())) {
        std::ostringstream msg;
        msg << "nth out of range (" << index << ") for " << matches.size() << " candidate(s)"
            << " at func_addr=" << static_cast<uint64_t>(out.func_addr)
            << ", ea=" << static_cast<uint64_t>(target_ea);
        if (!op_name_filter.empty()) {
            msg << ", op_name='" << op_name_filter << "'";
        }
        msg << ". hint: " << ctree_expr_resolution_hint_sql(out.func_addr, target_ea, op_name_filter);
        out.diagnostic = msg.str();
        return out;
    }

    out.ok = true;
    out.item_id = matches[static_cast<size_t>(index)].item_id;
    return out;
}

static bool normalize_func_for_ea(ea_t requested_func_addr, ea_t target_ea, ea_t& out_func_addr) {
    out_func_addr = BADADDR;
    if (target_ea == BADADDR || target_ea == 0) return false;
    func_t* f = get_func(target_ea);
    if (!f) return false;
    out_func_addr = f->start_ea;
    if (requested_func_addr != 0 && requested_func_addr != out_func_addr) return false;
    return true;
}

static bool synthesize_numform_from_operand_representation(ea_t target_ea, int opnum, number_format_t& out_fmt) {
    const std::string kind = entities::operand_repr_kind_text(target_ea, opnum);
    if (kind != "enum" && kind != "stroff") {
        return false;
    }

    out_fmt = number_format_t(opnum);
    const flags64_t flags = get_flags(target_ea);
    out_fmt.flags = flags;
    out_fmt.flags32 = static_cast<flags_t>(flags);
    out_fmt.props = static_cast<char>(NF_FIXED | NF_VALID);
    out_fmt.serial = 0;
    out_fmt.type_name = entities::operand_repr_type_name_text(target_ea, opnum).c_str();

    if (kind == "enum") {
        out_fmt.serial = static_cast<uchar>(entities::operand_enum_serial(target_ea, opnum));
    }

    return true;
}

static bool set_user_numform_at_ea(ea_t requested_func_addr, ea_t target_ea, int opnum, const entities::OperandApplyRequest& req) {
    if (!decompiler::hexrays_available()) return false;
    if (opnum < 0 || opnum >= UA_MAXOP) return false;
    if (req.kind == entities::OperandApplyKind::None) return true;  // Explicit no-op for empty spec.

    ea_t func_addr = BADADDR;
    if (!normalize_func_for_ea(requested_func_addr, target_ea, func_addr)) return false;

    // Keep disassembly and decompiler layers consistent first.
    if (!entities::apply_operand_representation(target_ea, opnum, req)) return false;

    user_numforms_t* numforms = nullptr;
    bool metadata_ok = false;
    try {
        numforms = restore_user_numforms(func_addr);
        if (!numforms) {
            numforms = user_numforms_new();
            if (!numforms) return false;
        }

        const operand_locator_t loc(target_ea, opnum);
        const auto end = user_numforms_end(numforms);
        auto it = user_numforms_find(numforms, loc);

        if (req.kind == entities::OperandApplyKind::Clear) {
            if (it != end) {
                user_numforms_erase(numforms, it);
            }
            metadata_ok = true;
        } else {
            number_format_t fmt(opnum);
            metadata_ok = synthesize_numform_from_operand_representation(target_ea, opnum, fmt);
            if (metadata_ok) {
                if (it == end) {
                    user_numforms_insert(numforms, loc, fmt);
                } else {
                    user_numforms_second(it) = fmt;
                }
            }
        }

        if (metadata_ok) {
            save_user_numforms(func_addr, numforms);
        }
    } catch (...) {
        metadata_ok = false;
    }

    if (numforms) {
        user_numforms_free(numforms);
    }
    decompiler::invalidate_decompiler_cache(func_addr);
    // Representation apply already succeeded above; treat numform persistence as best-effort.
    // Some databases may not persist user_numforms for specific operands, but callers should
    // still observe the live representation change via decompile()/instructions.
    return true;
}

static bool get_user_numform_at_ea(ea_t requested_func_addr, ea_t target_ea, int opnum, number_format_t& out_fmt) {
    out_fmt = number_format_t(opnum);
    if (!decompiler::hexrays_available()) return false;
    if (opnum < 0 || opnum >= UA_MAXOP) return false;

    ea_t func_addr = BADADDR;
    if (!normalize_func_for_ea(requested_func_addr, target_ea, func_addr)) return false;

    user_numforms_t* numforms = nullptr;
    bool found = false;
    try {
        numforms = restore_user_numforms(func_addr);
        if (numforms) {
            const operand_locator_t loc(target_ea, opnum);
            auto it = user_numforms_find(numforms, loc);
            found = (it != user_numforms_end(numforms));
            if (found) {
                out_fmt = user_numforms_second(it);
            }
        }

        if (!found) {
            found = synthesize_numform_from_operand_representation(target_ea, opnum, out_fmt);
        }
    } catch (...) {
        found = false;
    }
    if (numforms) {
        user_numforms_free(numforms);
    }
    return found;
}

static std::string number_format_kind(const number_format_t& nf) {
    if (nf.is_enum()) return "enum";
    if (nf.is_stroff()) return "stroff";
    if (nf.is_char()) return "char";
    return "num";
}

static std::string numform_to_json(ea_t target_ea, int opnum, const number_format_t& nf) {
    xsql::json obj = {
        {"ea", static_cast<int64_t>(target_ea)},
        {"opnum", opnum},
        {"kind", number_format_kind(nf)},
        {"type_name", std::string(nf.type_name.c_str())},
        {"serial", static_cast<int>(nf.serial)},
        {"props", static_cast<int>(static_cast<unsigned char>(nf.props))},
        {"fixed", (nf.props & NF_FIXED) != 0},
        {"valid", (nf.props & NF_VALID) != 0}
    };
    if (nf.is_stroff()) {
        obj["delta"] = entities::operand_stroff_delta(target_ea, opnum);
    } else {
        obj["delta"] = 0;
    }
    return obj.dump();
}

// set_union_selection(func_addr, ea, path) - Set/clear union selection path at ea.
// path format: JSON array (e.g. "[0,1]") or CSV ("0,1"); empty/null clears.
static void sql_set_union_selection(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("set_union_selection requires 3 arguments (func_addr, ea, path)");
        return;
    }

    ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());
    const char* path_spec = argv[2].is_null() ? "" : argv[2].as_c_str();

    intvec_t path;
    std::string parse_error;
    if (!parse_union_path_spec(path_spec, path, parse_error)) {
        ctx.result_error(parse_error);
        return;
    }

    bool ok = decompiler::set_union_selection_at_ea(func_addr, target_ea, path);
    ctx.result_int(ok ? 1 : 0);
}

// set_union_selection_item(func_addr, item_id, path) - Set/clear by ctree item id.
static void sql_set_union_selection_item(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("set_union_selection_item requires 3 arguments (func_addr, item_id, path)");
        return;
    }

    ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    int item_id = argv[1].as_int();
    const char* path_spec = argv[2].is_null() ? "" : argv[2].as_c_str();

    intvec_t path;
    std::string parse_error;
    if (!parse_union_path_spec(path_spec, path, parse_error)) {
        ctx.result_error(parse_error);
        return;
    }

    bool ok = decompiler::set_union_selection_at_item(func_addr, item_id, path);
    ctx.result_int(ok ? 1 : 0);
}

// get_union_selection(func_addr, ea) - Get union path JSON at ea, or NULL if unset.
static void sql_get_union_selection(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("get_union_selection requires 2 arguments (func_addr, ea)");
        return;
    }

    ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());

    intvec_t path;
    bool found = decompiler::get_union_selection_at_ea(func_addr, target_ea, path);
    if (!found) {
        ctx.result_null();
        return;
    }

    ctx.result_text(union_path_to_json(path));
}

// get_union_selection_item(func_addr, item_id) - Get union path JSON by ctree item id.
static void sql_get_union_selection_item(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("get_union_selection_item requires 2 arguments (func_addr, item_id)");
        return;
    }

    ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    int item_id = argv[1].as_int();
    ea_t target_ea = BADADDR;
    if (!decompiler::get_ctree_item_ea(func_addr, item_id, target_ea)) {
        ctx.result_null();
        return;
    }

    intvec_t path;
    bool found = decompiler::get_union_selection_at_ea(func_addr, target_ea, path);
    if (!found) {
        ctx.result_null();
        return;
    }

    ctx.result_text(union_path_to_json(path));
}

// set_union_selection_ea_arg(func_addr, ea, arg_idx, path[, callee]) - Resolve arg item by call-site coordinate.
static void sql_set_union_selection_ea_arg(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 4) {
        ctx.result_error("set_union_selection_ea_arg requires 4-5 arguments (func_addr, ea, arg_idx, path, [callee])");
        return;
    }

    const ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    const ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());
    const int arg_idx = argv[2].as_int();
    const char* path_spec = argv[3].is_null() ? "" : argv[3].as_c_str();
    const char* callee = (argc >= 5 && !argv[4].is_null()) ? argv[4].as_c_str() : "";

    intvec_t path;
    std::string parse_error;
    if (!parse_union_path_spec(path_spec, path, parse_error)) {
        ctx.result_error(parse_error);
        return;
    }

    const CallArgResolution resolved = resolve_call_arg_item(func_addr, target_ea, arg_idx, callee);
    if (!resolved.ok) {
        ctx.result_error(resolved.diagnostic);
        return;
    }

    const bool ok = decompiler::set_union_selection_at_item(resolved.func_addr, resolved.arg_item_id, path);
    ctx.result_int(ok ? 1 : 0);
}

// get_union_selection_ea_arg(func_addr, ea, arg_idx[, callee]) - Resolve arg item and read union selection.
static void sql_get_union_selection_ea_arg(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("get_union_selection_ea_arg requires 3-4 arguments (func_addr, ea, arg_idx, [callee])");
        return;
    }

    const ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    const ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());
    const int arg_idx = argv[2].as_int();
    const char* callee = (argc >= 4 && !argv[3].is_null()) ? argv[3].as_c_str() : "";

    const CallArgResolution resolved = resolve_call_arg_item(func_addr, target_ea, arg_idx, callee);
    if (!resolved.ok) {
        ctx.result_error(resolved.diagnostic);
        return;
    }

    ea_t item_ea = BADADDR;
    if (!decompiler::get_ctree_item_ea(resolved.func_addr, resolved.arg_item_id, item_ea)) {
        ctx.result_null();
        return;
    }

    intvec_t path;
    const bool found = decompiler::get_union_selection_at_ea(resolved.func_addr, item_ea, path);
    if (!found) {
        ctx.result_null();
        return;
    }
    ctx.result_text(union_path_to_json(path));
}

// call_arg_item(func_addr, ea, arg_idx[, callee]) - Resolve call-arg coordinate to explicit ctree arg_item_id.
static void sql_call_arg_item(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("call_arg_item requires 3-4 arguments (func_addr, ea, arg_idx, [callee])");
        return;
    }

    const ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    const ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());
    const int arg_idx = argv[2].as_int();
    const char* callee = (argc >= 4 && !argv[3].is_null()) ? argv[3].as_c_str() : "";

    const CallArgResolution resolved = resolve_call_arg_item(func_addr, target_ea, arg_idx, callee);
    if (!resolved.ok) {
        ctx.result_error(resolved.diagnostic);
        return;
    }

    ctx.result_int(resolved.arg_item_id);
}

// ctree_item_at(func_addr, ea[, op_name[, nth]]) - Resolve generic expression coordinate to ctree item id.
static void sql_ctree_item_at(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("ctree_item_at requires 2-4 arguments (func_addr, ea, [op_name], [nth])");
        return;
    }

    const ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    const ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());
    const char* op_name = (argc >= 3 && !argv[2].is_null()) ? argv[2].as_c_str() : "";
    const bool nth_explicit = (argc >= 4);
    const int nth = nth_explicit ? argv[3].as_int() : 0;

    const CtreeExprResolution resolved =
        resolve_ctree_expr_item(func_addr, target_ea, op_name, nth_explicit, nth);
    if (!resolved.ok) {
        ctx.result_error(resolved.diagnostic);
        return;
    }

    ctx.result_int(resolved.item_id);
}

// set_union_selection_ea_expr(func_addr, ea, path[, op_name[, nth]]) - Resolve expr item and set/clear path.
static void sql_set_union_selection_ea_expr(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("set_union_selection_ea_expr requires 3-5 arguments (func_addr, ea, path, [op_name], [nth])");
        return;
    }

    const ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    const ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());
    const char* path_spec = argv[2].is_null() ? "" : argv[2].as_c_str();
    const char* op_name = (argc >= 4 && !argv[3].is_null()) ? argv[3].as_c_str() : "";
    const bool nth_explicit = (argc >= 5);
    const int nth = nth_explicit ? argv[4].as_int() : 0;

    intvec_t path;
    std::string parse_error;
    if (!parse_union_path_spec(path_spec, path, parse_error)) {
        ctx.result_error(parse_error);
        return;
    }

    const CtreeExprResolution resolved =
        resolve_ctree_expr_item(func_addr, target_ea, op_name, nth_explicit, nth);
    if (!resolved.ok) {
        ctx.result_error(resolved.diagnostic);
        return;
    }

    const bool ok = decompiler::set_union_selection_at_item(resolved.func_addr, resolved.item_id, path);
    ctx.result_int(ok ? 1 : 0);
}

// get_union_selection_ea_expr(func_addr, ea[, op_name[, nth]]) - Resolve expr item and read union path JSON.
static void sql_get_union_selection_ea_expr(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 2) {
        ctx.result_error("get_union_selection_ea_expr requires 2-4 arguments (func_addr, ea, [op_name], [nth])");
        return;
    }

    const ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    const ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());
    const char* op_name = (argc >= 3 && !argv[2].is_null()) ? argv[2].as_c_str() : "";
    const bool nth_explicit = (argc >= 4);
    const int nth = nth_explicit ? argv[3].as_int() : 0;

    const CtreeExprResolution resolved =
        resolve_ctree_expr_item(func_addr, target_ea, op_name, nth_explicit, nth);
    if (!resolved.ok) {
        ctx.result_error(resolved.diagnostic);
        return;
    }

    ea_t item_ea = BADADDR;
    if (!decompiler::get_ctree_item_ea(resolved.func_addr, resolved.item_id, item_ea)) {
        ctx.result_null();
        return;
    }

    intvec_t path;
    const bool found = decompiler::get_union_selection_at_ea(resolved.func_addr, item_ea, path);
    if (!found) {
        ctx.result_null();
        return;
    }
    ctx.result_text(union_path_to_json(path));
}

// set_numform(func_addr, ea, opnum, spec) - Set/clear decompiler number format at ea/opnum.
// spec format matches instructions.operand*_format_spec:
//   clear | plain | none
//   enum:<enum_name>[,serial=<n>]
//   stroff:<udt[/nested_udt...]>[,delta=<n>]
static void sql_set_numform(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 4) {
        ctx.result_error("set_numform requires 4 arguments (func_addr, ea, opnum, spec)");
        return;
    }

    ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());
    int opnum = argv[2].as_int();
    const char* spec = argv[3].is_null() ? "" : argv[3].as_c_str();

    entities::OperandApplyRequest req;
    if (!entities::parse_operand_apply_spec(spec, req)) {
        ctx.result_error("invalid numform spec (expected clear|enum:<name>[,serial=n]|stroff:<type[/nested]>[,delta=n])");
        return;
    }

    bool ok = set_user_numform_at_ea(func_addr, target_ea, opnum, req);
    ctx.result_int(ok ? 1 : 0);
}

// set_numform_item(func_addr, item_id, opnum, spec) - Set/clear number format by ctree item.
static void sql_set_numform_item(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 4) {
        ctx.result_error("set_numform_item requires 4 arguments (func_addr, item_id, opnum, spec)");
        return;
    }

    ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    int item_id = argv[1].as_int();
    int opnum = argv[2].as_int();
    const char* spec = argv[3].is_null() ? "" : argv[3].as_c_str();

    ea_t target_ea = BADADDR;
    if (!decompiler::get_ctree_item_ea(func_addr, item_id, target_ea)) {
        ctx.result_int(0);
        return;
    }

    entities::OperandApplyRequest req;
    if (!entities::parse_operand_apply_spec(spec, req)) {
        ctx.result_error("invalid numform spec (expected clear|enum:<name>[,serial=n]|stroff:<type[/nested]>[,delta=n])");
        return;
    }

    bool ok = set_user_numform_at_ea(func_addr, target_ea, opnum, req);
    ctx.result_int(ok ? 1 : 0);
}

// set_numform_ea_arg(func_addr, ea, arg_idx, opnum, spec[, callee]) - Resolve arg item by call-site coordinate.
static void sql_set_numform_ea_arg(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 5) {
        ctx.result_error("set_numform_ea_arg requires 5-6 arguments (func_addr, ea, arg_idx, opnum, spec, [callee])");
        return;
    }

    const ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    const ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());
    const int arg_idx = argv[2].as_int();
    const int opnum = argv[3].as_int();
    const char* spec = argv[4].is_null() ? "" : argv[4].as_c_str();
    const char* callee = (argc >= 6 && !argv[5].is_null()) ? argv[5].as_c_str() : "";

    entities::OperandApplyRequest req;
    if (!entities::parse_operand_apply_spec(spec, req)) {
        ctx.result_error("invalid numform spec (expected clear|enum:<name>[,serial=n]|stroff:<type[/nested]>[,delta=n])");
        return;
    }

    const CallArgResolution resolved = resolve_call_arg_item(func_addr, target_ea, arg_idx, callee);
    if (!resolved.ok) {
        ctx.result_error(resolved.diagnostic);
        return;
    }

    ea_t item_ea = BADADDR;
    if (!decompiler::get_ctree_item_ea(resolved.func_addr, resolved.arg_item_id, item_ea)) {
        ctx.result_int(0);
        return;
    }

    const bool ok = set_user_numform_at_ea(resolved.func_addr, item_ea, opnum, req);
    ctx.result_int(ok ? 1 : 0);
}

// set_numform_ea_expr(func_addr, ea, opnum, spec[, op_name[, nth]]) - Resolve expr item and set/clear numform.
static void sql_set_numform_ea_expr(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 4) {
        ctx.result_error("set_numform_ea_expr requires 4-6 arguments (func_addr, ea, opnum, spec, [op_name], [nth])");
        return;
    }

    const ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    const ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());
    const int opnum = argv[2].as_int();
    const char* spec = argv[3].is_null() ? "" : argv[3].as_c_str();
    const char* op_name = (argc >= 5 && !argv[4].is_null()) ? argv[4].as_c_str() : "";
    const bool nth_explicit = (argc >= 6);
    const int nth = nth_explicit ? argv[5].as_int() : 0;

    entities::OperandApplyRequest req;
    if (!entities::parse_operand_apply_spec(spec, req)) {
        ctx.result_error("invalid numform spec (expected clear|enum:<name>[,serial=n]|stroff:<type[/nested]>[,delta=n])");
        return;
    }

    const CtreeExprResolution resolved =
        resolve_ctree_expr_item(func_addr, target_ea, op_name, nth_explicit, nth);
    if (!resolved.ok) {
        ctx.result_error(resolved.diagnostic);
        return;
    }

    ea_t item_ea = BADADDR;
    if (!decompiler::get_ctree_item_ea(resolved.func_addr, resolved.item_id, item_ea)) {
        ctx.result_int(0);
        return;
    }

    const bool ok = set_user_numform_at_ea(resolved.func_addr, item_ea, opnum, req);
    ctx.result_int(ok ? 1 : 0);
}

// get_numform(func_addr, ea, opnum) - Get decompiler number format JSON at ea/opnum, or NULL if unset.
static void sql_get_numform(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("get_numform requires 3 arguments (func_addr, ea, opnum)");
        return;
    }

    ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());
    int opnum = argv[2].as_int();

    number_format_t nf(opnum);
    if (!get_user_numform_at_ea(func_addr, target_ea, opnum, nf)) {
        ctx.result_null();
        return;
    }

    ctx.result_text(numform_to_json(target_ea, opnum, nf));
}

// get_numform_item(func_addr, item_id, opnum) - Get number format JSON by ctree item, or NULL if unset.
static void sql_get_numform_item(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("get_numform_item requires 3 arguments (func_addr, item_id, opnum)");
        return;
    }

    ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    int item_id = argv[1].as_int();
    int opnum = argv[2].as_int();

    ea_t target_ea = BADADDR;
    if (!decompiler::get_ctree_item_ea(func_addr, item_id, target_ea)) {
        ctx.result_null();
        return;
    }

    number_format_t nf(opnum);
    if (!get_user_numform_at_ea(func_addr, target_ea, opnum, nf)) {
        ctx.result_null();
        return;
    }

    ctx.result_text(numform_to_json(target_ea, opnum, nf));
}

// get_numform_ea_arg(func_addr, ea, arg_idx, opnum[, callee]) - Resolve arg item and return numform JSON.
static void sql_get_numform_ea_arg(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 4) {
        ctx.result_error("get_numform_ea_arg requires 4-5 arguments (func_addr, ea, arg_idx, opnum, [callee])");
        return;
    }

    const ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    const ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());
    const int arg_idx = argv[2].as_int();
    const int opnum = argv[3].as_int();
    const char* callee = (argc >= 5 && !argv[4].is_null()) ? argv[4].as_c_str() : "";

    const CallArgResolution resolved = resolve_call_arg_item(func_addr, target_ea, arg_idx, callee);
    if (!resolved.ok) {
        ctx.result_error(resolved.diagnostic);
        return;
    }

    ea_t item_ea = BADADDR;
    if (!decompiler::get_ctree_item_ea(resolved.func_addr, resolved.arg_item_id, item_ea)) {
        ctx.result_null();
        return;
    }

    number_format_t nf(opnum);
    if (!get_user_numform_at_ea(resolved.func_addr, item_ea, opnum, nf)) {
        ctx.result_null();
        return;
    }
    ctx.result_text(numform_to_json(item_ea, opnum, nf));
}

// get_numform_ea_expr(func_addr, ea, opnum[, op_name[, nth]]) - Resolve expr item and return numform JSON.
static void sql_get_numform_ea_expr(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 3) {
        ctx.result_error("get_numform_ea_expr requires 3-5 arguments (func_addr, ea, opnum, [op_name], [nth])");
        return;
    }

    const ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());
    const ea_t target_ea = static_cast<ea_t>(argv[1].as_int64());
    const int opnum = argv[2].as_int();
    const char* op_name = (argc >= 4 && !argv[3].is_null()) ? argv[3].as_c_str() : "";
    const bool nth_explicit = (argc >= 5);
    const int nth = nth_explicit ? argv[4].as_int() : 0;

    const CtreeExprResolution resolved =
        resolve_ctree_expr_item(func_addr, target_ea, op_name, nth_explicit, nth);
    if (!resolved.ok) {
        ctx.result_error(resolved.diagnostic);
        return;
    }

    ea_t item_ea = BADADDR;
    if (!decompiler::get_ctree_item_ea(resolved.func_addr, resolved.item_id, item_ea)) {
        ctx.result_null();
        return;
    }

    number_format_t nf(opnum);
    if (!get_user_numform_at_ea(resolved.func_addr, item_ea, opnum, nf)) {
        ctx.result_null();
        return;
    }
    ctx.result_text(numform_to_json(item_ea, opnum, nf));
}

// list_lvars(func_addr) - List local variables for a function as JSON
static void sql_list_lvars(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1) {
        ctx.result_error("list_lvars requires 1 argument (func_addr)");
        return;
    }

    ea_t func_addr = static_cast<ea_t>(argv[0].as_int64());

    // Check cached Hex-Rays availability
    if (!decompiler::hexrays_available()) {
        ctx.result_error("Hex-Rays not available");
        return;
    }

    func_t* f = get_func(func_addr);
    if (!f) {
        ctx.result_error("Function not found");
        return;
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc) {
        std::string err = "Decompilation failed: " + std::string(hf.str.c_str());
        ctx.result_error(err);
        return;
    }

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) {
        ctx.result_text_static("[]");
        return;
    }

    xsql::json arr = xsql::json::array();
    for (size_t i = 0; i < lvars->size(); i++) {
        const lvar_t& lv = (*lvars)[i];
        std::string lv_name = lv.name.c_str();

        qstring type_str;
        lv.type().print(&type_str);

        arr.push_back({
            {"idx", i},
            {"name", lv_name},
            {"type", type_str.c_str()},
            {"comment", lv.cmt.c_str()},
            {"size", lv.width},
            {"is_arg", lv.is_arg_var()},
            {"is_result", lv.is_result_var()},
            {"is_user_nameable", !lv_name.empty()},
            {"displayed_in_pseudocode", !lv_name.empty()},
            {"can_rename", !lv_name.empty()}
        });
    }

    std::string str = arr.dump();
    ctx.result_text(str);
}

// ============================================================================
// Grep Search Function (unified entity search)
// ============================================================================

inline std::string escape_sql_text(const char* in) {
    std::string escaped;
    if (!in) return escaped;
    for (const char* p = in; *p; ++p) {
        if (*p == '\'') escaped += "''";
        else escaped.push_back(*p);
    }
    return escaped;
}

// grep(pattern [, limit [, offset]]) -> JSON array of matching entities.
// Pattern is passed to the grep virtual table's `pattern` column.
static void sql_grep(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 1 || argc > 3) {
        ctx.result_error("grep requires 1-3 arguments (pattern, [limit], [offset])");
        return;
    }

    const char* pattern = argv[0].as_c_str();
    if (!pattern || !pattern[0]) {
        ctx.result_text_static("[]");
        return;
    }

    int limit = 50;
    int offset = 0;
    if (argc >= 2 && !argv[1].is_null()) {
        limit = argv[1].as_int();
    }
    if (argc >= 3 && !argv[2].is_null()) {
        offset = argv[2].as_int();
    }
    if (limit < 0) limit = 0;
    if (limit > 10000) limit = 10000;
    if (offset < 0) offset = 0;

    std::ostringstream query;
    query << "SELECT name, kind, address, ordinal, parent_name, full_name "
          << "FROM grep "
          << "WHERE pattern = '" << escape_sql_text(pattern) << "' "
          << "ORDER BY kind, name "
          << "LIMIT " << limit << " OFFSET " << offset;

    xsql::json arr = xsql::json::array();
    std::string err;
    if (!ctx.query_each(query.str(), [&](const xsql::QueryRow& row) {
        const char* name = row.text(0);
        const char* kind = row.text(1);
        const char* parent = row.text(4);
        const char* full_name = row.text(5);

        xsql::json obj = {
            {"name", name ? name : ""},
            {"kind", kind ? kind : ""},
            {"full_name", full_name ? full_name : ""}
        };

        obj["address"] = row.is_null(2) ? xsql::json(nullptr) : xsql::json(row.int64_value(2));
        obj["ordinal"] = row.is_null(3) ? xsql::json(nullptr) : xsql::json(row.int_value(3));
        obj["parent_name"] = parent ? xsql::json(parent) : xsql::json(nullptr);
        arr.push_back(obj);
    }, &err)) {
        std::string err_msg = "grep query error: " + err;
        ctx.result_error(err_msg);
        return;
    }

    ctx.result_text(arr.dump());
}

// ============================================================================
// String List Functions
// ============================================================================

// rebuild_strings() - Rebuild IDA's string list
// Returns: number of strings found
//
// Args (all optional):
//   min_len: minimum string length (default 5)
//   types: string types bitmask (default 3 = ASCII + UTF-16)
//          1 = ASCII (STRTYPE_C)
//          2 = UTF-16 (STRTYPE_C_16)
//          4 = UTF-32 (STRTYPE_C_32)
//          3 = ASCII + UTF-16 (default)
//          7 = all types
//
// Example:
//   SELECT rebuild_strings();        -- Default: ASCII + UTF-16, minlen 5
//   SELECT rebuild_strings(4);       -- ASCII + UTF-16, minlen 4
//   SELECT rebuild_strings(5, 1);    -- ASCII only, minlen 5
//   SELECT rebuild_strings(5, 7);    -- All types, minlen 5
static void sql_rebuild_strings(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    int min_len = 5;
    int types_mask = 3;  // Default: ASCII + UTF-16

    if (argc >= 1 && !argv[0].is_null()) {
        min_len = argv[0].as_int();
        if (min_len < 1) min_len = 1;
        if (min_len > 1000) min_len = 1000;
    }
    if (argc >= 2 && !argv[1].is_null()) {
        types_mask = argv[1].as_int();
    }

    // Get the options pointer - despite 'const', it IS modifiable (same as Python bindings)
    strwinsetup_t* opts = const_cast<strwinsetup_t*>(get_strlist_options());

    // Configure string types based on mask
    opts->strtypes.clear();
    if (types_mask & 1) opts->strtypes.push_back(STRTYPE_C);      // ASCII
    if (types_mask & 2) opts->strtypes.push_back(STRTYPE_C_16);   // UTF-16
    if (types_mask & 4) opts->strtypes.push_back(STRTYPE_C_32);   // UTF-32

    // Set minimum length
    opts->minlen = min_len;

    // Allow extended ASCII
    opts->only_7bit = 0;

    // Clear and rebuild with new settings
    clear_strlist();
    build_strlist();

    // Invalidate the strings virtual table cache so queries see new data
    entities::TableRegistry::invalidate_strings_cache_global();

    // Return the count
    size_t count = get_strlist_qty();
    ctx.result_int64(static_cast<int64_t>(count));
}

// string_count() - Get current count of strings in IDA's cached list (no rebuild)
static void sql_string_count(xsql::FunctionContext& ctx, int /*argc*/, xsql::FunctionArg* /*argv*/) {
    ctx.result_int64(static_cast<int64_t>(get_strlist_qty()));
}

// ============================================================================
// Database Persistence
// ============================================================================

// save_database() - Persist changes to the IDA database file
// Returns: 1 on success, 0 on failure
static void sql_save_database(xsql::FunctionContext& ctx, int /*argc*/, xsql::FunctionArg* /*argv*/) {
    bool ok = save_database();  // IDA API: save to current file with default flags
    ctx.result_int(ok ? 1 : 0);
}

// ============================================================================
// Registration
// ============================================================================

inline bool register_sql_functions(xsql::Database& db) {
    // Disassembly
    db.register_function("disasm_at", 1, xsql::ScalarFn(sql_disasm_at));
    db.register_function("disasm_at", 2, xsql::ScalarFn(sql_disasm_at));
    db.register_function("disasm", 1, xsql::ScalarFn(sql_disasm));
    db.register_function("disasm", 2, xsql::ScalarFn(sql_disasm));
    db.register_function("disasm_range", 2, xsql::ScalarFn(sql_disasm_range));
    db.register_function("disasm_func", 1, xsql::ScalarFn(sql_disasm_func));

    // Bytes
    db.register_function("bytes", 2, xsql::ScalarFn(sql_bytes_hex));
    db.register_function("bytes_raw", 2, xsql::ScalarFn(sql_bytes_raw));

    // Byte patching
    db.register_function("patch_byte", 2, xsql::ScalarFn(sql_patch_byte));
    db.register_function("patch_word", 2, xsql::ScalarFn(sql_patch_word));
    db.register_function("patch_dword", 2, xsql::ScalarFn(sql_patch_dword));
    db.register_function("patch_qword", 2, xsql::ScalarFn(sql_patch_qword));
    db.register_function("revert_byte", 1, xsql::ScalarFn(sql_revert_byte));
    db.register_function("get_original_byte", 1, xsql::ScalarFn(sql_get_original_byte));

    // Names
    db.register_function("name_at", 1, xsql::ScalarFn(sql_name_at));
    db.register_function("func_at", 1, xsql::ScalarFn(sql_func_at));
    db.register_function("func_start", 1, xsql::ScalarFn(sql_func_start));
    db.register_function("func_end", 1, xsql::ScalarFn(sql_func_end));
    db.register_function("set_name", 2, xsql::ScalarFn(sql_set_name));
    db.register_function("type_at", 1, xsql::ScalarFn(sql_type_at));
    db.register_function("set_type", 2, xsql::ScalarFn(sql_set_type));
    db.register_function("parse_decls", 1, xsql::ScalarFn(sql_parse_decls));

    // Function index (O(1) access)
    db.register_function("func_qty", 0, xsql::ScalarFn(sql_func_qty));
    db.register_function("func_at_index", 1, xsql::ScalarFn(sql_func_at_index));

    // Segments
    db.register_function("segment_at", 1, xsql::ScalarFn(sql_segment_at));

    // Comments
    db.register_function("comment_at", 1, xsql::ScalarFn(sql_comment_at));
    db.register_function("set_comment", 2, xsql::ScalarFn(sql_set_comment));
    db.register_function("set_comment", 3, xsql::ScalarFn(sql_set_comment));

    // Cross-references
    db.register_function("xrefs_to", 1, xsql::ScalarFn(sql_xrefs_to));
    db.register_function("xrefs_from", 1, xsql::ScalarFn(sql_xrefs_from));

    // Decompiler (only registered if Hex-Rays is available)
    if (decompiler::hexrays_available()) {
        db.register_function("decompile", 1, xsql::ScalarFn(sql_decompile));
        db.register_function("decompile", 2, xsql::ScalarFn(sql_decompile_2));
        db.register_function("list_lvars", 1, xsql::ScalarFn(sql_list_lvars));
        db.register_function("rename_lvar", 3, xsql::ScalarFn(sql_rename_lvar));
        db.register_function("rename_lvar_by_name", 3, xsql::ScalarFn(sql_rename_lvar_by_name));
        db.register_function("set_lvar_comment", 3, xsql::ScalarFn(sql_set_lvar_comment));
        db.register_function("set_union_selection", 3, xsql::ScalarFn(sql_set_union_selection));
        db.register_function("set_union_selection_item", 3, xsql::ScalarFn(sql_set_union_selection_item));
        db.register_function("set_union_selection_ea_arg", 4, xsql::ScalarFn(sql_set_union_selection_ea_arg));
        db.register_function("set_union_selection_ea_arg", 5, xsql::ScalarFn(sql_set_union_selection_ea_arg));
        db.register_function("get_union_selection", 2, xsql::ScalarFn(sql_get_union_selection));
        db.register_function("get_union_selection_item", 2, xsql::ScalarFn(sql_get_union_selection_item));
        db.register_function("get_union_selection_ea_arg", 3, xsql::ScalarFn(sql_get_union_selection_ea_arg));
        db.register_function("get_union_selection_ea_arg", 4, xsql::ScalarFn(sql_get_union_selection_ea_arg));
        db.register_function("call_arg_item", 3, xsql::ScalarFn(sql_call_arg_item));
        db.register_function("call_arg_item", 4, xsql::ScalarFn(sql_call_arg_item));
        db.register_function("ctree_item_at", 2, xsql::ScalarFn(sql_ctree_item_at));
        db.register_function("ctree_item_at", 3, xsql::ScalarFn(sql_ctree_item_at));
        db.register_function("ctree_item_at", 4, xsql::ScalarFn(sql_ctree_item_at));
        db.register_function("set_union_selection_ea_expr", 3, xsql::ScalarFn(sql_set_union_selection_ea_expr));
        db.register_function("set_union_selection_ea_expr", 4, xsql::ScalarFn(sql_set_union_selection_ea_expr));
        db.register_function("set_union_selection_ea_expr", 5, xsql::ScalarFn(sql_set_union_selection_ea_expr));
        db.register_function("get_union_selection_ea_expr", 2, xsql::ScalarFn(sql_get_union_selection_ea_expr));
        db.register_function("get_union_selection_ea_expr", 3, xsql::ScalarFn(sql_get_union_selection_ea_expr));
        db.register_function("get_union_selection_ea_expr", 4, xsql::ScalarFn(sql_get_union_selection_ea_expr));
        db.register_function("set_numform", 4, xsql::ScalarFn(sql_set_numform));
        db.register_function("set_numform_item", 4, xsql::ScalarFn(sql_set_numform_item));
        db.register_function("set_numform_ea_arg", 5, xsql::ScalarFn(sql_set_numform_ea_arg));
        db.register_function("set_numform_ea_arg", 6, xsql::ScalarFn(sql_set_numform_ea_arg));
        db.register_function("set_numform_ea_expr", 4, xsql::ScalarFn(sql_set_numform_ea_expr));
        db.register_function("set_numform_ea_expr", 5, xsql::ScalarFn(sql_set_numform_ea_expr));
        db.register_function("set_numform_ea_expr", 6, xsql::ScalarFn(sql_set_numform_ea_expr));
        db.register_function("get_numform", 3, xsql::ScalarFn(sql_get_numform));
        db.register_function("get_numform_item", 3, xsql::ScalarFn(sql_get_numform_item));
        db.register_function("get_numform_ea_arg", 4, xsql::ScalarFn(sql_get_numform_ea_arg));
        db.register_function("get_numform_ea_arg", 5, xsql::ScalarFn(sql_get_numform_ea_arg));
        db.register_function("get_numform_ea_expr", 3, xsql::ScalarFn(sql_get_numform_ea_expr));
        db.register_function("get_numform_ea_expr", 4, xsql::ScalarFn(sql_get_numform_ea_expr));
        db.register_function("get_numform_ea_expr", 5, xsql::ScalarFn(sql_get_numform_ea_expr));
    }

    // Address utilities
    db.register_function("next_head", 1, xsql::ScalarFn(sql_next_head));
    db.register_function("prev_head", 1, xsql::ScalarFn(sql_prev_head));
    db.register_function("hex", 1, xsql::ScalarFn(sql_hex));

    // Item query functions
    db.register_function("item_type", 1, xsql::ScalarFn(sql_item_type));
    db.register_function("item_size", 1, xsql::ScalarFn(sql_item_size));
    db.register_function("is_code", 1, xsql::ScalarFn(sql_is_code));
    db.register_function("is_data", 1, xsql::ScalarFn(sql_is_data));
    db.register_function("mnemonic", 1, xsql::ScalarFn(sql_mnemonic));
    db.register_function("operand", 2, xsql::ScalarFn(sql_operand));
    db.register_function("flags_at", 1, xsql::ScalarFn(sql_flags_at));

    // Instruction decoding
    db.register_function("itype", 1, xsql::ScalarFn(sql_itype));
    db.register_function("decode_insn", 1, xsql::ScalarFn(sql_decode_insn));
    db.register_function("operand_type", 2, xsql::ScalarFn(sql_operand_type));
    db.register_function("operand_value", 2, xsql::ScalarFn(sql_operand_value));

    // File generation
    db.register_function("gen_asm_file", 3, xsql::ScalarFn(sql_gen_asm_file));
    db.register_function("gen_lst_file", 3, xsql::ScalarFn(sql_gen_lst_file));
    db.register_function("gen_map_file", 1, xsql::ScalarFn(sql_gen_map_file));
    db.register_function("gen_idc_file", 3, xsql::ScalarFn(sql_gen_idc_file));
    db.register_function("gen_html_file", 3, xsql::ScalarFn(sql_gen_html_file));

    // Graph generation
    db.register_function("gen_cfg_dot", 1, xsql::ScalarFn(sql_gen_cfg_dot));
    db.register_function("gen_cfg_dot_file", 2, xsql::ScalarFn(sql_gen_cfg_dot_file));
    db.register_function("gen_schema_dot", 0, xsql::ScalarFn(sql_gen_schema_dot));

    // Grep search
    db.register_function("grep", 1, xsql::ScalarFn(sql_grep));
    db.register_function("grep", 2, xsql::ScalarFn(sql_grep));
    db.register_function("grep", 3, xsql::ScalarFn(sql_grep));

    // String list functions
    db.register_function("rebuild_strings", 0, xsql::ScalarFn(sql_rebuild_strings));
    db.register_function("rebuild_strings", 1, xsql::ScalarFn(sql_rebuild_strings));
    db.register_function("rebuild_strings", 2, xsql::ScalarFn(sql_rebuild_strings));
    db.register_function("string_count", 0, xsql::ScalarFn(sql_string_count));

    // Database persistence
    db.register_function("save_database", 0, xsql::ScalarFn(sql_save_database));

    return true;
}

} // namespace functions
} // namespace idasql
