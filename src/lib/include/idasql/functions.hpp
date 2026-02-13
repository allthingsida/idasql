/**
 * ida_sql_functions.hpp - Custom SQL functions for IDA operations
 *
 * Query Functions:
 *   - disasm(address)           - Get disassembly line at address
 *   - disasm(address, count)    - Get multiple disassembly lines
 *   - decompile(address)        - Get decompiled pseudocode for function
 *   - bytes(address, count)     - Get bytes as hex string
 *   - bytes_raw(address, count) - Get bytes as blob
 *   - name_at(address)          - Get name at address
 *   - func_at(address)          - Get function name containing address
 *   - func_start(address)       - Get start address of function containing address
 *   - func_end(address)         - Get end address of function containing address
 *   - xrefs_to(address)         - Get xrefs to address (JSON array)
 *   - xrefs_from(address)       - Get xrefs from address (JSON array)
 *   - segment_at(address)       - Get segment name containing address
 *   - comment_at(address)       - Get comment at address
 *   - set_comment(address, text) - Set comment at address
 *   - set_name(address, name)   - Set name at address
 *
 * Function Index Functions (O(1) access):
 *   - func_qty()                - Get total function count
 *   - func_at_index(n)          - Get function address at index n
 *
 * Instruction Decoding Functions:
 *   - itype(address)            - Get instruction type code at address
 *   - decode_insn(address)      - Get full instruction info as JSON
 *   - operand_type(address, n)  - Get operand type (0-5)
 *   - operand_value(address, n) - Get operand value/address
 *
 * File Generation Functions:
 *   - gen_asm_file(ea1, ea2, path)  - Generate assembly file
 *   - gen_lst_file(ea1, ea2, path)  - Generate listing file (with addresses)
 *   - gen_map_file(path)            - Generate MAP file
 *   - gen_idc_file(ea1, ea2, path)  - Generate IDC script
 *   - gen_html_file(ea1, ea2, path) - Generate HTML listing
 *   - gen_cfg_dot(address)          - Generate CFG as DOT (returns string)
 *   - gen_cfg_dot_file(address, path) - Generate CFG DOT to file
 *   - gen_schema_dot()              - Generate schema diagram as DOT
 *
 * Database Persistence:
 *   - save_database()               - Persist changes to .i64 file (returns 1/0)
 *
 * Introspection (standard SQLite):
 *   - SELECT * FROM sqlite_master WHERE type='table'
 *   - PRAGMA table_info(tablename)
 *   - PRAGMA table_xinfo(tablename)
 */

#pragma once

#include <idasql/platform.hpp>

#include <xsql/database.hpp>
#include <xsql/json.hpp>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

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

// Hex-Rays decompiler - always included, runtime detection
#include <hexrays.hpp>
#include <idasql/decompiler.hpp>  // For hexrays_available()

namespace idasql {
namespace functions {

// ============================================================================
// Disassembly Functions
// ============================================================================

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
        qstring line;
        if (generate_disasm_line(&line, ea, GENDSM_FORCE_CODE)) {
            // Strip color codes
            tag_remove(&line);
            if (i > 0) result << "\n";
            result << std::hex << ea << ": " << line.c_str();
        }
        ea = next_head(ea, BADADDR);
    }

    std::string str = result.str();
    ctx.result_text(str);
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

// Render pseudocode lines with ea prefixes
static std::string render_pseudocode(cfuncptr_t& cfunc) {
    const strvec_t& sv = cfunc->get_pseudocode();
    std::ostringstream result;
    for (size_t i = 0; i < sv.size(); i++) {
        ea_t line_ea = decompiler::extract_line_ea(&*cfunc, sv[i].line);
        qstring line = sv[i].line;
        tag_remove(&line);
        if (i > 0) result << "\n";
        char prefix[48];
        if (line_ea != 0 && line_ea != BADADDR)
            qsnprintf(prefix, sizeof(prefix), "/* %a */ ", line_ea);
        else
            qsnprintf(prefix, sizeof(prefix), "/*          */ ");
        result << prefix << line.c_str();
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

// gen_schema_dot(db) - Generate DOT diagram of all tables
// This uses SQLite introspection to build the schema
static void sql_gen_schema_dot(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    sqlite3* db = ctx.db_handle();

    std::ostringstream dot;
    dot << "digraph IDASQL_Schema {\n";
    dot << "  rankdir=TB;\n";
    dot << "  node [shape=record, fontname=\"Helvetica\", fontsize=10];\n";
    dot << "  edge [fontname=\"Helvetica\", fontsize=8];\n\n";

    // Query all tables from sqlite_master
    sqlite3_stmt* stmt;
    const char* sql = "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY name";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        ctx.result_error("Failed to query schema");
        return;
    }

    std::vector<std::string> tables;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* name = (const char*)sqlite3_column_text(stmt, 0);
        const char* type = (const char*)sqlite3_column_text(stmt, 1);
        if (name) {
            tables.push_back(name);

            // Get column info for this table
            std::string pragma = "PRAGMA table_info(" + std::string(name) + ")";
            sqlite3_stmt* col_stmt;
            if (sqlite3_prepare_v2(db, pragma.c_str(), -1, &col_stmt, nullptr) == SQLITE_OK) {
                dot << "  " << name << " [label=\"{" << name;
                if (type && strcmp(type, "view") == 0) dot << " (view)";
                dot << "|";

                bool first = true;
                while (sqlite3_step(col_stmt) == SQLITE_ROW) {
                    const char* col_name = (const char*)sqlite3_column_text(col_stmt, 1);
                    const char* col_type = (const char*)sqlite3_column_text(col_stmt, 2);
                    if (!first) dot << "\\l";
                    first = false;
                    dot << (col_name ? col_name : "?");
                    if (col_type && strlen(col_type) > 0) {
                        dot << " : " << col_type;
                    }
                }
                dot << "\\l}\"];\n";
                sqlite3_finalize(col_stmt);
            }
        }
    }
    sqlite3_finalize(stmt);

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

    bool success = decompiler::rename_lvar_at(func_addr, lvar_idx, new_name);

    xsql::json result = {
        {"func_addr", func_addr},
        {"lvar_idx", lvar_idx},
        {"new_name", new_name},
        {"success", success}
    };
    if (!success) {
        result["error"] = "rename failed";
    }
    std::string str = result.dump();
    ctx.result_text(str);
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

        qstring type_str;
        lv.type().print(&type_str);

        arr.push_back({
            {"idx", i},
            {"name", lv.name.c_str()},
            {"type", type_str.c_str()},
            {"size", lv.width},
            {"is_arg", lv.is_arg_var()},
            {"is_result", lv.is_result_var()}
        });
    }

    std::string str = arr.dump();
    ctx.result_text(str);
}

// ============================================================================
// Jump Search Functions (unified entity search)
// ============================================================================

// Build dynamic SQL query for entity search
// prefix: search pattern
// contains: if true, use '%prefix%', otherwise 'prefix%'
// limit: max results
// offset: pagination offset
inline std::string build_jump_query(const std::string& prefix, bool contains, int limit, int offset) {
    if (prefix.empty()) return "";

    // Escape single quotes in prefix
    std::string escaped;
    for (char c : prefix) {
        if (c == '\'') escaped += "''";
        else escaped += std::tolower(c);
    }

    std::string pattern = contains
        ? ("'%" + escaped + "%'")
        : ("'" + escaped + "%'");

    std::ostringstream sql;
    sql << "SELECT name, kind, address, ordinal, parent_name, full_name FROM (\n";

    // Functions
    sql << "    SELECT name, 'function' as kind, address, NULL as ordinal,\n";
    sql << "           NULL as parent_name, name as full_name\n";
    sql << "    FROM funcs WHERE LOWER(name) LIKE " << pattern << "\n";
    sql << "    UNION ALL\n";

    // Labels (exclude function starts)
    sql << "    SELECT name, 'label', address, NULL, NULL, name\n";
    sql << "    FROM names n WHERE LOWER(name) LIKE " << pattern << "\n";
    sql << "      AND NOT EXISTS (SELECT 1 FROM funcs f WHERE f.address = n.address)\n";
    sql << "    UNION ALL\n";

    // Segments
    sql << "    SELECT name, 'segment', start_ea, NULL, NULL, name\n";
    sql << "    FROM segments WHERE LOWER(name) LIKE " << pattern << "\n";
    sql << "    UNION ALL\n";

    // Structs
    sql << "    SELECT name, 'struct', NULL, ordinal, NULL, name\n";
    sql << "    FROM types WHERE is_struct = 1 AND LOWER(name) LIKE " << pattern << "\n";
    sql << "    UNION ALL\n";

    // Unions
    sql << "    SELECT name, 'union', NULL, ordinal, NULL, name\n";
    sql << "    FROM types WHERE is_union = 1 AND LOWER(name) LIKE " << pattern << "\n";
    sql << "    UNION ALL\n";

    // Enums
    sql << "    SELECT name, 'enum', NULL, ordinal, NULL, name\n";
    sql << "    FROM types WHERE is_enum = 1 AND LOWER(name) LIKE " << pattern << "\n";
    sql << "    UNION ALL\n";

    // Struct/union members
    sql << "    SELECT member_name, 'member', NULL, type_ordinal,\n";
    sql << "           type_name, type_name || '.' || member_name\n";
    sql << "    FROM types_members WHERE LOWER(member_name) LIKE " << pattern << "\n";
    sql << "    UNION ALL\n";

    // Enum members
    sql << "    SELECT value_name, 'enum_member', NULL, type_ordinal,\n";
    sql << "           type_name, type_name || '.' || value_name\n";
    sql << "    FROM types_enum_values WHERE LOWER(value_name) LIKE " << pattern << "\n";

    sql << ")\n";
    sql << "ORDER BY kind, name\n";
    sql << "LIMIT " << limit << " OFFSET " << offset;

    return sql.str();
}

// jump_search(prefix, mode, limit, offset) - Search entities, return JSON array
// mode: 'prefix' or 'contains'
static void sql_jump_search(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 4) {
        ctx.result_error("jump_search requires 4 arguments (prefix, mode, limit, offset)");
        return;
    }

    const char* prefix = argv[0].as_c_str();
    const char* mode = argv[1].as_c_str();
    int limit = argv[2].as_int();
    int offset = argv[3].as_int();

    if (!prefix || !mode) {
        ctx.result_error("Invalid arguments");
        return;
    }

    bool contains = (strcmp(mode, "contains") == 0);
    std::string query = build_jump_query(prefix, contains, limit, offset);

    if (query.empty()) {
        ctx.result_text_static("[]");
        return;
    }

    // Execute query and build JSON result
    sqlite3* db = ctx.db_handle();
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::string err = "Query error: " + std::string(sqlite3_errmsg(db));
        ctx.result_error(err);
        return;
    }

    xsql::json arr = xsql::json::array();

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* name = (const char*)sqlite3_column_text(stmt, 0);
        const char* kind = (const char*)sqlite3_column_text(stmt, 1);
        int64_t address = sqlite3_column_int64(stmt, 2);
        int ordinal = sqlite3_column_int(stmt, 3);
        const char* parent = (const char*)sqlite3_column_text(stmt, 4);
        const char* full_name = (const char*)sqlite3_column_text(stmt, 5);

        xsql::json obj = {
            {"name", name ? name : ""},
            {"kind", kind ? kind : ""},
            {"full_name", full_name ? full_name : ""}
        };

        // Handle nullable fields
        if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
            obj["address"] = address;
        } else {
            obj["address"] = nullptr;
        }

        if (sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
            obj["ordinal"] = ordinal;
        } else {
            obj["ordinal"] = nullptr;
        }

        obj["parent_name"] = parent ? xsql::json(parent) : xsql::json(nullptr);

        arr.push_back(obj);
    }

    sqlite3_finalize(stmt);

    std::string result = arr.dump();
    ctx.result_text(result);
}

// jump_query(prefix, mode, limit, offset) - Return the SQL query string
static void sql_jump_query(xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
    if (argc < 4) {
        ctx.result_error("jump_query requires 4 arguments (prefix, mode, limit, offset)");
        return;
    }

    const char* prefix = argv[0].as_c_str();
    const char* mode = argv[1].as_c_str();
    int limit = argv[2].as_int();
    int offset = argv[3].as_int();

    if (!prefix || !mode) {
        ctx.result_error("Invalid arguments");
        return;
    }

    bool contains = (strcmp(mode, "contains") == 0);
    std::string query = build_jump_query(prefix, contains, limit, offset);

    ctx.result_text(query);
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
    db.register_function("disasm", 1, xsql::ScalarFn(sql_disasm));
    db.register_function("disasm", 2, xsql::ScalarFn(sql_disasm));

    // Bytes
    db.register_function("bytes", 2, xsql::ScalarFn(sql_bytes_hex));
    db.register_function("bytes_raw", 2, xsql::ScalarFn(sql_bytes_raw));

    // Names
    db.register_function("name_at", 1, xsql::ScalarFn(sql_name_at));
    db.register_function("func_at", 1, xsql::ScalarFn(sql_func_at));
    db.register_function("func_start", 1, xsql::ScalarFn(sql_func_start));
    db.register_function("func_end", 1, xsql::ScalarFn(sql_func_end));
    db.register_function("set_name", 2, xsql::ScalarFn(sql_set_name));

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

    // Jump search
    db.register_function("jump_search", 4, xsql::ScalarFn(sql_jump_search));
    db.register_function("jump_query", 4, xsql::ScalarFn(sql_jump_query));

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
