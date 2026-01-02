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
 * Introspection (standard SQLite):
 *   - SELECT * FROM sqlite_master WHERE type='table'
 *   - PRAGMA table_info(tablename)
 *   - PRAGMA table_xinfo(tablename)
 */

#pragma once

#include <sqlite3.h>
#include <xsql/database.hpp>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

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

// Hex-Rays decompiler (optional)
#ifdef HAS_HEXRAYS
#include <hexrays.hpp>
#endif

namespace idasql {
namespace functions {

// ============================================================================
// Disassembly Functions
// ============================================================================

// disasm(address) - Get single disassembly line
// disasm(address, count) - Get multiple lines
static void sql_disasm(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "disasm requires at least 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    int count = (argc >= 2) ? sqlite3_value_int(argv[1]) : 1;
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
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}

// ============================================================================
// Bytes Functions
// ============================================================================

// bytes(address, count) - Get bytes as hex string
static void sql_bytes_hex(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 2) {
        sqlite3_result_error(ctx, "bytes requires 2 arguments (address, count)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    size_t count = static_cast<size_t>(sqlite3_value_int(argv[1]));
    if (count > 4096) count = 4096;  // Safety limit

    std::ostringstream result;
    result << std::hex << std::setfill('0');
    for (size_t i = 0; i < count; i++) {
        if (i > 0) result << " ";
        uchar byte = get_byte(ea + i);
        result << std::setw(2) << static_cast<int>(byte);
    }

    std::string str = result.str();
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}

// bytes_raw(address, count) - Get bytes as blob
static void sql_bytes_raw(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 2) {
        sqlite3_result_error(ctx, "bytes_raw requires 2 arguments (address, count)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    size_t count = static_cast<size_t>(sqlite3_value_int(argv[1]));
    if (count > 4096) count = 4096;  // Safety limit

    std::vector<uchar> data(count);
    for (size_t i = 0; i < count; i++) {
        data[i] = get_byte(ea + i);
    }

    sqlite3_result_blob(ctx, data.data(), static_cast<int>(data.size()), SQLITE_TRANSIENT);
}

// ============================================================================
// Name Functions
// ============================================================================

// name_at(address) - Get name at address
static void sql_name_at(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "name_at requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    qstring name;
    if (get_name(&name, ea) > 0 && !name.empty()) {
        sqlite3_result_text(ctx, name.c_str(), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_result_null(ctx);
    }
}

// func_at(address) - Get function name containing address
static void sql_func_at(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "func_at requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    func_t* func = get_func(ea);
    if (func) {
        qstring name;
        if (get_func_name(&name, func->start_ea) > 0) {
            sqlite3_result_text(ctx, name.c_str(), -1, SQLITE_TRANSIENT);
            return;
        }
    }
    sqlite3_result_null(ctx);
}

// func_start(address) - Get start address of function containing address
static void sql_func_start(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "func_start requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    func_t* func = get_func(ea);
    if (func) {
        sqlite3_result_int64(ctx, func->start_ea);
    } else {
        sqlite3_result_null(ctx);
    }
}

// func_end(address) - Get end address of function containing address
static void sql_func_end(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "func_end requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    func_t* func = get_func(ea);
    if (func) {
        sqlite3_result_int64(ctx, func->end_ea);
    } else {
        sqlite3_result_null(ctx);
    }
}

// ============================================================================
// Function Index Functions (O(1) access)
// ============================================================================

// func_qty() - Get total function count
static void sql_func_qty(sqlite3_context* ctx, int, sqlite3_value**) {
    sqlite3_result_int64(ctx, get_func_qty());
}

// func_at_index(n) - Get function address at index n
static void sql_func_at_index(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "func_at_index requires 1 argument (index)", -1);
        return;
    }

    size_t idx = static_cast<size_t>(sqlite3_value_int64(argv[0]));
    size_t qty = get_func_qty();

    if (idx >= qty) {
        sqlite3_result_null(ctx);
        return;
    }

    func_t* f = getn_func(idx);
    if (f) {
        sqlite3_result_int64(ctx, f->start_ea);
    } else {
        sqlite3_result_null(ctx);
    }
}

// ============================================================================
// Name Modification Functions
// ============================================================================

// set_name(address, name) - Set name at address
static void sql_set_name(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 2) {
        sqlite3_result_error(ctx, "set_name requires 2 arguments (address, name)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    const char* name = (const char*)sqlite3_value_text(argv[1]);

    bool success = set_name(ea, name, SN_CHECK) != 0;
    sqlite3_result_int(ctx, success ? 1 : 0);
}

// ============================================================================
// Segment Functions
// ============================================================================

// segment_at(address) - Get segment name containing address
static void sql_segment_at(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "segment_at requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    segment_t* seg = getseg(ea);
    if (seg) {
        qstring name;
        if (get_segm_name(&name, seg) > 0) {
            sqlite3_result_text(ctx, name.c_str(), -1, SQLITE_TRANSIENT);
            return;
        }
    }
    sqlite3_result_null(ctx);
}

// ============================================================================
// Comment Functions
// ============================================================================

// comment_at(address) - Get comment at address
static void sql_comment_at(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "comment_at requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    qstring cmt;
    if (get_cmt(&cmt, ea, false) > 0) {
        sqlite3_result_text(ctx, cmt.c_str(), -1, SQLITE_TRANSIENT);
    } else if (get_cmt(&cmt, ea, true) > 0) {
        // Try repeatable comment
        sqlite3_result_text(ctx, cmt.c_str(), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_result_null(ctx);
    }
}

// set_comment(address, text) - Set comment at address
// set_comment(address, text, repeatable) - Set comment with type
static void sql_set_comment(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 2) {
        sqlite3_result_error(ctx, "set_comment requires 2-3 arguments (address, text, [repeatable])", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    const char* cmt = (const char*)sqlite3_value_text(argv[1]);
    bool repeatable = (argc >= 3) ? sqlite3_value_int(argv[2]) != 0 : false;

    bool success = set_cmt(ea, cmt ? cmt : "", repeatable);
    sqlite3_result_int(ctx, success ? 1 : 0);
}

// ============================================================================
// Cross-Reference Functions
// ============================================================================

// xrefs_to(address) - Get xrefs to address as JSON array
static void sql_xrefs_to(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "xrefs_to requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));

    std::ostringstream json;
    json << "[";
    bool first = true;

    xrefblk_t xb;
    for (bool ok = xb.first_to(ea, XREF_ALL); ok; ok = xb.next_to()) {
        if (!first) json << ",";
        first = false;
        json << "{\"from\":" << xb.from << ",\"type\":" << static_cast<int>(xb.type) << "}";
    }

    json << "]";
    std::string str = json.str();
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}

// xrefs_from(address) - Get xrefs from address as JSON array
static void sql_xrefs_from(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "xrefs_from requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));

    std::ostringstream json;
    json << "[";
    bool first = true;

    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
        if (!first) json << ",";
        first = false;
        json << "{\"to\":" << xb.to << ",\"type\":" << static_cast<int>(xb.type) << "}";
    }

    json << "]";
    std::string str = json.str();
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}

// ============================================================================
// Decompiler Functions (Optional - requires Hex-Rays)
// ============================================================================

#ifdef HAS_HEXRAYS
// decompile(address) - Get decompiled pseudocode
static void sql_decompile(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "decompile requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));

    func_t* func = get_func(ea);
    if (!func) {
        sqlite3_result_error(ctx, "No function at address", -1);
        return;
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf);
    if (!cfunc) {
        std::string err = "Decompilation failed: " + std::string(hf.desc().c_str());
        sqlite3_result_error(ctx, err.c_str(), -1);
        return;
    }

    const strvec_t& sv = cfunc->get_pseudocode();
    std::ostringstream result;
    for (size_t i = 0; i < sv.size(); i++) {
        qstring line = sv[i].line;
        tag_remove(&line);
        if (i > 0) result << "\n";
        result << line.c_str();
    }

    std::string str = result.str();
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}
#else
// Stub when Hex-Rays not available
static void sql_decompile(sqlite3_context* ctx, int, sqlite3_value**) {
    sqlite3_result_error(ctx, "Decompiler not available (requires Hex-Rays)", -1);
}
#endif

// ============================================================================
// Address Utility Functions
// ============================================================================

// next_head(address) - Get next defined head
static void sql_next_head(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "next_head requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    ea_t next = next_head(ea, BADADDR);
    if (next != BADADDR) {
        sqlite3_result_int64(ctx, next);
    } else {
        sqlite3_result_null(ctx);
    }
}

// prev_head(address) - Get previous defined head
static void sql_prev_head(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "prev_head requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    ea_t prev = prev_head(ea, 0);
    if (prev != BADADDR) {
        sqlite3_result_int64(ctx, prev);
    } else {
        sqlite3_result_null(ctx);
    }
}

// hex(value) - Format integer as hex string
static void sql_hex(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "hex requires 1 argument (value)", -1);
        return;
    }

    int64_t val = sqlite3_value_int64(argv[0]);
    std::ostringstream result;
    result << "0x" << std::hex << val;
    std::string str = result.str();
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}

// ============================================================================
// Item Query Functions
// ============================================================================

// item_type(address) - Get type of item at address
static void sql_item_type(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "item_type requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    flags64_t f = get_flags(ea);

    const char* type = "unknown";
    if (is_code(f)) type = "code";
    else if (is_strlit(f)) type = "string";
    else if (is_struct(f)) type = "struct";
    else if (is_align(f)) type = "align";
    else if (is_data(f)) type = "data";

    sqlite3_result_text(ctx, type, -1, SQLITE_STATIC);
}

// item_size(address) - Get size of item at address
static void sql_item_size(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "item_size requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    asize_t size = get_item_size(ea);
    sqlite3_result_int64(ctx, size);
}

// is_code(address) - Check if address is code
static void sql_is_code(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "is_code requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    sqlite3_result_int(ctx, is_code(get_flags(ea)) ? 1 : 0);
}

// is_data(address) - Check if address is data
static void sql_is_data(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "is_data requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    sqlite3_result_int(ctx, is_data(get_flags(ea)) ? 1 : 0);
}

// mnemonic(address) - Get instruction mnemonic
static void sql_mnemonic(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "mnemonic requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    if (!is_code(get_flags(ea))) {
        sqlite3_result_null(ctx);
        return;
    }

    qstring mnem;
    print_insn_mnem(&mnem, ea);
    sqlite3_result_text(ctx, mnem.c_str(), -1, SQLITE_TRANSIENT);
}

// operand(address, n) - Get operand text
static void sql_operand(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 2) {
        sqlite3_result_error(ctx, "operand requires 2 arguments (address, operand_num)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    int n = sqlite3_value_int(argv[1]);

    if (!is_code(get_flags(ea)) || n < 0 || n > 5) {
        sqlite3_result_null(ctx);
        return;
    }

    qstring op;
    print_operand(&op, ea, n);
    tag_remove(&op);
    if (op.empty()) {
        sqlite3_result_null(ctx);
    } else {
        sqlite3_result_text(ctx, op.c_str(), -1, SQLITE_TRANSIENT);
    }
}

// flags_at(address) - Get raw flags at address
static void sql_flags_at(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "flags_at requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    sqlite3_result_int64(ctx, get_flags(ea));
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
static void sql_itype(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "itype requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));

    if (!is_code(get_flags(ea))) {
        sqlite3_result_null(ctx);
        return;
    }

    insn_t insn;
    if (decode_insn(&insn, ea) > 0) {
        sqlite3_result_int(ctx, insn.itype);
    } else {
        sqlite3_result_null(ctx);
    }
}

// decode_insn(address) - Get full instruction info as JSON
static void sql_decode_insn(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "decode_insn requires 1 argument (address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));

    if (!is_code(get_flags(ea))) {
        sqlite3_result_null(ctx);
        return;
    }

    insn_t insn;
    int len = decode_insn(&insn, ea);
    if (len <= 0) {
        sqlite3_result_null(ctx);
        return;
    }

    // Get mnemonic
    qstring mnem;
    print_insn_mnem(&mnem, ea);

    // Build JSON
    std::ostringstream json;
    json << "{";
    json << "\"ea\":" << insn.ea << ",";
    json << "\"itype\":" << insn.itype << ",";
    json << "\"size\":" << insn.size << ",";
    json << "\"mnemonic\":\"" << mnem.c_str() << "\",";

    // Operands array
    json << "\"operands\":[";
    bool first_op = true;
    for (int i = 0; i < UA_MAXOP; i++) {
        const op_t& op = insn.ops[i];
        if (op.type == o_void) break;

        if (!first_op) json << ",";
        first_op = false;

        // Get operand text
        qstring op_text;
        print_operand(&op_text, ea, i);
        tag_remove(&op_text);

        json << "{";
        json << "\"n\":" << i << ",";
        json << "\"type\":" << static_cast<int>(op.type) << ",";
        json << "\"type_name\":\"" << get_optype_name(op.type) << "\",";
        json << "\"dtype\":" << static_cast<int>(op.dtype) << ",";
        json << "\"reg\":" << op.reg << ",";
        json << "\"addr\":" << op.addr << ",";
        json << "\"value\":" << op.value << ",";

        // Escape quotes in operand text
        std::string escaped;
        for (char c : std::string(op_text.c_str())) {
            if (c == '"') escaped += "\\\"";
            else if (c == '\\') escaped += "\\\\";
            else escaped += c;
        }
        json << "\"text\":\"" << escaped << "\"";
        json << "}";
    }
    json << "]";

    json << "}";

    std::string str = json.str();
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}

// operand_type(address, n) - Get operand type
static void sql_operand_type(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 2) {
        sqlite3_result_error(ctx, "operand_type requires 2 arguments (address, operand_num)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    int n = sqlite3_value_int(argv[1]);

    if (!is_code(get_flags(ea)) || n < 0 || n >= UA_MAXOP) {
        sqlite3_result_null(ctx);
        return;
    }

    insn_t insn;
    if (decode_insn(&insn, ea) <= 0) {
        sqlite3_result_null(ctx);
        return;
    }

    const op_t& op = insn.ops[n];
    if (op.type == o_void) {
        sqlite3_result_null(ctx);
    } else {
        sqlite3_result_text(ctx, get_optype_name(op.type), -1, SQLITE_STATIC);
    }
}

// operand_value(address, n) - Get operand value (immediate or address)
static void sql_operand_value(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 2) {
        sqlite3_result_error(ctx, "operand_value requires 2 arguments (address, operand_num)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    int n = sqlite3_value_int(argv[1]);

    if (!is_code(get_flags(ea)) || n < 0 || n >= UA_MAXOP) {
        sqlite3_result_null(ctx);
        return;
    }

    insn_t insn;
    if (decode_insn(&insn, ea) <= 0) {
        sqlite3_result_null(ctx);
        return;
    }

    const op_t& op = insn.ops[n];
    switch (op.type) {
        case o_void:
            sqlite3_result_null(ctx);
            break;
        case o_imm:
            sqlite3_result_int64(ctx, op.value);
            break;
        case o_mem:
        case o_near:
        case o_far:
        case o_displ:
            sqlite3_result_int64(ctx, op.addr);
            break;
        case o_reg:
            sqlite3_result_int(ctx, op.reg);
            break;
        default:
            sqlite3_result_int64(ctx, op.value);
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
static void sql_gen_asm_file(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 3) {
        sqlite3_result_error(ctx, "gen_asm_file requires 3 arguments (ea1, ea2, path)", -1);
        return;
    }

    ea_t ea1 = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    ea_t ea2 = static_cast<ea_t>(sqlite3_value_int64(argv[1]));
    const char* path = (const char*)sqlite3_value_text(argv[2]);
    if (!path) {
        sqlite3_result_error(ctx, "Invalid path", -1);
        return;
    }

    int result = gen_file_helper(OFILE_ASM, path, ea1, ea2, 0);
    sqlite3_result_int(ctx, result);
}

// gen_lst_file(ea1, ea2, path) - Generate listing file with addresses
static void sql_gen_lst_file(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 3) {
        sqlite3_result_error(ctx, "gen_lst_file requires 3 arguments (ea1, ea2, path)", -1);
        return;
    }

    ea_t ea1 = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    ea_t ea2 = static_cast<ea_t>(sqlite3_value_int64(argv[1]));
    const char* path = (const char*)sqlite3_value_text(argv[2]);
    if (!path) {
        sqlite3_result_error(ctx, "Invalid path", -1);
        return;
    }

    int result = gen_file_helper(OFILE_LST, path, ea1, ea2, 0);
    sqlite3_result_int(ctx, result);
}

// gen_map_file(path) - Generate MAP file
static void sql_gen_map_file(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "gen_map_file requires 1 argument (path)", -1);
        return;
    }

    const char* path = (const char*)sqlite3_value_text(argv[0]);
    if (!path) {
        sqlite3_result_error(ctx, "Invalid path", -1);
        return;
    }

    // MAP files ignore ea1/ea2, use GENFLG_MAPSEG | GENFLG_MAPNAME
    int flags = GENFLG_MAPSEG | GENFLG_MAPNAME | GENFLG_MAPDMNG;
    int result = gen_file_helper(OFILE_MAP, path, 0, BADADDR, flags);
    sqlite3_result_int(ctx, result);
}

// gen_idc_file(ea1, ea2, path) - Generate IDC script
static void sql_gen_idc_file(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 3) {
        sqlite3_result_error(ctx, "gen_idc_file requires 3 arguments (ea1, ea2, path)", -1);
        return;
    }

    ea_t ea1 = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    ea_t ea2 = static_cast<ea_t>(sqlite3_value_int64(argv[1]));
    const char* path = (const char*)sqlite3_value_text(argv[2]);
    if (!path) {
        sqlite3_result_error(ctx, "Invalid path", -1);
        return;
    }

    int result = gen_file_helper(OFILE_IDC, path, ea1, ea2, 0);
    sqlite3_result_int(ctx, result);
}

// gen_html_file(ea1, ea2, path) - Generate HTML listing
static void sql_gen_html_file(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 3) {
        sqlite3_result_error(ctx, "gen_html_file requires 3 arguments (ea1, ea2, path)", -1);
        return;
    }

    ea_t ea1 = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    ea_t ea2 = static_cast<ea_t>(sqlite3_value_int64(argv[1]));
    const char* path = (const char*)sqlite3_value_text(argv[2]);
    if (!path) {
        sqlite3_result_error(ctx, "Invalid path", -1);
        return;
    }

    int result = gen_file_helper(OFILE_LST, path, ea1, ea2, GENFLG_GENHTML);
    sqlite3_result_int(ctx, result);
}

// gen_cfg_dot(address) - Generate CFG as DOT string
static void sql_gen_cfg_dot(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "gen_cfg_dot requires 1 argument (func_address)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    func_t* func = get_func(ea);
    if (!func) {
        sqlite3_result_error(ctx, "No function at address", -1);
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
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}

// gen_cfg_dot_file(address, path) - Generate CFG DOT to file
static void sql_gen_cfg_dot_file(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 2) {
        sqlite3_result_error(ctx, "gen_cfg_dot_file requires 2 arguments (func_address, path)", -1);
        return;
    }

    ea_t ea = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    const char* path = (const char*)sqlite3_value_text(argv[1]);
    if (!path) {
        sqlite3_result_error(ctx, "Invalid path", -1);
        return;
    }

    func_t* func = get_func(ea);
    if (!func) {
        sqlite3_result_error(ctx, "No function at address", -1);
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
        sqlite3_result_error(ctx, "Failed to open file", -1);
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

    sqlite3_result_int(ctx, 1);  // Success
}

// gen_schema_dot(db) - Generate DOT diagram of all tables
// This uses SQLite introspection to build the schema
static void sql_gen_schema_dot(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    sqlite3* db = sqlite3_context_db_handle(ctx);

    std::ostringstream dot;
    dot << "digraph IDASQL_Schema {\n";
    dot << "  rankdir=TB;\n";
    dot << "  node [shape=record, fontname=\"Helvetica\", fontsize=10];\n";
    dot << "  edge [fontname=\"Helvetica\", fontsize=8];\n\n";

    // Query all tables from sqlite_master
    sqlite3_stmt* stmt;
    const char* sql = "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY name";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_result_error(ctx, "Failed to query schema", -1);
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
    sqlite3_result_text(ctx, str.c_str(), -1, SQLITE_TRANSIENT);
}

// ============================================================================
// Decompiler Lvar Functions (requires Hex-Rays)
// ============================================================================

#ifdef HAS_HEXRAYS
// rename_lvar(func_addr, lvar_idx, new_name) - Rename a local variable
// Returns JSON with result details for debugging the API
static void sql_rename_lvar(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 3) {
        sqlite3_result_error(ctx, "rename_lvar requires 3 arguments (func_addr, lvar_idx, new_name)", -1);
        return;
    }

    ea_t func_addr = static_cast<ea_t>(sqlite3_value_int64(argv[0]));
    int lvar_idx = sqlite3_value_int(argv[1]);
    const char* new_name = (const char*)sqlite3_value_text(argv[2]);

    if (!new_name) {
        sqlite3_result_error(ctx, "Invalid name", -1);
        return;
    }

    std::ostringstream result;
    result << "{\"func_addr\":" << func_addr << ",\"lvar_idx\":" << lvar_idx;
    result << ",\"new_name\":\"" << new_name << "\"";

    // Initialize Hex-Rays
    if (!init_hexrays_plugin()) {
        result << ",\"error\":\"Hex-Rays not available\"}";
        sqlite3_result_text(ctx, result.str().c_str(), -1, SQLITE_TRANSIENT);
        return;
    }

    // Get function
    func_t* f = get_func(func_addr);
    if (!f) {
        result << ",\"error\":\"Function not found\"}";
        sqlite3_result_text(ctx, result.str().c_str(), -1, SQLITE_TRANSIENT);
        return;
    }

    // Decompile
    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc) {
        result << ",\"error\":\"Decompilation failed: " << hf.str.c_str() << "\"}";
        sqlite3_result_text(ctx, result.str().c_str(), -1, SQLITE_TRANSIENT);
        return;
    }

    // Get lvars
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || lvar_idx < 0 || static_cast<size_t>(lvar_idx) >= lvars->size()) {
        result << ",\"error\":\"Invalid lvar index (count=" << (lvars ? lvars->size() : 0) << ")\"}";
        sqlite3_result_text(ctx, result.str().c_str(), -1, SQLITE_TRANSIENT);
        return;
    }

    lvar_t& lv = (*lvars)[lvar_idx];
    std::string old_name = lv.name.c_str();
    result << ",\"old_name\":\"" << old_name << "\"";

    // Try approach 1: rename_lvar (cfunc, lvar, name)
    bool success1 = rename_lvar(cfunc.get(), &lv, new_name);
    result << ",\"rename_lvar_result\":" << (success1 ? "true" : "false");

    // Try approach 2: modify_user_lvar_info
    lvar_saved_info_t lsi;
    lsi.ll = lv;  // Copy lvar_locator_t
    lsi.name = new_name;
    lsi.flags = LVINF_NAME;

    bool success2 = modify_user_lvar_info(func_addr, MLI_NAME, lsi);
    result << ",\"modify_user_lvar_info_result\":" << (success2 ? "true" : "false");

    // Verify by re-decompiling
    cfuncptr_t cfunc2 = decompile(f, &hf);
    if (cfunc2) {
        lvars_t* lvars2 = cfunc2->get_lvars();
        if (lvars2 && static_cast<size_t>(lvar_idx) < lvars2->size()) {
            result << ",\"verified_name\":\"" << (*lvars2)[lvar_idx].name.c_str() << "\"";
        }
    }

    result << ",\"success\":" << ((success1 || success2) ? "true" : "false") << "}";
    sqlite3_result_text(ctx, result.str().c_str(), -1, SQLITE_TRANSIENT);
}

// list_lvars(func_addr) - List local variables for a function as JSON
static void sql_list_lvars(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 1) {
        sqlite3_result_error(ctx, "list_lvars requires 1 argument (func_addr)", -1);
        return;
    }

    ea_t func_addr = static_cast<ea_t>(sqlite3_value_int64(argv[0]));

    // Initialize Hex-Rays
    if (!init_hexrays_plugin()) {
        sqlite3_result_error(ctx, "Hex-Rays not available", -1);
        return;
    }

    func_t* f = get_func(func_addr);
    if (!f) {
        sqlite3_result_error(ctx, "Function not found", -1);
        return;
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(f, &hf);
    if (!cfunc) {
        std::string err = "Decompilation failed: " + std::string(hf.str.c_str());
        sqlite3_result_error(ctx, err.c_str(), -1);
        return;
    }

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) {
        sqlite3_result_text(ctx, "[]", -1, SQLITE_STATIC);
        return;
    }

    std::ostringstream json;
    json << "[";
    for (size_t i = 0; i < lvars->size(); i++) {
        const lvar_t& lv = (*lvars)[i];
        if (i > 0) json << ",";

        qstring type_str;
        lv.type().print(&type_str);

        json << "{\"idx\":" << i;
        json << ",\"name\":\"" << lv.name.c_str() << "\"";
        json << ",\"type\":\"" << type_str.c_str() << "\"";
        json << ",\"size\":" << lv.width;
        json << ",\"is_arg\":" << (lv.is_arg_var() ? "true" : "false");
        json << ",\"is_result\":" << (lv.is_result_var() ? "true" : "false");
        json << "}";
    }
    json << "]";

    sqlite3_result_text(ctx, json.str().c_str(), -1, SQLITE_TRANSIENT);
}
#else
static void sql_rename_lvar(sqlite3_context* ctx, int, sqlite3_value**) {
    sqlite3_result_error(ctx, "rename_lvar requires Hex-Rays decompiler", -1);
}
static void sql_list_lvars(sqlite3_context* ctx, int, sqlite3_value**) {
    sqlite3_result_error(ctx, "list_lvars requires Hex-Rays decompiler", -1);
}
#endif

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
static void sql_jump_search(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 4) {
        sqlite3_result_error(ctx, "jump_search requires 4 arguments (prefix, mode, limit, offset)", -1);
        return;
    }

    const char* prefix = (const char*)sqlite3_value_text(argv[0]);
    const char* mode = (const char*)sqlite3_value_text(argv[1]);
    int limit = sqlite3_value_int(argv[2]);
    int offset = sqlite3_value_int(argv[3]);

    if (!prefix || !mode) {
        sqlite3_result_error(ctx, "Invalid arguments", -1);
        return;
    }

    bool contains = (strcmp(mode, "contains") == 0);
    std::string query = build_jump_query(prefix, contains, limit, offset);

    if (query.empty()) {
        sqlite3_result_text(ctx, "[]", -1, SQLITE_STATIC);
        return;
    }

    // Execute query and build JSON result
    sqlite3* db = sqlite3_context_db_handle(ctx);
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::string err = "Query error: " + std::string(sqlite3_errmsg(db));
        sqlite3_result_error(ctx, err.c_str(), -1);
        return;
    }

    std::ostringstream json;
    json << "[";
    bool first = true;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (!first) json << ",";
        first = false;

        const char* name = (const char*)sqlite3_column_text(stmt, 0);
        const char* kind = (const char*)sqlite3_column_text(stmt, 1);
        int64_t address = sqlite3_column_int64(stmt, 2);
        int ordinal = sqlite3_column_int(stmt, 3);
        const char* parent = (const char*)sqlite3_column_text(stmt, 4);
        const char* full_name = (const char*)sqlite3_column_text(stmt, 5);

        json << "{";
        json << "\"name\":\"" << (name ? name : "") << "\",";
        json << "\"kind\":\"" << (kind ? kind : "") << "\",";

        if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
            json << "\"address\":" << address << ",";
        } else {
            json << "\"address\":null,";
        }

        if (sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
            json << "\"ordinal\":" << ordinal << ",";
        } else {
            json << "\"ordinal\":null,";
        }

        json << "\"parent_name\":" << (parent ? ("\"" + std::string(parent) + "\"") : "null") << ",";
        json << "\"full_name\":\"" << (full_name ? full_name : "") << "\"";
        json << "}";
    }

    json << "]";
    sqlite3_finalize(stmt);

    std::string result = json.str();
    sqlite3_result_text(ctx, result.c_str(), -1, SQLITE_TRANSIENT);
}

// jump_query(prefix, mode, limit, offset) - Return the SQL query string
static void sql_jump_query(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc < 4) {
        sqlite3_result_error(ctx, "jump_query requires 4 arguments (prefix, mode, limit, offset)", -1);
        return;
    }

    const char* prefix = (const char*)sqlite3_value_text(argv[0]);
    const char* mode = (const char*)sqlite3_value_text(argv[1]);
    int limit = sqlite3_value_int(argv[2]);
    int offset = sqlite3_value_int(argv[3]);

    if (!prefix || !mode) {
        sqlite3_result_error(ctx, "Invalid arguments", -1);
        return;
    }

    bool contains = (strcmp(mode, "contains") == 0);
    std::string query = build_jump_query(prefix, contains, limit, offset);

    sqlite3_result_text(ctx, query.c_str(), -1, SQLITE_TRANSIENT);
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
static void sql_rebuild_strings(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    int min_len = 5;
    int types_mask = 3;  // Default: ASCII + UTF-16

    if (argc >= 1 && sqlite3_value_type(argv[0]) == SQLITE_INTEGER) {
        min_len = sqlite3_value_int(argv[0]);
        if (min_len < 1) min_len = 1;
        if (min_len > 1000) min_len = 1000;
    }
    if (argc >= 2 && sqlite3_value_type(argv[1]) == SQLITE_INTEGER) {
        types_mask = sqlite3_value_int(argv[1]);
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

    // Return the count
    size_t count = get_strlist_qty();
    sqlite3_result_int64(ctx, static_cast<int64_t>(count));
}

// string_count() - Get current count of strings in IDA's cached list (no rebuild)
static void sql_string_count(sqlite3_context* ctx, int /*argc*/, sqlite3_value** /*argv*/) {
    sqlite3_result_int64(ctx, static_cast<int64_t>(get_strlist_qty()));
}

// ============================================================================
// Registration
// ============================================================================

inline bool register_sql_functions(xsql::Database& db) {
    // Disassembly
    sqlite3_create_function(db.handle(), "disasm", 1, SQLITE_UTF8, nullptr, sql_disasm, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "disasm", 2, SQLITE_UTF8, nullptr, sql_disasm, nullptr, nullptr);

    // Bytes
    sqlite3_create_function(db.handle(), "bytes", 2, SQLITE_UTF8, nullptr, sql_bytes_hex, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "bytes_raw", 2, SQLITE_UTF8, nullptr, sql_bytes_raw, nullptr, nullptr);

    // Names
    sqlite3_create_function(db.handle(), "name_at", 1, SQLITE_UTF8, nullptr, sql_name_at, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "func_at", 1, SQLITE_UTF8, nullptr, sql_func_at, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "func_start", 1, SQLITE_UTF8, nullptr, sql_func_start, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "func_end", 1, SQLITE_UTF8, nullptr, sql_func_end, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "set_name", 2, SQLITE_UTF8, nullptr, sql_set_name, nullptr, nullptr);

    // Function index (O(1) access)
    sqlite3_create_function(db.handle(), "func_qty", 0, SQLITE_UTF8, nullptr, sql_func_qty, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "func_at_index", 1, SQLITE_UTF8, nullptr, sql_func_at_index, nullptr, nullptr);

    // Segments
    sqlite3_create_function(db.handle(), "segment_at", 1, SQLITE_UTF8, nullptr, sql_segment_at, nullptr, nullptr);

    // Comments
    sqlite3_create_function(db.handle(), "comment_at", 1, SQLITE_UTF8, nullptr, sql_comment_at, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "set_comment", 2, SQLITE_UTF8, nullptr, sql_set_comment, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "set_comment", 3, SQLITE_UTF8, nullptr, sql_set_comment, nullptr, nullptr);

    // Cross-references
    sqlite3_create_function(db.handle(), "xrefs_to", 1, SQLITE_UTF8, nullptr, sql_xrefs_to, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "xrefs_from", 1, SQLITE_UTF8, nullptr, sql_xrefs_from, nullptr, nullptr);

    // Decompiler
    sqlite3_create_function(db.handle(), "decompile", 1, SQLITE_UTF8, nullptr, sql_decompile, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "list_lvars", 1, SQLITE_UTF8, nullptr, sql_list_lvars, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "rename_lvar", 3, SQLITE_UTF8, nullptr, sql_rename_lvar, nullptr, nullptr);

    // Address utilities
    sqlite3_create_function(db.handle(), "next_head", 1, SQLITE_UTF8, nullptr, sql_next_head, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "prev_head", 1, SQLITE_UTF8, nullptr, sql_prev_head, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "hex", 1, SQLITE_UTF8, nullptr, sql_hex, nullptr, nullptr);

    // Item query functions
    sqlite3_create_function(db.handle(), "item_type", 1, SQLITE_UTF8, nullptr, sql_item_type, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "item_size", 1, SQLITE_UTF8, nullptr, sql_item_size, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "is_code", 1, SQLITE_UTF8, nullptr, sql_is_code, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "is_data", 1, SQLITE_UTF8, nullptr, sql_is_data, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "mnemonic", 1, SQLITE_UTF8, nullptr, sql_mnemonic, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "operand", 2, SQLITE_UTF8, nullptr, sql_operand, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "flags_at", 1, SQLITE_UTF8, nullptr, sql_flags_at, nullptr, nullptr);

    // Instruction decoding
    sqlite3_create_function(db.handle(), "itype", 1, SQLITE_UTF8, nullptr, sql_itype, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "decode_insn", 1, SQLITE_UTF8, nullptr, sql_decode_insn, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "operand_type", 2, SQLITE_UTF8, nullptr, sql_operand_type, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "operand_value", 2, SQLITE_UTF8, nullptr, sql_operand_value, nullptr, nullptr);

    // File generation
    sqlite3_create_function(db.handle(), "gen_asm_file", 3, SQLITE_UTF8, nullptr, sql_gen_asm_file, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "gen_lst_file", 3, SQLITE_UTF8, nullptr, sql_gen_lst_file, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "gen_map_file", 1, SQLITE_UTF8, nullptr, sql_gen_map_file, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "gen_idc_file", 3, SQLITE_UTF8, nullptr, sql_gen_idc_file, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "gen_html_file", 3, SQLITE_UTF8, nullptr, sql_gen_html_file, nullptr, nullptr);

    // Graph generation
    sqlite3_create_function(db.handle(), "gen_cfg_dot", 1, SQLITE_UTF8, nullptr, sql_gen_cfg_dot, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "gen_cfg_dot_file", 2, SQLITE_UTF8, nullptr, sql_gen_cfg_dot_file, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "gen_schema_dot", 0, SQLITE_UTF8, nullptr, sql_gen_schema_dot, nullptr, nullptr);

    // Jump search
    sqlite3_create_function(db.handle(), "jump_search", 4, SQLITE_UTF8, nullptr, sql_jump_search, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "jump_query", 4, SQLITE_UTF8, nullptr, sql_jump_query, nullptr, nullptr);

    // String list functions
    sqlite3_create_function(db.handle(), "rebuild_strings", 0, SQLITE_UTF8, nullptr, sql_rebuild_strings, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "rebuild_strings", 1, SQLITE_UTF8, nullptr, sql_rebuild_strings, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "rebuild_strings", 2, SQLITE_UTF8, nullptr, sql_rebuild_strings, nullptr, nullptr);
    sqlite3_create_function(db.handle(), "string_count", 0, SQLITE_UTF8, nullptr, sql_string_count, nullptr, nullptr);

    return true;
}

} // namespace functions
} // namespace idasql
