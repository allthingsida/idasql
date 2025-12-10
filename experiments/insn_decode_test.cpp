/**
 * insn_decode_test.cpp - Standalone instruction decoding experiment
 *
 * Tests IDA SDK instruction decoding APIs:
 * - decode_insn() for decoding instructions
 * - insn_t structure fields (itype, ea, size, ops)
 * - op_t operand structure
 * - Mnemonic retrieval via print_insn_mnem()
 *
 * Build: Use idalib (headless IDA)
 */

#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>

#include <cstdio>
#include <string>
#include <vector>
#include <map>

// Operand type names for display
static const char* operand_type_names[] = {
    "o_void",     // 0 - No operand
    "o_reg",      // 1 - General Register
    "o_mem",      // 2 - Direct memory reference
    "o_phrase",   // 3 - Indirect [reg]
    "o_displ",    // 4 - Indirect [reg+disp]
    "o_imm",      // 5 - Immediate value
    "o_far",      // 6 - Far code reference
    "o_near",     // 7 - Near code reference
    "o_idpspec0", // 8 - Processor specific
    "o_idpspec1", // 9
    "o_idpspec2", // 10
    "o_idpspec3", // 11
    "o_idpspec4", // 12
    "o_idpspec5", // 13
};

// Get operand type name
const char* get_optype_name(optype_t type) {
    if (type < sizeof(operand_type_names)/sizeof(operand_type_names[0])) {
        return operand_type_names[type];
    }
    return "unknown";
}

// Data type (dtype) names
static const char* dtype_names[] = {
    "dt_byte",    // 0 - 8 bit
    "dt_word",    // 1 - 16 bit
    "dt_dword",   // 2 - 32 bit
    "dt_float",   // 3 - 4 byte float
    "dt_double",  // 4 - 8 byte float
    "dt_tbyte",   // 5 - 10 byte float
    "dt_packreal",// 6 - packed real
    "dt_qword",   // 7 - 64 bit
    "dt_byte16",  // 8 - 128 bit
    "dt_code",    // 9 - code pointer
    "dt_void",    // 10 - void
    "dt_fword",   // 11 - 48 bit
    "dt_bitfield",// 12 - bit field
    "dt_string",  // 13 - string
    "dt_unicode", // 14 - unicode string
    "dt_ldbl",    // 15 - long double
    "dt_byte32",  // 16 - 256 bit
    "dt_byte64",  // 17 - 512 bit
};

const char* get_dtype_name(char dtype) {
    unsigned char dt = (unsigned char)dtype;
    if (dt < sizeof(dtype_names)/sizeof(dtype_names[0])) {
        return dtype_names[dt];
    }
    return "unknown";
}

// Structure to hold decoded instruction info
struct DecodedInstruction {
    ea_t ea;                      // Linear address
    uint16 itype;                 // Instruction type code
    uint16 size;                  // Instruction size in bytes
    std::string mnemonic;         // Mnemonic string
    std::string disasm;           // Full disassembly line

    // Operand info
    struct Operand {
        optype_t type;            // Operand type (o_reg, o_mem, etc.)
        char dtype;               // Data type (dt_byte, dt_dword, etc.)
        uint16 reg;               // Register number (if o_reg)
        ea_t addr;                // Address (if o_mem, o_near, o_far)
        uint64 value;             // Immediate value (if o_imm)
        std::string text;         // Operand text representation
    };
    std::vector<Operand> operands;
};

// Decode an instruction at address
bool decode_instruction_at(ea_t ea, DecodedInstruction& out) {
    insn_t insn;
    int len = decode_insn(&insn, ea);
    if (len <= 0) {
        return false;
    }

    out.ea = insn.ea;
    out.itype = insn.itype;
    out.size = insn.size;

    // Get mnemonic
    qstring mnem;
    print_insn_mnem(&mnem, ea);
    out.mnemonic = mnem.c_str();

    // Get full disassembly
    qstring disasm;
    generate_disasm_line(&disasm, ea, 0);
    tag_remove(&disasm);
    out.disasm = disasm.c_str();

    // Process operands
    for (int i = 0; i < UA_MAXOP; i++) {
        const op_t& op = insn.ops[i];
        if (op.type == o_void) break;

        DecodedInstruction::Operand operand;
        operand.type = op.type;
        operand.dtype = op.dtype;
        operand.reg = op.reg;
        operand.addr = op.addr;
        operand.value = op.value;

        // Get operand text
        qstring op_text;
        print_operand(&op_text, ea, i);
        tag_remove(&op_text);
        operand.text = op_text.c_str();

        out.operands.push_back(operand);
    }

    return true;
}

// Print decoded instruction info
void print_instruction(const DecodedInstruction& insn) {
    printf("Address:    0x%llx\n", (unsigned long long)insn.ea);
    printf("itype:      %u\n", insn.itype);
    printf("Size:       %u bytes\n", insn.size);
    printf("Mnemonic:   %s\n", insn.mnemonic.c_str());
    printf("Disasm:     %s\n", insn.disasm.c_str());
    printf("Operands:   %zu\n", insn.operands.size());

    for (size_t i = 0; i < insn.operands.size(); i++) {
        const auto& op = insn.operands[i];
        printf("  [%zu] type=%s dtype=%s text='%s'\n",
               i,
               get_optype_name(op.type),
               get_dtype_name(op.dtype),
               op.text.c_str());

        switch (op.type) {
            case o_reg:
                printf("      reg=%u\n", op.reg);
                break;
            case o_mem:
            case o_near:
            case o_far:
                printf("      addr=0x%llx\n", (unsigned long long)op.addr);
                break;
            case o_imm:
                printf("      value=0x%llx (%llu)\n",
                       (unsigned long long)op.value,
                       (unsigned long long)op.value);
                break;
            case o_displ:
            case o_phrase:
                printf("      reg=%u addr=0x%llx\n",
                       op.reg, (unsigned long long)op.addr);
                break;
            default:
                break;
        }
    }
    printf("\n");
}

// Build itype frequency map across all functions
void analyze_itype_distribution() {
    std::map<uint16, std::pair<std::string, int>> itype_stats;  // itype -> (mnemonic, count)

    int func_count = get_func_qty();
    printf("Analyzing %d functions...\n", func_count);

    for (int i = 0; i < func_count; i++) {
        func_t* func = getn_func(i);
        if (!func) continue;

        ea_t ea = func->start_ea;
        while (ea < func->end_ea && ea != BADADDR) {
            insn_t insn;
            int len = decode_insn(&insn, ea);
            if (len > 0) {
                auto& entry = itype_stats[insn.itype];
                if (entry.first.empty()) {
                    qstring mnem;
                    print_insn_mnem(&mnem, ea);
                    entry.first = mnem.c_str();
                }
                entry.second++;
                ea += len;
            } else {
                ea = next_head(ea, func->end_ea);
            }
        }
    }

    // Sort by count and print top instructions
    std::vector<std::tuple<int, uint16, std::string>> sorted;
    for (const auto& p : itype_stats) {
        sorted.emplace_back(p.second.second, p.first, p.second.first);
    }
    std::sort(sorted.rbegin(), sorted.rend());

    printf("\nTop 30 instruction types by frequency:\n");
    printf("%-8s %-12s %s\n", "itype", "mnemonic", "count");
    printf("-------------------------------------\n");
    for (size_t i = 0; i < 30 && i < sorted.size(); i++) {
        printf("%-8u %-12s %d\n",
               std::get<1>(sorted[i]),
               std::get<2>(sorted[i]).c_str(),
               std::get<0>(sorted[i]));
    }

    printf("\nTotal unique instruction types: %zu\n", itype_stats.size());
}

// Main test function - call from IDA or idalib
void run_insn_decode_test() {
    printf("=== Instruction Decode Test ===\n\n");

    // Test 1: Decode first few instructions of each function
    printf("--- Test 1: First instruction of functions ---\n\n");

    int func_count = get_func_qty();
    int shown = 0;

    for (int i = 0; i < func_count && shown < 5; i++) {
        func_t* func = getn_func(i);
        if (!func) continue;

        qstring func_name;
        get_func_name(&func_name, func->start_ea);
        printf("Function: %s\n", func_name.c_str());

        DecodedInstruction decoded;
        if (decode_instruction_at(func->start_ea, decoded)) {
            print_instruction(decoded);
            shown++;
        }
    }

    // Test 2: Show different operand types
    printf("--- Test 2: Finding different operand types ---\n\n");

    std::map<optype_t, DecodedInstruction> optype_examples;

    for (int i = 0; i < func_count && optype_examples.size() < 8; i++) {
        func_t* func = getn_func(i);
        if (!func) continue;

        ea_t ea = func->start_ea;
        while (ea < func->end_ea && ea != BADADDR) {
            DecodedInstruction decoded;
            if (decode_instruction_at(ea, decoded)) {
                for (const auto& op : decoded.operands) {
                    if (optype_examples.find(op.type) == optype_examples.end()) {
                        optype_examples[op.type] = decoded;
                    }
                }
            }
            ea = next_head(ea, func->end_ea);
        }
    }

    printf("Found examples for %zu operand types:\n\n", optype_examples.size());
    for (const auto& p : optype_examples) {
        printf("Operand type %s:\n", get_optype_name(p.first));
        print_instruction(p.second);
    }

    // Test 3: itype distribution
    printf("--- Test 3: Instruction type distribution ---\n\n");
    analyze_itype_distribution();
}

// Entry point for standalone testing
#ifdef STANDALONE_TEST
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <idb_path>\n", argv[0]);
        return 1;
    }

    // Initialize idalib
    if (!init_library()) {
        printf("Failed to initialize idalib\n");
        return 1;
    }

    // Open database
    if (!open_database(argv[1], false)) {
        printf("Failed to open database: %s\n", argv[1]);
        term_library();
        return 1;
    }

    // Run tests
    run_insn_decode_test();

    // Cleanup
    close_database(false);
    term_library();

    return 0;
}
#endif
