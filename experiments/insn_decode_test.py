"""
insn_decode_test.py - Instruction decoding experiment for IDA Python

Tests:
- decode_insn() API
- insn_t structure (itype, ea, size, ops[])
- op_t operand structure (type, dtype, reg, addr, value)
- itype to mnemonic mapping

Run with: ask_ida exec file experiments/insn_decode_test.py
"""

import idaapi
import idautils
import idc
import ida_funcs
import ida_ua
import ida_bytes
import ida_name

# Try to import ida_allins for instruction type constants
try:
    import ida_allins
    HAS_ALLINS = True
except ImportError:
    HAS_ALLINS = False
    print("[!] ida_allins not available - itype constants won't be resolved")

# Operand type constants and names
OPTYPE_NAMES = {
    ida_ua.o_void: "o_void",      # No operand
    ida_ua.o_reg: "o_reg",        # Register (al, ax, es, etc)
    ida_ua.o_mem: "o_mem",        # Direct memory reference
    ida_ua.o_phrase: "o_phrase",  # Indirect [reg]
    ida_ua.o_displ: "o_displ",    # Indirect [reg+disp]
    ida_ua.o_imm: "o_imm",        # Immediate value
    ida_ua.o_far: "o_far",        # Far code reference
    ida_ua.o_near: "o_near",      # Near code reference
}

# Add processor-specific types
for i in range(6):
    key = getattr(ida_ua, f"o_idpspec{i}", None)
    if key is not None:
        OPTYPE_NAMES[key] = f"o_idpspec{i}"

# Data type names
DTYPE_NAMES = {
    ida_ua.dt_byte: "dt_byte",       # 8 bit
    ida_ua.dt_word: "dt_word",       # 16 bit
    ida_ua.dt_dword: "dt_dword",     # 32 bit
    ida_ua.dt_float: "dt_float",     # 4 byte float
    ida_ua.dt_double: "dt_double",   # 8 byte float
    ida_ua.dt_tbyte: "dt_tbyte",     # 10 byte float
    ida_ua.dt_qword: "dt_qword",     # 64 bit
    ida_ua.dt_byte16: "dt_byte16",   # 128 bit
    ida_ua.dt_fword: "dt_fword",     # 48 bit
}


def decode_instruction(ea):
    """
    Decode an instruction at the given address.

    Returns dict with:
    - ea: Address
    - itype: Instruction type code
    - size: Instruction size in bytes
    - mnemonic: Mnemonic string
    - disasm: Full disassembly line
    - operands: List of operand dicts
    """
    insn = ida_ua.insn_t()
    length = ida_ua.decode_insn(insn, ea)

    if length <= 0:
        return None

    result = {
        'ea': insn.ea,
        'itype': insn.itype,
        'size': insn.size,
        'mnemonic': idc.print_insn_mnem(ea),
        'disasm': idc.generate_disasm_line(ea, 0),
        'operands': []
    }

    # Process operands
    for i in range(ida_ua.UA_MAXOP):
        op = insn.ops[i]
        if op.type == ida_ua.o_void:
            break

        op_info = {
            'n': i,
            'type': op.type,
            'type_name': OPTYPE_NAMES.get(op.type, f"unknown({op.type})"),
            'dtype': op.dtype,
            'dtype_name': DTYPE_NAMES.get(op.dtype, f"unknown({op.dtype})"),
            'reg': op.reg,
            'addr': op.addr,
            'value': op.value,
            'text': idc.print_operand(ea, i),
        }
        result['operands'].append(op_info)

    return result


def print_instruction(insn_info):
    """Pretty print decoded instruction info."""
    if insn_info is None:
        print("  [Failed to decode]")
        return

    print(f"  Address:  0x{insn_info['ea']:x}")
    print(f"  itype:    {insn_info['itype']}")
    print(f"  Size:     {insn_info['size']} bytes")
    print(f"  Mnemonic: {insn_info['mnemonic']}")
    print(f"  Disasm:   {insn_info['disasm']}")
    print(f"  Operands: {len(insn_info['operands'])}")

    for op in insn_info['operands']:
        print(f"    [{op['n']}] type={op['type_name']} dtype={op['dtype_name']} text='{op['text']}'")
        if op['type'] == ida_ua.o_reg:
            print(f"        reg={op['reg']}")
        elif op['type'] in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
            print(f"        addr=0x{op['addr']:x}")
        elif op['type'] == ida_ua.o_imm:
            print(f"        value=0x{op['value']:x} ({op['value']})")
        elif op['type'] in (ida_ua.o_displ, ida_ua.o_phrase):
            print(f"        reg={op['reg']} addr=0x{op['addr']:x}")


def build_itype_mapping():
    """
    Build a mapping from itype values to mnemonic strings.

    This scans all instructions in the database to discover
    which itype values correspond to which mnemonics.
    """
    itype_to_mnem = {}

    func_count = ida_funcs.get_func_qty()
    print(f"Scanning {func_count} functions for itype mapping...")

    for i in range(func_count):
        func = ida_funcs.getn_func(i)
        if not func:
            continue

        for ea in idautils.FuncItems(func.start_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) > 0:
                if insn.itype not in itype_to_mnem:
                    mnem = idc.print_insn_mnem(ea)
                    itype_to_mnem[insn.itype] = mnem

    return itype_to_mnem


def analyze_itype_distribution():
    """Analyze instruction type distribution across the database."""
    itype_stats = {}  # itype -> (mnemonic, count)

    func_count = ida_funcs.get_func_qty()
    print(f"Analyzing instruction distribution in {func_count} functions...")

    total_insns = 0
    for i in range(func_count):
        func = ida_funcs.getn_func(i)
        if not func:
            continue

        for ea in idautils.FuncItems(func.start_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) > 0:
                total_insns += 1
                if insn.itype not in itype_stats:
                    mnem = idc.print_insn_mnem(ea)
                    itype_stats[insn.itype] = [mnem, 0]
                itype_stats[insn.itype][1] += 1

    # Sort by count
    sorted_stats = sorted(itype_stats.items(), key=lambda x: x[1][1], reverse=True)

    print(f"\nTotal instructions analyzed: {total_insns}")
    print(f"Unique instruction types: {len(itype_stats)}")
    print(f"\nTop 30 instructions by frequency:")
    print(f"{'itype':<8} {'mnemonic':<12} {'count':<10} {'%':>6}")
    print("-" * 40)

    for itype, (mnem, count) in sorted_stats[:30]:
        pct = (count / total_insns) * 100 if total_insns > 0 else 0
        print(f"{itype:<8} {mnem:<12} {count:<10} {pct:>5.1f}%")

    return itype_stats


def find_operand_type_examples():
    """Find example instructions for each operand type."""
    examples = {}  # optype -> instruction info

    func_count = ida_funcs.get_func_qty()

    for i in range(func_count):
        if len(examples) >= len(OPTYPE_NAMES):
            break

        func = ida_funcs.getn_func(i)
        if not func:
            continue

        for ea in idautils.FuncItems(func.start_ea):
            insn_info = decode_instruction(ea)
            if insn_info:
                for op in insn_info['operands']:
                    optype = op['type']
                    if optype not in examples and optype != ida_ua.o_void:
                        examples[optype] = insn_info

    return examples


def generate_itype_header():
    """Generate a C++ header with itype to mnemonic mapping."""
    mapping = build_itype_mapping()

    print(f"\n// Generated itype mapping ({len(mapping)} entries)")
    print("static const char* itype_to_mnemonic[] = {")

    max_itype = max(mapping.keys()) if mapping else 0
    for i in range(max_itype + 1):
        if i in mapping:
            print(f'    /* {i:4} */ "{mapping[i]}",')
        else:
            print(f'    /* {i:4} */ nullptr,')

    print("};")
    print(f"static const size_t itype_count = {max_itype + 1};")


def run_tests():
    """Run all instruction decoding tests."""
    print("=" * 60)
    print("INSTRUCTION DECODING TEST")
    print("=" * 60)

    # Test 1: Decode first instruction of some functions
    print("\n--- Test 1: First instruction of functions ---\n")
    func_count = ida_funcs.get_func_qty()
    shown = 0

    for i in range(func_count):
        if shown >= 5:
            break
        func = ida_funcs.getn_func(i)
        if not func:
            continue

        func_name = ida_name.get_name(func.start_ea)
        print(f"Function: {func_name}")

        insn_info = decode_instruction(func.start_ea)
        print_instruction(insn_info)
        print()
        shown += 1

    # Test 2: Operand type examples
    print("\n--- Test 2: Operand type examples ---\n")
    examples = find_operand_type_examples()

    for optype, insn_info in sorted(examples.items()):
        print(f"Example for {OPTYPE_NAMES.get(optype, 'unknown')}:")
        print_instruction(insn_info)
        print()

    # Test 3: itype distribution
    print("\n--- Test 3: itype distribution ---\n")
    analyze_itype_distribution()

    # Test 4: Generate C++ mapping (partial output)
    print("\n--- Test 4: C++ itype mapping (preview) ---\n")
    mapping = build_itype_mapping()
    print(f"Found {len(mapping)} unique itype values")
    print("First 10 entries:")
    for itype in sorted(mapping.keys())[:10]:
        print(f"  itype {itype:4} -> {mapping[itype]}")


if __name__ == "__main__":
    run_tests()
