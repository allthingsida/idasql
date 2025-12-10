"""
extract_allins.py - Extract instruction type constants from ida_allins

This script extracts all NN_* constants from the ida_allins module
and generates a C++ header file with the mapping.

Run with: ask_ida exec file experiments/extract_allins.py
"""

import sys

try:
    import ida_allins
except ImportError:
    print("ERROR: ida_allins module not available")
    print("This script must be run inside IDA Pro")
    sys.exit(1)


def extract_nn_constants():
    """Extract all NN_* constants from ida_allins."""
    constants = {}

    for name in dir(ida_allins):
        if name.startswith('NN_'):
            value = getattr(ida_allins, name)
            if isinstance(value, int):
                constants[value] = name

    return constants


def generate_cpp_header(constants, output_path=None):
    """Generate C++ header with itype mapping."""
    lines = []
    lines.append("/**")
    lines.append(" * ida_itype_names.hpp - Auto-generated instruction type mapping")
    lines.append(" *")
    lines.append(" * Generated from ida_allins module")
    lines.append(f" * Total constants: {len(constants)}")
    lines.append(" */")
    lines.append("")
    lines.append("#pragma once")
    lines.append("")
    lines.append("#include <cstddef>")
    lines.append("")
    lines.append("namespace idasql {")
    lines.append("namespace x86 {")
    lines.append("")

    # Find max itype value
    max_itype = max(constants.keys()) if constants else 0

    lines.append(f"// Max instruction type value: {max_itype}")
    lines.append(f"static constexpr size_t ITYPE_COUNT = {max_itype + 1};")
    lines.append("")

    # Generate the mapping array
    lines.append("// Instruction type to name mapping")
    lines.append("// Index is the itype value, value is the constant name (without NN_ prefix)")
    lines.append("static const char* itype_names[ITYPE_COUNT] = {")

    for i in range(max_itype + 1):
        if i in constants:
            name = constants[i]
            # Remove NN_ prefix for cleaner output
            short_name = name[3:] if name.startswith('NN_') else name
            lines.append(f'    /* {i:4} */ "{short_name}",')
        else:
            lines.append(f'    /* {i:4} */ nullptr,')

    lines.append("};")
    lines.append("")

    # Generate lookup function
    lines.append("// Get instruction name by itype")
    lines.append("inline const char* get_itype_name(unsigned int itype) {")
    lines.append("    if (itype >= ITYPE_COUNT) return nullptr;")
    lines.append("    return itype_names[itype];")
    lines.append("}")
    lines.append("")

    lines.append("}  // namespace x86")
    lines.append("}  // namespace idasql")

    content = '\n'.join(lines)

    if output_path:
        with open(output_path, 'w') as f:
            f.write(content)
        print(f"Generated: {output_path}")
    else:
        print(content)

    return content


def generate_enum(constants):
    """Generate a C++ enum for instruction types."""
    lines = []
    lines.append("// Instruction type enum (from ida_allins)")
    lines.append("enum itype_t : uint16 {")

    for itype in sorted(constants.keys()):
        name = constants[itype]
        lines.append(f"    {name} = {itype},")

    lines.append("};")
    return '\n'.join(lines)


def print_stats(constants):
    """Print statistics about extracted constants."""
    print(f"Extracted {len(constants)} instruction type constants")
    print(f"itype range: 0 - {max(constants.keys())}")
    print()

    # Group by prefix
    prefixes = {}
    for itype, name in constants.items():
        # Get the base instruction name (first part before _)
        parts = name[3:].split('_')  # Remove NN_ and split
        base = parts[0].lower()
        if base not in prefixes:
            prefixes[base] = []
        prefixes[base].append((itype, name))

    # Find most common instruction families
    sorted_families = sorted(prefixes.items(), key=lambda x: len(x[1]), reverse=True)

    print("Top 20 instruction families:")
    print("-" * 40)
    for prefix, entries in sorted_families[:20]:
        print(f"  {prefix:<15} {len(entries):>4} variants")

    print()
    print("Sample entries (first 20):")
    print("-" * 40)
    for itype in sorted(constants.keys())[:20]:
        print(f"  {itype:4} -> {constants[itype]}")


def main():
    """Main entry point."""
    print("=" * 60)
    print("Extracting x86/x64 instruction type constants from ida_allins")
    print("=" * 60)
    print()

    constants = extract_nn_constants()

    if not constants:
        print("ERROR: No NN_* constants found in ida_allins")
        print("Make sure you're analyzing an x86/x64 binary")
        return

    print_stats(constants)

    # Generate header file
    print()
    print("=" * 60)
    print("Generating C++ header...")
    print("=" * 60)

    # Just show preview
    lines = generate_cpp_header(constants)


if __name__ == "__main__":
    main()
