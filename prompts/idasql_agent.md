# IDASQL Agent Guide

A comprehensive reference for AI agents to effectively use IDASQL - an SQL interface for reverse engineering binary analysis with IDA Pro.

---

## What is IDA and Why SQL?

**IDA Pro** is the industry-standard disassembler and reverse engineering tool. It analyzes compiled binaries (executables, DLLs, firmware) and produces:
- **Disassembly** - Human-readable assembly code
- **Functions** - Detected code boundaries with names
- **Cross-references** - Who calls what, who references what data
- **Types** - Structures, enums, function prototypes
- **Decompilation** - C-like pseudocode (with Hex-Rays plugin)

**IDASQL** exposes all this analysis data through SQL virtual tables, enabling:
- Complex queries across multiple data types (JOINs)
- Aggregations and statistics (COUNT, GROUP BY)
- Pattern detection across the entire binary
- Scriptable analysis without writing IDA plugins or IDAPython scripts

---

## Core Concepts for Binary Analysis

### Addresses (ea_t)
Everything in a binary has an **address** - a memory location where code or data lives. IDA uses `ea_t` (effective address) as unsigned 64-bit integers. SQL shows these as integers; use `printf('0x%X', address)` for hex display.

### Functions
IDA groups code into **functions** with:
- `address` / `start_ea` - Where the function begins
- `end_ea` - Where it ends
- `name` - Assigned or auto-generated name (e.g., `main`, `sub_401000`)
- `size` - Total bytes in the function

### Cross-References (xrefs)
Binary analysis is about understanding **relationships**:
- **Code xrefs** - Function calls, jumps between code
- **Data xrefs** - Code reading/writing data locations
- `from_ea` → `to_ea` represents "address X references address Y"

### Segments
Memory is divided into **segments** with different purposes:
- `.text` - Executable code (typically)
- `.data` - Initialized global data
- `.rdata` - Read-only data (strings, constants)
- `.bss` - Uninitialized data

Of course, segment names and types can vary. You may query the `segments` table to understand memory layout.

### Basic Blocks
Within a function, **basic blocks** are straight-line code sequences:
- No branches in the middle
- Single entry, single exit
- Useful for control flow analysis

### Decompilation (Hex-Rays)
The **Hex-Rays decompiler** converts assembly to C-like **pseudocode**:
- **ctree** - The Abstract Syntax Tree of decompiled code
- **lvars** - Local variables detected by the decompiler
- Much easier to analyze than raw assembly

---

## CLI Usage

```bash
# Single query
idasql -s database.i64 -q "SELECT * FROM funcs LIMIT 10"

# Execute SQL file
idasql -s database.i64 -f script.sql

# Interactive mode
idasql -s database.i64 -i

# Output as JSON
idasql -s database.i64 -q "SELECT * FROM funcs" --format=json

# Export tables to SQL
idasql -s database.i64 --export out.sql
```

**Note:** The `-s` flag specifies the IDA database file (`.i64` for 64-bit, `.idb` for 32-bit).

---

## Tables Reference

### Entity Tables (Read-Only)

#### funcs
All detected functions in the binary.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Function start address |
| `name` | TEXT | Function name |
| `size` | INT | Function size in bytes |
| `end_ea` | INT | Function end address |
| `flags` | INT | Function flags |

```sql
-- 10 largest functions
SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10;

-- Functions starting with "sub_" (auto-named, not analyzed)
SELECT name, printf('0x%X', address) as addr FROM funcs WHERE name LIKE 'sub_%';
```

#### segments
Memory segments.

| Column | Type | Description |
|--------|------|-------------|
| `start_ea` | INT | Segment start |
| `end_ea` | INT | Segment end |
| `name` | TEXT | Segment name (.text, .data, etc.) |
| `class` | TEXT | Segment class (CODE, DATA) |
| `perm` | INT | Permissions (R=4, W=2, X=1) |

```sql
-- Find executable segments
SELECT name, printf('0x%X', start_ea) as start FROM segments WHERE perm & 1 = 1;
```

#### names
All named locations (functions, labels, data).

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Address |
| `name` | TEXT | Name |

#### entries
Entry points (exports, program entry).

| Column | Type | Description |
|--------|------|-------------|
| `ordinal` | INT | Export ordinal |
| `address` | INT | Entry address |
| `name` | TEXT | Entry name |

#### imports
Imported functions from external libraries.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Import address (IAT entry) |
| `name` | TEXT | Import name |
| `module` | TEXT | Module/DLL name |
| `ordinal` | INT | Import ordinal |

```sql
-- Imports from kernel32.dll
SELECT name FROM imports WHERE module LIKE '%kernel32%';
```

#### strings
String literals found in the binary. IDA maintains a cached string list that can be configured.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | String address |
| `length` | INT | String length |
| `type` | INT | String type (raw encoding bits) |
| `type_name` | TEXT | Type name: ascii, utf16, utf32 |
| `width` | INT | Char width (0=1-byte, 1=2-byte, 2=4-byte) |
| `width_name` | TEXT | Width name: 1-byte, 2-byte, 4-byte |
| `layout` | INT | String layout (0=null-terminated, 1-3=pascal) |
| `layout_name` | TEXT | Layout name: termchr, pascal1, pascal2, pascal4 |
| `encoding` | INT | Encoding index (0=default) |
| `content` | TEXT | String content |

**String Type Encoding:**
IDA stores string type as a 32-bit value:
- Bits 0-1: Width (0=1B/ASCII, 1=2B/UTF-16, 2=4B/UTF-32)
- Bits 2-7: Layout (0=TERMCHR, 1=PASCAL1, 2=PASCAL2, 3=PASCAL4)
- Bits 8-15: term1 (first termination character)
- Bits 16-23: term2 (second termination character)
- Bits 24-31: encoding index

```sql
-- Find error messages
SELECT content, printf('0x%X', address) as addr FROM strings WHERE content LIKE '%error%';

-- ASCII strings only
SELECT * FROM strings WHERE type_name = 'ascii';

-- UTF-16 strings (common in Windows)
SELECT * FROM strings WHERE type_name = 'utf16';

-- Count strings by type
SELECT type_name, layout_name, COUNT(*) as count
FROM strings GROUP BY type_name, layout_name ORDER BY count DESC;
```

**Important:** IDA's string list is cached. If you see 0 strings, use `rebuild_strings()` to rebuild the list. To change string types/settings, use IDA's Strings window (Shift+F12 → Setup). See the String List Functions section below.

#### xrefs
Cross-references - the most important table for understanding code relationships.

| Column | Type | Description |
|--------|------|-------------|
| `from_ea` | INT | Source address (who references) |
| `to_ea` | INT | Target address (what is referenced) |
| `type` | INT | Xref type code |
| `is_code` | INT | 1=code xref (call/jump), 0=data xref |

```sql
-- Who calls function at 0x401000?
SELECT printf('0x%X', from_ea) as caller FROM xrefs WHERE to_ea = 0x401000 AND is_code = 1;

-- What does function at 0x401000 reference?
SELECT printf('0x%X', to_ea) as target FROM xrefs WHERE from_ea >= 0x401000 AND from_ea < 0x401100;
```

#### blocks
Basic blocks within functions. **Use `func_ea` constraint for performance.**

| Column | Type | Description |
|--------|------|-------------|
| `func_ea` | INT | Containing function |
| `start_ea` | INT | Block start |
| `end_ea` | INT | Block end |
| `size` | INT | Block size |

```sql
-- Blocks in a specific function (FAST - uses constraint pushdown)
SELECT * FROM blocks WHERE func_ea = 0x401000;

-- Functions with most basic blocks
SELECT func_at(func_ea) as name, COUNT(*) as blocks
FROM blocks GROUP BY func_ea ORDER BY blocks DESC LIMIT 10;
```

### Instruction Tables

#### instructions
Decoded instructions. **Always filter by `func_addr` for performance.**

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Instruction address |
| `func_addr` | INT | Containing function |
| `itype` | INT | Instruction type (architecture-specific) |
| `mnemonic` | TEXT | Instruction mnemonic |
| `size` | INT | Instruction size |
| `operand0` | TEXT | First operand |
| `operand1` | TEXT | Second operand |
| `disasm` | TEXT | Full disassembly line |

```sql
-- Instruction profile of a function (FAST)
SELECT mnemonic, COUNT(*) as count
FROM instructions WHERE func_addr = 0x401330
GROUP BY mnemonic ORDER BY count DESC;

-- Find all call instructions in a function
SELECT address, disasm FROM instructions
WHERE func_addr = 0x401000 AND mnemonic = 'call';
```

**Performance:** `WHERE func_addr = X` uses O(function_size) iteration. Without this constraint, it scans the entire database - SLOW.

#### disasm_calls
All call instructions with resolved targets.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function containing the call |
| `ea` | INT | Call instruction address |
| `callee_addr` | INT | Target address (0 if unknown) |
| `callee_name` | TEXT | Target name |

```sql
-- Functions that call malloc
SELECT DISTINCT func_at(func_addr) as caller
FROM disasm_calls WHERE callee_name LIKE '%malloc%';
```

### Database Modification

**Note:** IDASQL currently modifies the database via SQL functions rather than writable virtual tables.

#### Modification Functions

```sql
-- Rename a function or set a name at address
SELECT set_name(0x401000, 'my_main');

-- Add a regular comment
SELECT set_comment(0x401050, 'Check return value');

-- Add a repeatable comment (shows everywhere address is referenced)
SELECT set_comment(0x404000, 'Global config', 1);

-- Rename a local variable in decompiled code
SELECT rename_lvar(0x401000, 'v1', 'buffer_size');
```

**Future:** Live virtual tables (`funcs_live`, `names_live`, `comments_live`) with UPDATE/DELETE support are planned but not yet implemented.

### Decompiler Tables (Hex-Rays Required)

**CRITICAL:** Always filter by `func_addr`. Without constraint, these tables will decompile EVERY function - extremely slow!

#### pseudocode
Decompiled C-like code lines.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function address |
| `line_num` | INT | Line number |
| `line` | TEXT | Pseudocode text |
| `ea` | INT | Corresponding assembly address |

```sql
-- Get pseudocode for a specific function (FAST)
SELECT line FROM pseudocode WHERE func_addr = 0x401000 ORDER BY line_num;
```

#### ctree
Full Abstract Syntax Tree of decompiled code.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function address |
| `item_id` | INT | Unique node ID |
| `is_expr` | INT | 1=expression, 0=statement |
| `op_name` | TEXT | Node type (`cot_call`, `cit_if`, etc.) |
| `ea` | INT | Address in binary |
| `parent_id` | INT | Parent node ID |
| `depth` | INT | Tree depth |
| `x_id`, `y_id`, `z_id` | INT | Child node IDs |
| `var_idx` | INT | Local variable index |
| `var_name` | TEXT | Variable name |
| `obj_ea` | INT | Target address |
| `obj_name` | TEXT | Symbol name |
| `num_value` | INT | Numeric literal |
| `str_value` | TEXT | String literal |

#### ctree_lvars
Local variables from decompilation.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function address |
| `idx` | INT | Variable index |
| `name` | TEXT | Variable name |
| `type` | TEXT | Type string |
| `size` | INT | Size in bytes |
| `is_arg` | INT | 1=function argument |
| `is_stk_var` | INT | 1=stack variable |
| `stkoff` | INT | Stack offset |

#### ctree_call_args
Flattened call arguments for easy querying.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function address |
| `call_item_id` | INT | Call node ID |
| `arg_idx` | INT | Argument index (0-based) |
| `arg_op` | TEXT | Argument type |
| `arg_var_name` | TEXT | Variable name if applicable |
| `arg_var_is_stk` | INT | 1=stack variable |
| `arg_num_value` | INT | Numeric value |
| `arg_str_value` | TEXT | String value |

### Decompiler Views

Pre-built views for common patterns:

| View | Purpose |
|------|---------|
| `ctree_v_calls` | Function calls with callee info |
| `ctree_v_loops` | for/while/do loops |
| `ctree_v_ifs` | if statements |
| `ctree_v_comparisons` | Comparisons with operands |
| `ctree_v_assignments` | Assignments with operands |
| `ctree_v_derefs` | Pointer dereferences |
| `ctree_v_returns` | Return statements with value details |
| `ctree_v_calls_in_loops` | Calls inside loops (recursive) |
| `ctree_v_calls_in_ifs` | Calls inside if branches (recursive) |
| `ctree_v_leaf_funcs` | Functions with no outgoing calls |
| `ctree_v_call_chains` | Call chain paths up to depth 10 |

#### ctree_v_returns

Return statements with details about what's being returned.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function address |
| `item_id` | INT | Return statement item_id |
| `ea` | INT | Address of return |
| `return_op` | TEXT | Return value opcode (`cot_num`, `cot_var`, `cot_call`, etc.) |
| `return_num` | INT | Numeric value (if `cot_num`) |
| `return_str` | TEXT | String value (if `cot_str`) |
| `return_var` | TEXT | Variable name (if `cot_var`) |
| `returns_arg` | INT | 1 if returning a function argument |
| `returns_call_result` | INT | 1 if returning result of another call |

```sql
-- Functions that return 0
SELECT DISTINCT func_at(func_addr) as name FROM ctree_v_returns
WHERE return_op = 'cot_num' AND return_num = 0;

-- Functions that return -1 (error sentinel)
SELECT DISTINCT func_at(func_addr) as name FROM ctree_v_returns
WHERE return_op = 'cot_num' AND return_num = -1;

-- Functions that return their argument (pass-through)
SELECT DISTINCT func_at(func_addr) as name FROM ctree_v_returns
WHERE returns_arg = 1;
```

### Type Tables

#### types
All local type definitions.

| Column | Type | Description |
|--------|------|-------------|
| `ordinal` | INT | Type ordinal |
| `name` | TEXT | Type name |
| `size` | INT | Size in bytes |
| `kind` | TEXT | struct/union/enum/typedef/func |
| `is_struct` | INT | 1=struct |
| `is_union` | INT | 1=union |
| `is_enum` | INT | 1=enum |

#### types_members
Structure and union members.

| Column | Type | Description |
|--------|------|-------------|
| `type_ordinal` | INT | Parent type ordinal |
| `type_name` | TEXT | Parent type name |
| `member_name` | TEXT | Member name |
| `offset` | INT | Byte offset |
| `size` | INT | Member size |
| `member_type` | TEXT | Type string |
| `mt_is_ptr` | INT | 1=pointer |
| `mt_is_array` | INT | 1=array |
| `mt_is_struct` | INT | 1=embedded struct |

#### types_enum_values
Enum constant values.

| Column | Type | Description |
|--------|------|-------------|
| `type_ordinal` | INT | Enum type ordinal |
| `type_name` | TEXT | Enum name |
| `value_name` | TEXT | Constant name |
| `value` | INT | Constant value |

#### types_func_args
Function prototype arguments with type classification.

| Column | Type | Description |
|--------|------|-------------|
| `type_ordinal` | INT | Function type ordinal |
| `type_name` | TEXT | Function type name |
| `arg_index` | INT | Argument index (-1 = return type, 0+ = args) |
| `arg_name` | TEXT | Argument name |
| `arg_type` | TEXT | Argument type string |
| `calling_conv` | TEXT | Calling convention (on return row only) |

**Surface-level type classification** (literal type as written):

| Column | Type | Description |
|--------|------|-------------|
| `is_ptr` | INT | 1 if pointer type |
| `is_int` | INT | 1 if exactly int type |
| `is_integral` | INT | 1 if int-like (int, long, short, char, bool) |
| `is_float` | INT | 1 if float/double |
| `is_void` | INT | 1 if void |
| `is_struct` | INT | 1 if struct/union |
| `is_array` | INT | 1 if array |
| `ptr_depth` | INT | Pointer depth (int** = 2) |
| `base_type` | TEXT | Type with pointers stripped |

**Resolved type classification** (after typedef resolution):

| Column | Type | Description |
|--------|------|-------------|
| `is_ptr_resolved` | INT | 1 if resolved type is pointer |
| `is_int_resolved` | INT | 1 if resolved type is exactly int |
| `is_integral_resolved` | INT | 1 if resolved type is int-like |
| `is_float_resolved` | INT | 1 if resolved type is float/double |
| `is_void_resolved` | INT | 1 if resolved type is void |
| `ptr_depth_resolved` | INT | Pointer depth after resolution |
| `base_type_resolved` | TEXT | Resolved type with pointers stripped |

```sql
-- Functions returning integers (strict: exactly int)
SELECT type_name FROM types_func_args
WHERE arg_index = -1 AND is_int = 1;

-- Functions returning integers (loose: includes BOOL, DWORD, LONG)
SELECT type_name FROM types_func_args
WHERE arg_index = -1 AND is_integral_resolved = 1;

-- Functions taking 4 pointer arguments
SELECT type_name, COUNT(*) as ptr_args FROM types_func_args
WHERE arg_index >= 0 AND is_ptr = 1
GROUP BY type_ordinal HAVING ptr_args = 4;

-- Typedefs that hide pointers (HANDLE, etc.)
SELECT type_name, arg_type FROM types_func_args
WHERE is_ptr = 0 AND is_ptr_resolved = 1;
```

### Type Views

Convenience views for filtering types:

| View | Description |
|------|-------------|
| `types_v_structs` | `SELECT * FROM types WHERE is_struct = 1` |
| `types_v_unions` | `SELECT * FROM types WHERE is_union = 1` |
| `types_v_enums` | `SELECT * FROM types WHERE is_enum = 1` |
| `types_v_typedefs` | `SELECT * FROM types WHERE is_typedef = 1` |
| `types_v_funcs` | `SELECT * FROM types WHERE is_func = 1` |
| `local_types` | Legacy compatibility view |

### Extended Tables

#### bookmarks
User-defined bookmarks/marked positions.

| Column | Type | Description |
|--------|------|-------------|
| `index` | INT | Bookmark index |
| `address` | INT | Bookmarked address |
| `description` | TEXT | Bookmark description |

```sql
-- List all bookmarks
SELECT printf('0x%X', address) as addr, description FROM bookmarks;
```

#### heads
All defined items (code/data heads) in the database.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Head address |
| `size` | INT | Item size |
| `flags` | INT | IDA flags |

**Performance:** This table can be very large. Always use address range filters.

#### fixups
Relocation and fixup information.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Fixup address |
| `type` | INT | Fixup type |
| `target` | INT | Target address |

#### hidden_ranges
Collapsed/hidden code regions in IDA.

| Column | Type | Description |
|--------|------|-------------|
| `start_ea` | INT | Range start |
| `end_ea` | INT | Range end |
| `description` | TEXT | Description |
| `visible` | INT | Visibility state |

#### problems
IDA analysis problems and warnings.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Problem address |
| `type` | INT | Problem type code |
| `description` | TEXT | Problem description |

```sql
-- Find all analysis problems
SELECT printf('0x%X', address) as addr, description FROM problems;
```

#### fchunks
Function chunks (for functions with non-contiguous code, like exception handlers).

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Parent function |
| `start_ea` | INT | Chunk start |
| `end_ea` | INT | Chunk end |
| `size` | INT | Chunk size |

```sql
-- Functions with multiple chunks (complex control flow)
SELECT func_at(func_addr) as name, COUNT(*) as chunks
FROM fchunks GROUP BY func_addr HAVING chunks > 1;
```

#### signatures
FLIRT signature matches.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Matched address |
| `name` | TEXT | Signature name |
| `library` | TEXT | Library name |

#### mappings
Memory mappings for debugging.

| Column | Type | Description |
|--------|------|-------------|
| `from_ea` | INT | Mapped from |
| `to_ea` | INT | Mapped to |
| `size` | INT | Mapping size |

### Metadata Tables

#### db_info
Database-level metadata.

| Column | Type | Description |
|--------|------|-------------|
| `key` | TEXT | Metadata key |
| `value` | TEXT | Metadata value |

```sql
-- Get database info
SELECT * FROM db_info;
```

#### ida_info
IDA processor and analysis info.

| Column | Type | Description |
|--------|------|-------------|
| `key` | TEXT | Info key |
| `value` | TEXT | Info value |

```sql
-- Get processor type
SELECT value FROM ida_info WHERE key = 'procname';
```

### Disassembly Tables

#### disasm_loops
Detected loops in disassembly.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function address |
| `loop_start` | INT | Loop header address |
| `loop_end` | INT | Loop end address |

### Disassembly Views

Views for disassembly-level analysis (no Hex-Rays required):

| View | Description |
|------|-------------|
| `disasm_v_leaf_funcs` | Functions with no outgoing calls |
| `disasm_v_call_chains` | Call chain paths (recursive CTE) |
| `disasm_v_calls_in_loops` | Calls inside loop bodies |
| `disasm_v_funcs_with_loops` | Functions containing loops |

```sql
-- Find functions that don't call anything
SELECT * FROM disasm_v_leaf_funcs LIMIT 10;

-- Find hotspot calls (inside loops)
SELECT func_at(func_addr) as func, callee_name
FROM disasm_v_calls_in_loops;
```

---

## SQL Functions

### Disassembly
| Function | Description |
|----------|-------------|
| `disasm(addr)` | Disassembly line at address |
| `disasm(addr, n)` | Multiple lines from address |
| `bytes(addr, n)` | Bytes as hex string |
| `bytes_raw(addr, n)` | Raw bytes as BLOB |
| `mnemonic(addr)` | Instruction mnemonic only |
| `operand(addr, n)` | Operand text (n=0-5) |

### Names & Functions
| Function | Description |
|----------|-------------|
| `name_at(addr)` | Name at address |
| `func_at(addr)` | Function name containing address |
| `func_start(addr)` | Start of containing function |
| `func_end(addr)` | End of containing function |
| `func_qty()` | Total function count |
| `func_at_index(n)` | Function address at index (O(1)) |

### Cross-References
| Function | Description |
|----------|-------------|
| `xrefs_to(addr)` | JSON array of xrefs TO address |
| `xrefs_from(addr)` | JSON array of xrefs FROM address |

### Navigation
| Function | Description |
|----------|-------------|
| `next_head(addr)` | Next defined item |
| `prev_head(addr)` | Previous defined item |
| `segment_at(addr)` | Segment name at address |
| `hex(val)` | Format as hex string |

### Comments
| Function | Description |
|----------|-------------|
| `comment_at(addr)` | Get comment at address |
| `set_comment(addr, text)` | Set regular comment |
| `set_comment(addr, text, 1)` | Set repeatable comment |

### Modification
| Function | Description |
|----------|-------------|
| `set_name(addr, name)` | Set name at address |

### Item Analysis
| Function | Description |
|----------|-------------|
| `item_type(addr)` | Item type flags at address |
| `item_size(addr)` | Item size at address |
| `is_code(addr)` | Returns 1 if address is code |
| `is_data(addr)` | Returns 1 if address is data |
| `flags_at(addr)` | Raw IDA flags at address |

### Instruction Details
| Function | Description |
|----------|-------------|
| `itype(addr)` | Instruction type code (processor-specific) |
| `decode_insn(addr)` | Full instruction info as JSON |
| `operand_type(addr, n)` | Operand type code (o_void, o_reg, etc.) |
| `operand_value(addr, n)` | Operand value (register num, immediate, etc.) |

```sql
-- Get instruction type for filtering
SELECT address, itype(address) as itype, mnemonic(address)
FROM heads WHERE is_code(address) = 1 LIMIT 10;

-- Decode full instruction
SELECT decode_insn(0x401000);
```

### Decompilation
| Function | Description |
|----------|-------------|
| `decompile(addr)` | Full pseudocode (requires Hex-Rays) |
| `list_lvars(addr)` | List local variables as JSON |
| `rename_lvar(addr, old, new)` | Rename a local variable |

```sql
-- Get all local variables in a function
SELECT list_lvars(0x401000);

-- Rename a variable
SELECT rename_lvar(0x401000, 'v1', 'buffer_size');
```

### File Generation
| Function | Description |
|----------|-------------|
| `gen_asm_file(start, end, path)` | Generate ASM file |
| `gen_lst_file(start, end, path)` | Generate listing file |
| `gen_map_file(path)` | Generate MAP file |
| `gen_idc_file(start, end, path)` | Generate IDC script |
| `gen_html_file(start, end, path)` | Generate HTML file |

```sql
-- Export function as ASM
SELECT gen_asm_file(0x401000, 0x401100, '/tmp/func.asm');

-- Generate MAP file
SELECT gen_map_file('/tmp/binary.map');
```

### Graph Generation
| Function | Description |
|----------|-------------|
| `gen_cfg_dot(addr)` | Generate CFG as DOT graph string |
| `gen_cfg_dot_file(addr, path)` | Write CFG DOT to file |
| `gen_schema_dot()` | Generate database schema as DOT |

```sql
-- Get CFG for a function as DOT format
SELECT gen_cfg_dot(0x401000);

-- Export schema visualization
SELECT gen_schema_dot();
```

### Entity Search ("Jump to Anything")
| Function | Description |
|----------|-------------|
| `jump_search(pattern, mode, limit, offset)` | Search entities, returns JSON array |
| `jump_query(pattern, mode, limit, offset)` | Returns the generated SQL string |

```sql
-- Search for functions/types/labels starting with 'sub'
SELECT jump_search('sub', 'prefix', 10, 0);

-- Search for anything containing 'main'
SELECT jump_search('main', 'contains', 10, 0);
```

### String List Functions

IDA maintains a cached list of strings. Use `rebuild_strings()` to detect and cache strings.

| Function | Description |
|----------|-------------|
| `rebuild_strings()` | Rebuild with ASCII + UTF-16, minlen 5 (default) |
| `rebuild_strings(minlen)` | Rebuild with custom minimum length |
| `rebuild_strings(minlen, types)` | Rebuild with custom length and type mask |
| `string_count()` | Get current string count (no rebuild) |

**Type mask values:**
- `1` = ASCII only (STRTYPE_C)
- `2` = UTF-16 only (STRTYPE_C_16)
- `4` = UTF-32 only (STRTYPE_C_32)
- `3` = ASCII + UTF-16 (default)
- `7` = All types

```sql
-- Check current string count
SELECT string_count();

-- Rebuild with defaults (ASCII + UTF-16, minlen 5)
SELECT rebuild_strings();

-- Rebuild with shorter minimum length
SELECT rebuild_strings(4);

-- Rebuild with specific types
SELECT rebuild_strings(5, 1);   -- ASCII only
SELECT rebuild_strings(5, 7);   -- All types (ASCII + UTF-16 + UTF-32)

-- Typical workflow: rebuild then query
SELECT rebuild_strings();
SELECT * FROM strings WHERE content LIKE '%error%';
```

**IMPORTANT - Agent Behavior for String Queries:**
When the user asks about strings (e.g., "show me the strings", "what strings are in this binary"):
1. First run `SELECT rebuild_strings()` to ensure strings are detected
2. Then query the `strings` table

The `rebuild_strings()` function configures IDA's string detection with sensible defaults (ASCII + UTF-16, minimum length 5) and rebuilds the string list. This ensures the user gets results even if the database had no prior string analysis.

---

## Entity Search Table (jump_entities)

A table-valued function for unified entity search with full SQL composability.

### Usage

```sql
-- Basic search (function-call syntax)
SELECT * FROM jump_entities('sub', 'prefix') LIMIT 10;

-- Filter by kind
SELECT * FROM jump_entities('EH', 'prefix') WHERE kind = 'struct';

-- JOIN with other tables
SELECT j.name, f.size
FROM jump_entities('sub', 'prefix') j
LEFT JOIN funcs f ON j.address = f.address
WHERE j.kind = 'function';
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `pattern` | Search pattern (required) |
| `mode` | `'prefix'` or `'contains'` |

### Columns

| Column | Type | Description |
|--------|------|-------------|
| `name` | TEXT | Entity name |
| `kind` | TEXT | function/label/segment/struct/union/enum/member/enum_member |
| `address` | INT | Address (for functions, labels, segments) |
| `ordinal` | INT | Type ordinal (for types, members) |
| `parent_name` | TEXT | Parent type (for members) |
| `full_name` | TEXT | Fully qualified name |

**Use Case:** Implement "Jump to Anything" with virtual scrolling - lazy cursor respects LIMIT.

---

## Performance Rules

### CRITICAL: Constraint Pushdown

Some tables have **optimized filters** that use efficient IDA SDK APIs:

| Table | Optimized Filter | Without Filter |
|-------|------------------|----------------|
| `instructions` | `func_addr = X` | O(all instructions) - SLOW |
| `blocks` | `func_ea = X` | O(all blocks) |
| `xrefs` | `to_ea = X` or `from_ea = X` | O(all xrefs) |
| `pseudocode` | `func_addr = X` | **Decompiles ALL functions** |
| `ctree*` | `func_addr = X` | **Decompiles ALL functions** |

**Always filter decompiler tables by `func_addr`!**

### Use Integer Comparisons

```sql
-- SLOW: String comparison
WHERE mnemonic = 'call'

-- FAST: Integer comparison
WHERE itype IN (16, 18)  -- x86 call opcodes
```

### O(1) Random Access

```sql
-- SLOW: O(n) - sorts all rows
SELECT address FROM funcs ORDER BY RANDOM() LIMIT 1;

-- FAST: O(1) - direct index access
SELECT func_at_index(ABS(RANDOM()) % func_qty());
```

---

## Common Query Patterns

### Find Most Called Functions

```sql
SELECT f.name, COUNT(*) as callers
FROM funcs f
JOIN xrefs x ON f.address = x.to_ea
WHERE x.is_code = 1
GROUP BY f.address
ORDER BY callers DESC
LIMIT 10;
```

### Find Functions Calling a Specific API

```sql
SELECT DISTINCT func_at(from_ea) as caller
FROM xrefs
WHERE to_ea = (SELECT address FROM imports WHERE name = 'CreateFileW');
```

### String Cross-Reference Analysis

```sql
SELECT s.content, func_at(x.from_ea) as used_by
FROM strings s
JOIN xrefs x ON s.address = x.to_ea
WHERE s.content LIKE '%password%';
```

### Function Complexity (by Block Count)

```sql
SELECT func_at(func_ea) as name, COUNT(*) as block_count
FROM blocks
GROUP BY func_ea
ORDER BY block_count DESC
LIMIT 10;
```

### Find Leaf Functions (No Outgoing Calls)

```sql
SELECT f.name, f.size
FROM funcs f
LEFT JOIN disasm_calls c ON c.func_addr = f.address
GROUP BY f.address
HAVING COUNT(c.ea) = 0
ORDER BY f.size DESC;
```

### Functions with Deep Call Chains

```sql
SELECT f.name, MAX(cc.depth) as max_depth
FROM disasm_v_call_chains cc
JOIN funcs f ON f.address = cc.root_func
GROUP BY cc.root_func
ORDER BY max_depth DESC
LIMIT 10;
```

### Security: Dangerous Function Calls with Stack Buffers

```sql
SELECT f.name, c.callee_name, printf('0x%X', c.ea) as address
FROM funcs f
JOIN ctree_v_calls c ON c.func_addr = f.address
JOIN ctree_call_args a ON a.func_addr = c.func_addr AND a.call_item_id = c.item_id
WHERE c.callee_name IN ('strcpy', 'strcat', 'sprintf', 'gets', 'memcpy')
  AND a.arg_idx = 0 AND a.arg_var_is_stk = 1
ORDER BY f.name;
```

### Find Zero Comparisons (Potential Error Checks)

```sql
SELECT func_at(func_addr) as func, printf('0x%X', ea) as addr
FROM ctree_v_comparisons
WHERE op_name = 'cot_eq' AND rhs_op = 'cot_num' AND rhs_num = 0;
```

### Calls Inside Loops (Performance Hotspots)

```sql
SELECT f.name, l.callee_name, l.loop_op
FROM ctree_v_calls_in_loops l
JOIN funcs f ON f.address = l.func_addr
ORDER BY f.name;
```

### malloc with Constant Size

```sql
SELECT func_at(c.func_addr) as func, a.arg_num_value as size
FROM ctree_v_calls c
JOIN ctree_call_args a ON a.func_addr = c.func_addr AND a.call_item_id = c.item_id
WHERE c.callee_name LIKE '%malloc%'
  AND a.arg_idx = 0 AND a.arg_op = 'cot_num'
ORDER BY a.arg_num_value DESC;
```

### Largest Structures

```sql
SELECT name, size, alignment
FROM types
WHERE is_struct = 1 AND size > 0
ORDER BY size DESC
LIMIT 10;
```

### Instruction Profile for a Function

```sql
SELECT mnemonic, COUNT(*) as count
FROM instructions
WHERE func_addr = 0x401330
GROUP BY mnemonic
ORDER BY count DESC;
```

### Import Dependency Map

```sql
-- Which modules does each function depend on?
SELECT f.name as func_name, i.module, COUNT(*) as api_count
FROM funcs f
JOIN disasm_calls dc ON dc.func_addr = f.address
JOIN imports i ON dc.callee_addr = i.address
GROUP BY f.address, i.module
ORDER BY f.name, api_count DESC;
```

### Find Indirect Calls (Potential Virtual Functions/Callbacks)

```sql
-- Functions with indirect calls (call through register/memory)
SELECT f.name, COUNT(*) as indirect_calls
FROM funcs f
JOIN disasm_calls dc ON dc.func_addr = f.address
WHERE dc.callee_addr = 0  -- Unresolved target = indirect
GROUP BY f.address
ORDER BY indirect_calls DESC
LIMIT 20;
```

### String Format Audit (printf-style Vulnerabilities)

```sql
-- Format string usage with variable formats (potential vuln)
SELECT f.name, c.callee_name, printf('0x%X', c.ea) as addr
FROM funcs f
JOIN ctree_v_calls c ON c.func_addr = f.address
JOIN ctree_call_args a ON a.func_addr = c.func_addr AND a.call_item_id = c.item_id
WHERE c.callee_name LIKE '%printf%'
  AND a.arg_idx = 0  -- First arg is format string
  AND a.arg_op = 'cot_var';  -- Variable, not constant string
```

### Memory Allocation Patterns

```sql
-- Find functions that allocate but may not free
WITH allocators AS (
    SELECT func_addr, COUNT(*) as alloc_count
    FROM disasm_calls
    WHERE callee_name LIKE '%alloc%' OR callee_name LIKE '%malloc%'
    GROUP BY func_addr
),
freers AS (
    SELECT func_addr, COUNT(*) as free_count
    FROM disasm_calls
    WHERE callee_name LIKE '%free%'
    GROUP BY func_addr
)
SELECT f.name,
       COALESCE(a.alloc_count, 0) as allocations,
       COALESCE(r.free_count, 0) as frees
FROM funcs f
LEFT JOIN allocators a ON f.address = a.func_addr
LEFT JOIN freers r ON f.address = r.func_addr
WHERE a.alloc_count > 0 AND COALESCE(r.free_count, 0) = 0
ORDER BY allocations DESC;
```

### Control Flow Anomalies

```sql
-- Functions with many basic blocks but few instructions (possibly obfuscated)
SELECT
    f.name,
    f.size,
    COUNT(DISTINCT b.start_ea) as blocks,
    f.size / COUNT(DISTINCT b.start_ea) as avg_block_size
FROM funcs f
JOIN blocks b ON b.func_ea = f.address
WHERE f.size > 100
GROUP BY f.address
HAVING COUNT(DISTINCT b.start_ea) > 10
   AND f.size / COUNT(DISTINCT b.start_ea) < 10  -- Very small blocks
ORDER BY blocks DESC;
```

### Return Value Analysis

```sql
-- Functions with multiple return statements (complex control flow)
SELECT f.name, COUNT(*) as return_count
FROM funcs f
JOIN ctree ct ON ct.func_addr = f.address
WHERE ct.op_name = 'cit_return'
GROUP BY f.address
HAVING COUNT(*) > 3
ORDER BY return_count DESC;

-- Functions that return 0 (common success pattern)
SELECT DISTINCT func_at(func_addr) as name FROM ctree_v_returns
WHERE return_op = 'cot_num' AND return_num = 0;

-- Functions that return -1 (error sentinel)
SELECT DISTINCT func_at(func_addr) as name FROM ctree_v_returns
WHERE return_op = 'cot_num' AND return_num = -1;

-- Functions that return a specific constant
SELECT DISTINCT func_at(func_addr) as name FROM ctree_v_returns
WHERE return_op = 'cot_num' AND return_num = 1;
```

### Function Signature Queries

```sql
-- Functions returning integers (includes BOOL, DWORD via resolved)
SELECT type_name FROM types_func_args
WHERE arg_index = -1 AND is_integral_resolved = 1;

-- Functions taking exactly 4 pointer arguments
SELECT type_name, COUNT(*) as ptr_args FROM types_func_args
WHERE arg_index >= 0 AND is_ptr = 1
GROUP BY type_ordinal HAVING ptr_args = 4;

-- Functions with string parameters (char*/wchar_t*)
SELECT DISTINCT type_name FROM types_func_args
WHERE arg_index >= 0 AND is_ptr = 1
  AND base_type_resolved IN ('char', 'wchar_t', 'CHAR', 'WCHAR');

-- Typedefs hiding pointers (HANDLE, HMODULE, etc.)
SELECT DISTINCT type_name, arg_type FROM types_func_args
WHERE is_ptr = 0 AND is_ptr_resolved = 1;

-- Functions returning void pointers
SELECT type_name FROM types_func_args
WHERE arg_index = -1 AND is_ptr_resolved = 1 AND is_void_resolved = 1;
```

### Loops with System Calls (Performance/Security Hotspots)

```sql
-- System API calls inside loops
SELECT
    f.name as function,
    l.callee_name as api_called,
    l.loop_op as loop_type
FROM ctree_v_calls_in_loops l
JOIN funcs f ON f.address = l.func_addr
JOIN imports i ON l.callee_name = i.name
ORDER BY f.name;
```

### Type Usage Statistics

```sql
-- Most referenced types (by struct member usage in decompiled code)
SELECT tm.type_name, COUNT(DISTINCT ct.func_addr) as func_count
FROM types_members tm
JOIN ctree ct ON ct.var_name = tm.member_name
GROUP BY tm.type_name
ORDER BY func_count DESC
LIMIT 20;
```

### Data Section Analysis

```sql
-- Find functions referencing data sections
SELECT
    f.name,
    s.name as segment,
    COUNT(*) as data_refs
FROM funcs f
JOIN xrefs x ON x.from_ea BETWEEN f.address AND f.end_ea
JOIN segments s ON x.to_ea BETWEEN s.start_ea AND s.end_ea
WHERE s.class = 'DATA' AND x.is_code = 0
GROUP BY f.address, s.name
ORDER BY data_refs DESC
LIMIT 20;
```

### Exception Handler Detection

```sql
-- Functions with multiple chunks (often due to exception handlers)
SELECT
    f.name,
    COUNT(*) as chunk_count,
    SUM(fc.size) as total_size
FROM funcs f
JOIN fchunks fc ON fc.func_addr = f.address
GROUP BY f.address
HAVING COUNT(*) > 1
ORDER BY chunk_count DESC;
```

---

## Advanced SQL Patterns

### Common Table Expressions (CTEs)

CTEs make complex queries readable and allow recursive traversal.

#### Basic CTE for Filtering

```sql
-- Find functions that both call malloc AND check return value
WITH malloc_callers AS (
    SELECT DISTINCT func_addr
    FROM disasm_calls
    WHERE callee_name LIKE '%malloc%'
),
null_checkers AS (
    SELECT DISTINCT func_addr
    FROM ctree_v_comparisons
    WHERE rhs_num = 0 AND op_name = 'cot_eq'
)
SELECT f.name
FROM funcs f
JOIN malloc_callers m ON f.address = m.func_addr
JOIN null_checkers n ON f.address = n.func_addr;
```

#### CTE with Aggregation

```sql
-- Functions ranked by complexity (calls * blocks)
WITH call_counts AS (
    SELECT func_addr, COUNT(*) as call_cnt
    FROM disasm_calls
    GROUP BY func_addr
),
block_counts AS (
    SELECT func_ea as func_addr, COUNT(*) as block_cnt
    FROM blocks
    GROUP BY func_ea
)
SELECT f.name,
       COALESCE(c.call_cnt, 0) as calls,
       COALESCE(b.block_cnt, 0) as blocks,
       COALESCE(c.call_cnt, 0) * COALESCE(b.block_cnt, 0) as complexity
FROM funcs f
LEFT JOIN call_counts c ON f.address = c.func_addr
LEFT JOIN block_counts b ON f.address = b.func_addr
ORDER BY complexity DESC
LIMIT 10;
```

### Recursive CTEs (Call Graph Traversal)

```sql
-- Find all functions reachable from main (up to depth 5)
WITH RECURSIVE call_graph AS (
    -- Base case: start from main
    SELECT address as func_addr, name, 0 as depth
    FROM funcs WHERE name = 'main'

    UNION ALL

    -- Recursive case: follow calls
    SELECT f.address, f.name, cg.depth + 1
    FROM call_graph cg
    JOIN disasm_calls dc ON dc.func_addr = cg.func_addr
    JOIN funcs f ON f.address = dc.callee_addr
    WHERE cg.depth < 5
      AND dc.callee_addr != 0  -- Skip indirect calls
)
SELECT DISTINCT func_addr, name, MIN(depth) as min_depth
FROM call_graph
GROUP BY func_addr
ORDER BY min_depth, name;
```

```sql
-- Reverse call graph: who calls this function (transitive)
WITH RECURSIVE callers AS (
    -- Base: direct callers of target
    SELECT DISTINCT dc.func_addr, 1 as depth
    FROM disasm_calls dc
    WHERE dc.callee_addr = 0x401000

    UNION ALL

    -- Recursive: who calls the callers
    SELECT DISTINCT dc.func_addr, c.depth + 1
    FROM callers c
    JOIN disasm_calls dc ON dc.callee_addr = c.func_addr
    WHERE c.depth < 5
)
SELECT func_at(func_addr) as caller, MIN(depth) as distance
FROM callers
GROUP BY func_addr
ORDER BY distance, caller;
```

### Window Functions

```sql
-- Rank functions by size within each segment
SELECT
    segment_at(f.address) as seg,
    f.name,
    f.size,
    ROW_NUMBER() OVER (PARTITION BY segment_at(f.address) ORDER BY f.size DESC) as rank
FROM funcs f
WHERE f.size > 0;
```

```sql
-- Running total of function sizes
SELECT
    name,
    size,
    SUM(size) OVER (ORDER BY address) as cumulative_size
FROM funcs
ORDER BY address;
```

```sql
-- Find consecutive functions with similar sizes (possible duplicates)
SELECT
    name,
    size,
    LAG(name) OVER (ORDER BY size) as prev_name,
    LAG(size) OVER (ORDER BY size) as prev_size
FROM funcs
WHERE size > 100;
```

### Complex JOINs

#### Multi-Table Join (Functions with Context)

```sql
-- Function overview with all relationships
SELECT
    f.name,
    f.size,
    segment_at(f.address) as segment,
    (SELECT COUNT(*) FROM blocks WHERE func_ea = f.address) as block_count,
    (SELECT COUNT(*) FROM disasm_calls WHERE func_addr = f.address) as outgoing_calls,
    (SELECT COUNT(*) FROM xrefs WHERE to_ea = f.address AND is_code = 1) as incoming_calls,
    (SELECT COUNT(*) FROM ctree_lvars WHERE func_addr = f.address) as local_vars
FROM funcs f
ORDER BY f.size DESC
LIMIT 20;
```

#### Self-Join (Compare Functions)

```sql
-- Find functions with identical sizes (potential clones)
SELECT
    f1.name as func1,
    f2.name as func2,
    f1.size
FROM funcs f1
JOIN funcs f2 ON f1.size = f2.size AND f1.address < f2.address
WHERE f1.size > 50  -- Ignore tiny functions
ORDER BY f1.size DESC;
```

### Subqueries

```sql
-- Functions that call more APIs than average
SELECT f.name, call_count
FROM (
    SELECT func_addr, COUNT(*) as call_count
    FROM disasm_calls dc
    JOIN imports i ON dc.callee_addr = i.address
    GROUP BY func_addr
) sub
JOIN funcs f ON f.address = sub.func_addr
WHERE call_count > (
    SELECT AVG(cnt) FROM (
        SELECT COUNT(*) as cnt
        FROM disasm_calls dc
        JOIN imports i ON dc.callee_addr = i.address
        GROUP BY func_addr
    )
)
ORDER BY call_count DESC;
```

### CASE Expressions

```sql
-- Categorize functions by complexity
SELECT
    name,
    size,
    CASE
        WHEN size < 50 THEN 'tiny'
        WHEN size < 200 THEN 'small'
        WHEN size < 1000 THEN 'medium'
        WHEN size < 5000 THEN 'large'
        ELSE 'huge'
    END as category
FROM funcs
ORDER BY size DESC;
```

```sql
-- Classify strings by content
SELECT
    content,
    CASE
        WHEN content LIKE '%error%' OR content LIKE '%fail%' THEN 'error'
        WHEN content LIKE '%password%' OR content LIKE '%key%' THEN 'sensitive'
        WHEN content LIKE '%http%' OR content LIKE '%://% ' THEN 'url'
        WHEN content LIKE '%.dll%' OR content LIKE '%.exe%' THEN 'file'
        ELSE 'other'
    END as category
FROM strings
WHERE length > 5;
```

### Batch Analysis with UNION ALL

```sql
-- Comprehensive security audit in one query
SELECT 'dangerous_func' as check_type, func_at(func_addr) as location, callee_name as detail
FROM disasm_calls
WHERE callee_name IN ('strcpy', 'strcat', 'sprintf', 'gets', 'scanf')

UNION ALL

SELECT 'crypto_usage', func_at(func_addr), callee_name
FROM disasm_calls
WHERE callee_name LIKE '%Crypt%' OR callee_name LIKE '%AES%' OR callee_name LIKE '%RSA%'

UNION ALL

SELECT 'network_call', func_at(func_addr), callee_name
FROM disasm_calls
WHERE callee_name IN ('socket', 'connect', 'send', 'recv', 'WSAStartup')

UNION ALL

SELECT 'registry_access', func_at(func_addr), callee_name
FROM disasm_calls
WHERE callee_name LIKE 'Reg%'

ORDER BY check_type, location;
```

### Efficient Pagination

```sql
-- Page through large result sets efficiently
SELECT * FROM (
    SELECT
        f.name,
        f.size,
        ROW_NUMBER() OVER (ORDER BY f.size DESC) as row_num
    FROM funcs f
)
WHERE row_num BETWEEN 101 AND 200;  -- Page 2 (100 per page)
```

### EXISTS for Efficient Filtering

```sql
-- Functions that have at least one string reference (more efficient than JOIN + DISTINCT)
SELECT f.name
FROM funcs f
WHERE EXISTS (
    SELECT 1 FROM xrefs x
    JOIN strings s ON x.to_ea = s.address
    WHERE x.from_ea BETWEEN f.address AND f.end_ea
);
```

```sql
-- Functions without any calls (leaf functions, EXISTS version)
SELECT f.name, f.size
FROM funcs f
WHERE NOT EXISTS (
    SELECT 1 FROM disasm_calls dc
    WHERE dc.func_addr = f.address
)
ORDER BY f.size DESC;
```

---

## Hex Address Formatting

IDA uses integer addresses. For display, use `printf()`:

```sql
-- 32-bit format
SELECT printf('0x%08X', address) as addr FROM funcs;

-- 64-bit format
SELECT printf('0x%016llX', address) as addr FROM funcs;

-- Auto-width
SELECT printf('0x%X', address) as addr FROM funcs;
```

---

## Common x86 Instruction Types

When filtering by `itype` (faster than string comparison):

| itype | Mnemonic | Description |
|-------|----------|-------------|
| 16 | call (near) | Direct call |
| 18 | call (indirect) | Indirect call |
| 122 | mov | Move data |
| 143 | push | Push to stack |
| 134 | pop | Pop from stack |
| 159 | retn | Return |
| 85 | jz | Jump if zero |
| 79 | jnz | Jump if not zero |
| 27 | cmp | Compare |
| 103 | nop | No operation |

---

## ctree Operation Names

Common Hex-Rays AST node types:

**Expressions (cot_*):**
- `cot_call` - Function call
- `cot_var` - Local variable
- `cot_obj` - Global object/function
- `cot_num` - Numeric constant
- `cot_str` - String literal
- `cot_ptr` - Pointer dereference
- `cot_ref` - Address-of
- `cot_asg` - Assignment
- `cot_add`, `cot_sub`, `cot_mul`, `cot_sdiv`, `cot_udiv` - Arithmetic
- `cot_eq`, `cot_ne`, `cot_lt`, `cot_gt` - Comparisons
- `cot_land`, `cot_lor`, `cot_lnot` - Logical
- `cot_band`, `cot_bor`, `cot_xor` - Bitwise

**Statements (cit_*):**
- `cit_if` - If statement
- `cit_for` - For loop
- `cit_while` - While loop
- `cit_do` - Do-while loop
- `cit_return` - Return statement
- `cit_block` - Code block

---

## Error Handling

- **No Hex-Rays license:** Decompiler tables (`pseudocode`, `ctree*`, `ctree_lvars`) will be empty or unavailable
- **No constraint on decompiler tables:** Query will be extremely slow (decompiles all functions)
- **Invalid address:** Functions like `func_at(addr)` return NULL
- **Missing function:** JOINs may return fewer rows than expected

---

## Quick Start Examples

### "What does this binary do?"

```sql
-- Entry points
SELECT * FROM entries;

-- Imported APIs (hints at functionality)
SELECT module, name FROM imports ORDER BY module, name;

-- Interesting strings
SELECT content FROM strings WHERE length > 10 ORDER BY length DESC LIMIT 20;
```

### "Find security-relevant code"

```sql
-- Dangerous string functions
SELECT DISTINCT func_at(func_addr) FROM disasm_calls
WHERE callee_name IN ('strcpy', 'strcat', 'sprintf', 'gets');

-- Crypto-related
SELECT * FROM imports WHERE name LIKE '%Crypt%' OR name LIKE '%Hash%';

-- Network-related
SELECT * FROM imports WHERE name LIKE '%socket%' OR name LIKE '%connect%' OR name LIKE '%send%';
```

### "Understand a specific function"

```sql
-- Basic info
SELECT * FROM funcs WHERE address = 0x401000;

-- Pseudocode (if Hex-Rays available)
SELECT line FROM pseudocode WHERE func_addr = 0x401000 ORDER BY line_num;

-- Local variables
SELECT name, type, size FROM ctree_lvars WHERE func_addr = 0x401000;

-- What it calls
SELECT callee_name FROM disasm_calls WHERE func_addr = 0x401000;

-- What calls it
SELECT func_at(from_ea) FROM xrefs WHERE to_ea = 0x401000 AND is_code = 1;
```

### "Find all uses of a string"

```sql
SELECT s.content, func_at(x.from_ea) as function, printf('0x%X', x.from_ea) as location
FROM strings s
JOIN xrefs x ON s.address = x.to_ea
WHERE s.content LIKE '%config%';
```

---

## Summary: When to Use What

| Goal | Table/Function |
|------|----------------|
| List all functions | `funcs` |
| Find who calls what | `xrefs` with `is_code = 1` |
| Find data references | `xrefs` with `is_code = 0` |
| Analyze imports | `imports` |
| Find strings | `strings` |
| Configure string types | `rebuild_strings(types, minlen)` |
| Instruction analysis | `instructions WHERE func_addr = X` |
| Decompiled code | `pseudocode WHERE func_addr = X` |
| AST pattern matching | `ctree WHERE func_addr = X` |
| Call patterns | `ctree_v_calls`, `disasm_calls` |
| Control flow | `ctree_v_loops`, `ctree_v_ifs` |
| Return value analysis | `ctree_v_returns` |
| Variable analysis | `ctree_lvars WHERE func_addr = X` |
| Type information | `types`, `types_members` |
| Function signatures | `types_func_args` (with type classification) |
| Functions by return type | `types_func_args WHERE arg_index = -1` |
| Modify database | `*_live` tables |
| Jump to Anything | `jump_entities('pattern', 'mode')` |
| Entity search (JSON) | `jump_search('pattern', 'mode', limit, offset)` |

**Remember:** Always use `func_addr = X` constraints on instruction and decompiler tables for acceptable performance.
