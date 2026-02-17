// Auto-generated from idasql_agent.md
// Generated: 2026-02-12T18:29:38.360124
// DO NOT EDIT - regenerate with: python scripts/embed_prompt.py

#pragma once

namespace idasql {

inline constexpr const char* SYSTEM_PROMPT =
    R"PROMPT(# IDASQL Agent Guide

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

## Command-Line Interface

IDASQL provides SQL access to IDA databases via command line or as a server.

### Invocation Modes

**1. Single Query (Local)**
```bash
idasql -s database.i64 -q "SELECT * FROM funcs LIMIT 10"
idasql -s database.i64 -c "SELECT COUNT(*) FROM funcs"  # -c is alias for -q
```

**2. SQL File Execution**
```bash
idasql -s database.i64 -f analysis.sql
```

**3. Interactive REPL**
```bash
idasql -s database.i64 -i
```

**4. Remote Mode** (connect to running server)
```bash
idasql --remote localhost:8080 -q "SELECT * FROM funcs"
idasql --remote localhost:8080 -i  # Remote interactive
```

**5. HTTP Server Mode**
```bash
idasql -s database.i64 --http 8080
# Then query via: curl -X POST http://localhost:8080/query -d "SELECT * FROM funcs"
```

**6. Export Mode**
```bash
idasql -s database.i64 --export dump.sql
idasql -s database.i64 --export dump.sql --export-tables=funcs,segments
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-s <file>` | IDA database file (.idb/.i64) |
| `--remote <host:port>` | Connect to IDASQL server |
| `--token <token>` | Auth token for remote/server mode |
| `-q <sql>` | Execute single SQL query |
| `-c <sql>` | Alias for -q (Python-style) |
| `-f <file>` | Execute SQL from file |
| `-i` | Interactive REPL mode |
| `-w, --write` | Save database changes on exit |
| `--export <file>` | Export tables to SQL file |
| `--export-tables=X` | Tables to export: `*` (all) or `table1,table2,...` |
| `--http [port]` | Start HTTP REST server (default: 8080) |
| `--bind <addr>` | Bind address for server (default: 127.0.0.1) |
| `-h, --help` | Show help |

### REPL Commands

| Command | Description |
|---------|-------------|
| `.tables` | List all virtual tables |
| `.schema [table]` | Show table schema |
| `.info` | Show database metadata |
| `.clear` | Clear session |
| `.quit` / `.exit` | Exit REPL |
| `.help` | Show available commands |
| `.http start` | Start HTTP server on random port |
| `.http stop` | Stop HTTP server |
| `.http status` | Show HTTP server status |
| `.agent` | Start AI agent mode |

### Performance Strategy

**Single queries:** Use `-q` directly.
```bash
idasql -s database.i64 -q "SELECT COUNT(*) FROM funcs"
```

**Multiple queries / exploration:** Start a server once, then query as a client.

Opening an IDA database has startup overhead (idalib initialization, auto-analysis). If you plan to run many queries—exploring the database, experimenting with different queries, or iterating on analysis—avoid re-opening the database each time.

**Recommended workflow for iterative analysis:**
```bash
# Terminal 1: Start server (opens database once)
idasql -s database.i64 --http 8080

# Terminal 2: Query repeatedly via remote client (instant responses)
idasql --remote localhost:8080 -q "SELECT * FROM funcs LIMIT 5"
idasql --remote localhost:8080 -q "SELECT * FROM strings WHERE content LIKE '%error%'"
idasql --remote localhost:8080 -q "SELECT name, size FROM funcs ORDER BY size DESC"
# ... as many queries as needed, no startup cost
```

Or use interactive mode on the remote connection:
```bash
idasql --remote localhost:8080 -i
idasql> SELECT COUNT(*) FROM funcs;
idasql> SELECT * FROM xrefs WHERE to_ea = 0x401000;
idasql> .quit
```

This approach is significantly faster for iterative analysis since the database remains open and queries go directly through the already-initialized session.

---

## Tables Reference

### Debugger Tables (Full CRUD)

#### breakpoints
Debugger breakpoints. Supports full CRUD (SELECT, INSERT, UPDATE, DELETE). Breakpoints persist in the IDB even without an active debugger session.

| Column | Type | RW | Description |
|--------|------|----|-------------|
| `address` | INT | R | Breakpoint address |
| `enabled` | INT | RW | 1=enabled, 0=disabled |
| `type` | INT | RW | Breakpoint type (0=software, 1=hw_write, 2=hw_read, 3=hw_rdwr, 4=hw_exec) |
| `type_name` | TEXT | R | Type name (software, hardware_write, etc.) |
| `size` | INT | RW | Breakpoint size (for hardware breakpoints) |
| `flags` | INT | RW | Breakpoint flags |
| `pass_count` | INT | RW | Pass count before trigger |
| `condition` | TEXT | RW | Condition expression |
| `loc_type` | INT | R | Location type code |
| `loc_type_name` | TEXT | R | Location type (absolute, relative, symbolic, source) |
| `module` | TEXT | R | Module path (relative breakpoints) |
| `symbol` | TEXT | R | Symbol name (symbolic breakpoints) |
| `offset` | INT | R | Offset (relative/symbolic) |
| `source_file` | TEXT | R | Source file (source breakpoints) |
| `source_line` | INT | R | Source line number |
| `is_hardware` | INT | R | 1=hardware breakpoint |
| `is_active` | INT | R | 1=currently active |
| `group` | TEXT | RW | Breakpoint group name |
| `bptid` | INT | R | Breakpoint ID |

```sql
-- List all breakpoints
SELECT printf('0x%08X', address) as addr, type_name, enabled, condition
FROM breakpoints;

-- Add software breakpoint
INSERT INTO breakpoints (address) VALUES (0x401000);

-- Add hardware write watchpoint
INSERT INTO breakpoints (address, type, size) VALUES (0x402000, 1, 4);

-- Add conditional breakpoint
INSERT INTO breakpoints (address, condition) VALUES (0x401000, 'eax == 0');

-- Disable a breakpoint
UPDATE breakpoints SET enabled = 0 WHERE address = 0x401000;

-- Delete a breakpoint
DELETE FROM breakpoints WHERE address = 0x401000;

-- Find which functions have breakpoints
SELECT b.address, f.name, b.type_name, b.enabled
FROM breakpoints b
JOIN funcs f ON b.address >= f.address AND b.address < f.end_ea;
```

### Entity Tables

#### funcs
All detected functions in the binary with prototype information.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Function start address |
| `name` | TEXT | Function name |
| `size` | INT | Function size in bytes |
| `end_ea` | INT | Function end address |
| `flags` | INT | Function flags |

**Prototype columns** (populated when type info available):

| Column | Type | Description |
|--------|------|-------------|
| `return_type` | TEXT | Return type string (e.g., "int", "void *") |
| `return_is_ptr` | INT | 1 if return type is pointer |
| `return_is_int` | INT | 1 if return type is exactly int |
| `return_is_integral` | INT | 1 if return type is int-like (int, long, DWORD, BOOL) |
| `return_is_void` | INT | 1 if return type is void |
| `arg_count` | INT | Number of function arguments |
| `calling_conv` | TEXT | Calling convention (cdecl, stdcall, fastcall, etc.) |

```sql
-- 10 largest functions
SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10;

-- Functions starting with "sub_" (auto-named, not analyzed)
SELECT name, printf('0x%X', address) as addr FROM funcs WHERE name LIKE 'sub_%';

-- Functions returning integers with 3+ arguments
SELECT name, return_type, arg_count FROM funcs
WHERE return_is_integral = 1 AND arg_count >= 3;

-- Void functions (side effects, callbacks)
SELECT name, arg_count FROM funcs WHERE return_is_void = 1;

-- Pointer-returning functions (factories, allocators)
SELECT name, return_type FROM funcs WHERE return_is_ptr = 1;

-- Simple getter functions (no args, returns value)
SELECT name, return_type FROM funcs
WHERE arg_count = 0 AND return_is_void = 0;

-- Functions by calling convention
SELECT calling_conv, COUNT(*) as count FROM funcs
WHERE calling_conv IS NOT NULL AND calling_conv != ''
GROUP BY calling_conv ORDER BY count DESC;
```

#### segments
Memory segments. Supports UPDATE (`name`, `class`, `perm`) and DELETE.

| Column | Type | RW | Description |
|--------|------|----|-------------|
| `start_ea` | INT | R | Segment start |
| `end_ea` | INT | R | Segment end |
| `name` | TEXT | RW | Segment name (.text, .data, etc.) |
| `class` | TEXT | RW | Segment class (CODE, DATA) |
| `perm` | INT | RW | Permissions (R=4, W=2, X=1) |

```sql
-- Find executable segments
SELECT name, printf('0x%X', start_ea) as start FROM segments WHERE perm & 1 = 1;

-- Rename a segment
UPDATE segments SET name = '.mytext' WHERE start_ea = 0x401000;

-- Change segment permissions to read+exec
UPDATE segments SET perm = 5 WHERE name = '.text';

-- Delete a segment
DELETE FROM segments WHERE name = '.rdata';
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

**Important:** For new analysis (exe/dll), strings are auto-built. For existing databases (i64/idb), strings are already saved. If you see 0 strings unexpectedly, run `SELECT rebuild_strings()` once to rebuild the list. See String List Functions section below.

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

### Convenience Views

Pre-built views for common xref analysis patterns. These simplify caller/callee queries.

#### callers
Who calls each function. Use this instead of manual xref JOINs.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Target function address |
| `caller_addr` | INT | Xref source address |
| `caller_name` | TEXT | Calling function name |
| `caller_func_addr` | INT | Calling function start |

```sql
-- Who calls function at 0x401000?
SELECT caller_name, printf('0x%X', caller_addr) as from_addr)PROMPT"
    R"PROMPT(FROM callers WHERE func_addr = 0x401000;

-- Most called functions
SELECT printf('0x%X', func_addr) as addr, COUNT(*) as callers
FROM callers GROUP BY func_addr ORDER BY callers DESC LIMIT 10;
```

#### callees
What each function calls. Inverse of callers view.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Calling function address |
| `func_name` | TEXT | Calling function name |
| `callee_addr` | INT | Called address |
| `callee_name` | TEXT | Called function/symbol name |

```sql
-- What does main call?
SELECT callee_name, printf('0x%X', callee_addr) as addr
FROM callees WHERE func_name LIKE '%main%';

-- Functions making most calls
SELECT func_name, COUNT(*) as call_count
FROM callees GROUP BY func_addr ORDER BY call_count DESC LIMIT 10;
```

#### string_refs
Which functions reference which strings. Great for finding functions by string content.

| Column | Type | Description |
|--------|------|-------------|
| `string_addr` | INT | String address |
| `string_value` | TEXT | String content |
| `string_length` | INT | String length |
| `ref_addr` | INT | Reference address |
| `func_addr` | INT | Referencing function |
| `func_name` | TEXT | Function name |

```sql
-- Find functions using error strings
SELECT func_name, string_value
FROM string_refs
WHERE string_value LIKE '%error%' OR string_value LIKE '%fail%';

-- Functions with most string references
SELECT func_name, COUNT(*) as string_count
FROM string_refs WHERE func_name IS NOT NULL
GROUP BY func_addr ORDER BY string_count DESC LIMIT 10;
```

### Instruction Tables

#### instructions
Decoded instructions. Supports DELETE (converts instruction to unexplored bytes). **Always filter by `func_addr` for performance.**

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

-- Delete an instruction (convert to unexplored bytes)
DELETE FROM instructions WHERE address = 0x401000;
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

The following tables support modification:

| Table | INSERT | UPDATE columns | DELETE |
|-------|--------|---------------|--------|
| `breakpoints` | Yes | `enabled`, `type`, `size`, `flags`, `pass_count`, `condition`, `group` | Yes |
| `funcs` | Yes | `name`, `flags` | Yes |
| `names` | Yes | `name` | Yes |
| `comments` | Yes | `comment`, `rep_comment` | Yes |
| `bookmarks` | Yes | `description` | Yes |
| `segments` | — | `name`, `class`, `perm` | Yes |
| `instructions` | — | — | Yes |
| `types` | Yes | Yes | Yes |
| `types_members` | Yes | Yes | Yes |
| `types_enum_values` | Yes | Yes | Yes |
| `ctree_lvars` | — | `name`, `type` | — |

**INSERT examples:**
```sql
-- Create a function (IDA auto-detects boundaries)
INSERT INTO funcs (address) VALUES (0x401000);

-- Create a function with name and explicit end
INSERT INTO funcs (address, name, end_ea) VALUES (0x401000, 'my_func', 0x401050);

-- Set a name at an address
INSERT INTO names (address, name) VALUES (0x401000, 'main');

-- Add a comment
INSERT INTO comments (address, comment) VALUES (0x401050, 'Check return value');

-- Add a repeatable comment
INSERT INTO comments (address, rpt_comment) VALUES (0x404000, 'Global config');

-- Add a bookmark (auto-assigned slot)
INSERT INTO bookmarks (address, description) VALUES (0x401000, 'interesting');

-- Add a bookmark at specific slot
INSERT INTO bookmarks (slot, address, description) VALUES (5, 0x401000, 'slot 5');
```

**UPDATE examples:**
```sql
-- Rename a function
UPDATE funcs SET name = 'my_main' WHERE address = 0x401000;

-- Rename any named address
UPDATE names SET name = 'my_global' WHERE address = 0x404000;

-- Add/update comment
UPDATE comments SET comment = 'Check return value' WHERE address = 0x401050;

-- Add repeatable comment
UPDATE comments SET rep_comment = 'Global config' WHERE address = 0x404000;

-- Delete a name
DELETE FROM names WHERE address = 0x401000;
```

**Segments:**
```sql
-- Rename a segment
UPDATE segments SET name = '.mytext' WHERE start_ea = 0x401000;

-- Change segment class
UPDATE segments SET class = 'DATA' WHERE name = '.rdata';

-- Change permissions (R=4, W=2, X=1)
UPDATE segments SET perm = 5 WHERE name = '.text';

-- Delete a segment
DELETE FROM segments WHERE name = '.rdata';
```

**Instructions:**
```sql
-- Delete an instruction (convert to unexplored bytes)
DELETE FROM instructions WHERE address = 0x401000;
```

**Types:**
```sql
-- Create a new struct
INSERT INTO types (name, kind) VALUES ('my_struct', 'struct');

-- Create an enum
INSERT INTO types (name, kind) VALUES ('my_flags', 'enum');

-- Create a union
INSERT INTO types (name, kind) VALUES ('my_union', 'union');

-- Add a struct member with type
INSERT INTO types_members (type_ordinal, member_name, member_type) VALUES (42, 'field1', 'int');

-- Add a struct member (name only, default type)
INSERT INTO types_members (type_ordinal, member_name) VALUES (42, 'field2');

-- Add an enum value
INSERT INTO types_enum_values (type_ordinal, value_name, value) VALUES (15, 'FLAG_ACTIVE', 1);

-- Add an enum value with comment
INSERT INTO types_enum_values (type_ordinal, value_name, value, comment)
VALUES (15, 'FLAG_HIDDEN', 2, 'not visible in UI');
```

**Decompiler local variables (requires Hex-Rays):**
```sql
-- Rename a local variable
UPDATE ctree_lvars SET name = 'buffer_size'
WHERE func_addr = 0x401000 AND name = 'v1';

-- Change variable type
UPDATE ctree_lvars SET type = 'char *'
WHERE func_addr = 0x401000 AND idx = 2;
```

### Persisting Changes

Changes to the database (UPDATE, set_name, etc.) are held in memory by default.

**To persist changes:**
```sql
-- Explicit save (recommended for scripts)
SELECT save_database();  -- Returns 1 on success, 0 on failure
```

**CLI flag for auto-save:**
```bash
# Auto-save on exit (use with caution)
idasql -s db.i64 -q "UPDATE funcs SET name='main' WHERE address=0x401000" -w
```

**Best practice for batch operations:**
```sql
-- Make multiple changes
UPDATE funcs SET name = 'init_config' WHERE address = 0x401000;
UPDATE names SET name = 'g_settings' WHERE address = 0x402000;
-- Persist once at the end
SELECT save_database();
```

> Without `save_database()` or `-w`, changes are lost when the session ends.

### Decompiler Tables (Hex-Rays Required)

**CRITICAL:** Always filter by `func_addr`. Without constraint, these tables will decompile EVERY function - extremely slow!

#### pseudocode
Structured line-by-line pseudocode with writable comments. **Use `decompile(addr)` to view pseudocode; use this table only for surgical edits (comments) or structured queries.**

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `func_addr` | INT | No | Function address |
| `line_num` | INT | No | Line number |
| `line` | TEXT | No | Pseudocode text |
| `ea` | INT | No | Corresponding assembly address (from COLOR_ADDR anchor) |
| `comment` | TEXT | **Yes** | Decompiler comment at this ea |
| `comment_placement` | TEXT | **Yes** | Comment placement: `semi` (inline, default), `block1` (above line) |

**Comment placements:** `semi` (after `;`), `block1` (own line above), `block2`, `curly1`, `curly2`, `colon`, `case`, `else`, `do`

```sql
-- VIEWING: Use decompile() function, NOT the pseudocode table
SELECT decompile(0x401000);

-- COMMENTING: Use pseudocode table to add/edit/delete comments
-- Add inline comment (appears after semicolon)
UPDATE pseudocode SET comment = 'buffer overflow here'
WHERE func_addr = 0x401000 AND ea = 0x401020;

-- Add block comment (appears on own line above the statement)
UPDATE pseudocode SET comment_placement = 'block1', comment = 'vulnerable call'
WHERE func_addr = 0x401000 AND ea = 0x401020;

-- Delete a comment
UPDATE pseudocode SET comment = NULL
WHERE func_addr = 0x401000 AND ea = 0x401020;

-- STRUCTURED QUERY: Get specific lines with ea and comment info
SELECT ea, line, comment FROM pseudocode WHERE func_addr = 0x401000;
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
All local type definitions. Supports INSERT (create struct/union/enum), UPDATE, and DELETE.

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
Structure and union members. Supports INSERT (add member to struct/union), UPDATE, and DELETE.

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
Enum constant values. Supports INSERT (add value to enum), UPDATE, and DELETE.

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
| `is_ptr_resolved` | INT | 1 if resolved type is pointer |)PROMPT"
    R"PROMPT(| `is_int_resolved` | INT | 1 if resolved type is exactly int |
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

### Binary Search
| Function | Description |
|----------|-------------|
| `search_bytes(pattern)` | Find all matches, returns JSON array |
| `search_bytes(pattern, start, end)` | Search within address range |
| `search_first(pattern)` | First match address (or NULL) |
| `search_first(pattern, start, end)` | First match in range |

**Pattern syntax (IDA native):**
- `"48 8B 05"` - Exact bytes (hex, space-separated)
- `"48 ? 05"` or `"48 ?? 05"` - `?` = any byte wildcard (whole byte only)
- `"(01 02 03)"` - Alternatives (match any of these bytes)

**Note:** Unlike Binary Ninja, IDA does NOT support nibble wildcards or regex.

**Example:**
```sql
-- Find all matches for a pattern
SELECT search_bytes('48 8B ? 00');

-- Parse JSON results
SELECT json_extract(value, '$.address') as addr
FROM json_each(search_bytes('48 89 ?'))
LIMIT 10;

-- First match only
SELECT printf('0x%llX', search_first('CC CC CC'));

-- Search with alternatives
SELECT search_bytes('E8 (01 02 03 04)');
```

**Optimization Pattern: Find functions using specific instruction**

To answer "How many functions use RDTSC instruction?" efficiently:
```sql
-- Count unique functions containing RDTSC (opcode: 0F 31)
SELECT COUNT(DISTINCT func_start(json_extract(value, '$.address'))) as count
FROM json_each(search_bytes('0F 31'))
WHERE func_start(json_extract(value, '$.address')) IS NOT NULL;

-- List those functions with names
SELECT DISTINCT
    func_start(json_extract(value, '$.address')) as func_ea,
    name_at(func_start(json_extract(value, '$.address'))) as func_name
FROM json_each(search_bytes('0F 31'))
WHERE func_start(json_extract(value, '$.address')) IS NOT NULL;
```

This is **much faster** than scanning all disassembly lines because:
- `search_bytes()` uses native binary search
- `func_start()` is O(1) lookup in IDA's function index

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

**When to use `decompile()` vs `pseudocode` table:**
- **To view/show pseudocode** → always use `SELECT decompile(addr)`. Returns the full function as a single text block with `/* ea */` address prefixes. This is fast, efficient, and what you should use when the user asks to "decompile", "show the code", or "show the pseudocode".
- **To read specific lines or columns** → query the `pseudocode` table. If you already have the full output from `decompile()`, refer to it directly. Only query the table when you need structured access (e.g. filtering by ea, reading comment values).
- **To add/edit/delete comments** → `UPDATE pseudocode SET comment = '...' WHERE func_addr = X AND ea = Y`. The pseudocode table is the write interface for decompiler comments.

| Function | Description |
|----------|-------------|
| `decompile(addr)` | **PREFERRED** — Full pseudocode with `/* ea */` prefixes (requires Hex-Rays) |
| `decompile(addr, 1)` | Same but forces re-decompilation (use after writing comments or renaming variables) |
| `list_lvars(addr)` | List local variables as JSON |
| `rename_lvar(addr, old, new)` | Rename a local variable (shortcut for `UPDATE ctree_lvars`) |

```sql
-- Decompile a function (PREFERRED way to view pseudocode)
SELECT decompile(0x401000);

-- After modifying comments or variables, re-decompile to see changes
SELECT decompile(0x401000, 1);

-- Get all local variables in a function
SELECT list_lvars(0x401000);

-- Rename a variable (function shortcut)
SELECT rename_lvar(0x401000, 'v1', 'buffer_size');

-- Equivalent using UPDATE (canonical approach)
UPDATE ctree_lvars SET name = 'buffer_size' WHERE func_addr = 0x401000 AND name = 'v1';
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
| `kind` | TEXT | function/label/segment/struct/union/enum/member/enum_member |)PROMPT"
    R"PROMPT(| `address` | INT | Address (for functions, labels, segments) |
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
FROM disasm_calls)PROMPT"
    R"PROMPT(WHERE callee_name LIKE '%Crypt%' OR callee_name LIKE '%AES%' OR callee_name LIKE '%RSA%'

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

-- Decompile (if Hex-Rays available)
SELECT decompile(0x401000);

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

## Natural Language Query Examples

These examples show how to translate common user questions into SQL.

### Function Signature Queries

**"Show me functions that return integers"**
```sql
-- Using funcs table (recommended - direct and fast)
SELECT name, return_type, arg_count FROM funcs
WHERE return_is_integral = 1
LIMIT 20;

-- Or via types_func_args (for typedef-aware queries)
SELECT DISTINCT type_name FROM types_func_args
WHERE arg_index = -1 AND is_integral_resolved = 1;
```

**"Show me functions that take 4 string arguments"**
```sql
-- String = char* or wchar_t*
SELECT type_name, COUNT(*) as string_args
FROM types_func_args
WHERE arg_index >= 0
  AND is_ptr_resolved = 1
  AND base_type_resolved IN ('char', 'wchar_t', 'CHAR', 'WCHAR')
GROUP BY type_ordinal
HAVING string_args = 4;
```

**"Which functions return pointers?"**
```sql
SELECT name, return_type FROM funcs
WHERE return_is_ptr = 1
ORDER BY name LIMIT 20;
```

**"Find void functions with many arguments"**
```sql
SELECT name, arg_count FROM funcs
WHERE return_is_void = 1 AND arg_count >= 4
ORDER BY arg_count DESC;
```

**"What calling conventions are used?"**
```sql
SELECT calling_conv, COUNT(*) as count
FROM funcs
WHERE calling_conv IS NOT NULL AND calling_conv != ''
GROUP BY calling_conv ORDER BY count DESC;
```

### Return Value Analysis

**"Which functions return 0?"**
```sql
SELECT DISTINCT f.name FROM funcs f
JOIN ctree_v_returns r ON r.func_addr = f.address
WHERE r.return_num = 0;
```

**"Find functions that return -1 (error pattern)"**
```sql
SELECT DISTINCT f.name FROM funcs f
JOIN ctree_v_returns r ON r.func_addr = f.address
WHERE r.return_num = -1;
```

**"Functions that return their input argument"**
```sql
SELECT DISTINCT f.name FROM funcs f
JOIN ctree_v_returns r ON r.func_addr = f.address
WHERE r.returns_arg = 1;
```

**"Functions that return the result of another call (wrappers)"**
```sql
SELECT DISTINCT f.name FROM funcs f
JOIN ctree_v_returns r ON r.func_addr = f.address
WHERE r.returns_call_result = 1;
```

**"Functions with multiple return statements"**
```sql
SELECT f.name, COUNT(*) as return_count
FROM funcs f
JOIN ctree_v_returns r ON r.func_addr = f.address
GROUP BY f.address
HAVING return_count > 1
ORDER BY return_count DESC LIMIT 20;
```

### Type Analysis

**"Find typedefs that hide pointers (like HANDLE)"**
```sql
SELECT DISTINCT type_name, arg_type, base_type_resolved
FROM types_func_args
WHERE is_ptr = 0 AND is_ptr_resolved = 1;
```

**"Functions with struct parameters"**
```sql
SELECT type_name, arg_name, arg_type FROM types_func_args
WHERE arg_index >= 0 AND is_struct = 1;
```

### Combined Queries

**"Integer-returning functions with 3+ args that return specific values"**
```sql
SELECT f.name, f.return_type, f.arg_count, r.return_num
FROM funcs f
JOIN ctree_v_returns r ON r.func_addr = f.address
WHERE f.return_is_integral = 1
  AND f.arg_count >= 3
  AND r.return_num IS NOT NULL
ORDER BY r.return_num;
```

**"Fastcall functions that return pointers"**
```sql
SELECT name, return_type, arg_count FROM funcs
WHERE calling_conv = 'fastcall' AND return_is_ptr = 1;
```

---

## Summary: When to Use What

| Goal | Table/Function |
|------|----------------|
| List all functions | `funcs` |
| Functions by return type | `funcs WHERE return_is_integral = 1` |
| Functions by arg count | `funcs WHERE arg_count >= N` |
| Void functions | `funcs WHERE return_is_void = 1` |
| Pointer-returning functions | `funcs WHERE return_is_ptr = 1` |
| Functions by calling convention | `funcs WHERE calling_conv = 'fastcall'` |
| Find who calls what | `xrefs` with `is_code = 1` |
| Find data references | `xrefs` with `is_code = 0` |
| Analyze imports | `imports` |
| Find strings | `strings` |
| Configure string types | `rebuild_strings(types, minlen)` |
| Instruction analysis | `instructions WHERE func_addr = X` |
| View decompiled code | `decompile(addr)` |
| Edit decompiler comments | `UPDATE pseudocode SET comment = '...' WHERE func_addr = X AND ea = Y` |
| AST pattern matching | `ctree WHERE func_addr = X` |
| Call patterns | `ctree_v_calls`, `disasm_calls` |
| Control flow | `ctree_v_loops`, `ctree_v_ifs` |
| Return value analysis | `ctree_v_returns` |
| Functions returning specific values | `ctree_v_returns WHERE return_num = 0` |
| Pass-through functions | `ctree_v_returns WHERE returns_arg = 1` |
| Wrapper functions | `ctree_v_returns WHERE returns_call_result = 1` |
| Variable analysis | `ctree_lvars WHERE func_addr = X` |
| Type information | `types`, `types_members` |
| Function signatures | `types_func_args` (with type classification) |
| Functions by return type | `types_func_args WHERE arg_index = -1` |
| Typedef-aware type queries | `types_func_args` (surface vs resolved) |
| Hidden pointer types | `types_func_args WHERE is_ptr = 0 AND is_ptr_resolved = 1` |
| Manage breakpoints | `breakpoints` (full CRUD) |
| Modify segments | `segments` (UPDATE name/class/perm, DELETE) |
| Delete instructions | `instructions` (DELETE converts to unexplored bytes) |
| Create types | `types` (INSERT struct/union/enum) |
| Add struct members | `types_members` (INSERT) |
| Add enum values | `types_enum_values` (INSERT) |
| Modify database | `funcs`, `names`, `comments`, `bookmarks` (INSERT/UPDATE/DELETE) |
| Jump to Anything | `jump_entities('pattern', 'mode')` |
| Entity search (JSON) | `jump_search('pattern', 'mode', limit, offset)` |

**Remember:** Always use `func_addr = X` constraints on instruction and decompiler tables for acceptable performance.

---

## Server Modes

IDASQL supports two server protocols for remote queries: **HTTP REST** (recommended) and raw TCP.

---

### HTTP REST Server (Recommended)

Standard REST API that works with curl, any HTTP client, or LLM tools.

**Starting the server:**
```bash
# Default port 8081
idasql -s database.i64 --http

# Custom port and bind address
idasql -s database.i64 --http 9000 --bind 0.0.0.0

# With authentication
idasql -s database.i64 --http 8081 --token mysecret
```

**HTTP Endpoints:**

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | No | Welcome message |
| `/help` | GET | No | API documentation (for LLM discovery) |
| `/query` | POST | Yes* | Execute SQL (body = raw SQL) |
| `/status` | GET | Yes* | Health check |
| `/shutdown` | POST | Yes* | Stop server |

*Auth required only if `--token` was specified.

**Example with curl:**
```bash
# Get API documentation
curl http://localhost:8081/help

# Execute SQL query
curl -X POST http://localhost:8081/query -d "SELECT name, size FROM funcs LIMIT 5"

# With authentication
curl -X POST http://localhost:8081/query \
     -H "Authorization: Bearer mysecret" \
     -d "SELECT * FROM funcs"

# Check status
curl http://localhost:8081/status
```

**Response Format (JSON):**
```json
{"success": true, "columns": ["name", "size"], "rows": [["main", "500"]], "row_count": 1}
```

```json
{"success": false, "error": "no such table: bad_table"}
```

---

### Raw TCP Server (Legacy)

Binary protocol with length-prefixed JSON. Use only when HTTP is not available.

**Starting the server:**
```bash
idasql -s database.i64 --server 13337
idasql -s database.i64 --server 13337 --token mysecret
```

**Connecting as client:**
```bash
idasql --remote localhost:13337 -q "SELECT name FROM funcs LIMIT 5"
idasql --remote localhost:13337 -i
```
)PROMPT";

} // namespace idasql
