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

Address-taking SQL functions accept integer EAs (`0x401000`), numeric
strings (`'0x401000'`), and global symbol names (`'DriverEntry'`); symbol
names resolve via `get_name_ea`. Table predicates compare address columns
to integer EAs (e.g. `WHERE address = 0x401000`). Unresolved symbols
return `Could not resolve name to address: <name>`.

```sql
SELECT decompile('DriverEntry');
UPDATE applied_types
SET decl = 'NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING);'
WHERE address = 'DriverEntry';
SELECT (SELECT comment FROM comments WHERE address = 0x401000 LIMIT 1);
```

### Functions
IDA groups code into **functions** with:
- `address` / `start_ea` - Where the function begins
- `end_ea` - Where it ends
- `name` - Assigned or auto-generated name (e.g., `main`, `sub_401000`)
- `size` - Total bytes in the function

There will be addresses and disassembly listing not belonging to a function. IDASQL can still get the bytes, disassembly listing ranges, etc.
For single-EA disassembly (code or data), prefer `disasm_at(ea[, context])` over function-scoped queries.

### Cross-References (xrefs)
Binary analysis is about understanding **relationships**:
- **Code xrefs** - Function calls, jumps between code
- **Data xrefs** - Code reading/writing data locations, or data referring to other data (pointers)
- `from_ea` → `to_ea` represents "address X references address Y"
Use table: `xrefs(from_ea, to_ea, type, is_code)`.

### Segments

Use table: `segments(start_ea, end_ea, name, class, perm)`.

Memory is divided into **segments** with different purposes. For example, a typical PE file, has these segments:

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
Use table: `blocks(start_ea, end_ea, func_ea, size)`.

### Decompilation (Hex-Rays)
The **Hex-Rays decompiler** converts assembly to C-like **pseudocode**:
- **ctree** - The Abstract Syntax Tree of decompiled code
- **lvars** - Local variables detected by the decompiler
- Much easier to analyze than raw assembly

Core decompiler surfaces:
- `decompile(addr)` (**PRIMARY read/display surface**)
  - Returns the entire function as one text block.
  - Each output line is prefixed for address grounding:
    - Addressed line: `/* 401010 */ ...`
    - Non-anchored line: `/*          */ ...` (no address anchor for that line)
  - Use this first when the user asks to "decompile", "show code", "show pseudocode", or "explain function logic".
- `pseudocode` table (**structured/edit surface**)
  - Use for line-level filtering (`func_addr`, `ea`, `line_num`) and comment writes.
  - Not the preferred display surface for full-function code.
- `ctree` and `ctree_call_args` for AST-level analysis
- `ctree_lvars` for local variable rename/type/comment updates

---

## Context Awareness (Plugin UI)

Use `get_ui_context_json()` when the user asks context-aware questions such as:
- "what am I looking at?"
- "what is on the screen?"
- "what's selected?"
- references like "this", "here", "current", "selected", or "that function"
- "grab the UI context"

Behavior contract:
- If there is a selection, capture selection begin/end and preview text lines.
- Capture current widget type/title and whether it is a custom view.
- Capture chooser/list selections when available (for example, Local Types selections).
- Capture code context (address/function/segment) when available.
- In non-address views, return structured context with `has_address: false` and a reason.

Capture a fresh context snapshot per user question; reuse it across that
question's turns; refresh only when the user explicitly asks to re-check.

Availability:
- `get_ui_context_json()` is registered in every runtime, but only returns live
  UI state in the IDA GUI plugin.
- Under idalib/CLI it returns a stub envelope (`available:false`,
  `capture.source:"cli"`) — no error, just no UI.
- If the result is the CLI stub, continue with non-UI SQL workflows and state that
  UI context is unavailable in this runtime.

Database orientation:
- Use `SELECT * FROM welcome` for a quick database overview (processor, bitness, address range, entry point, counts).
- To confirm which binary/instance this connection is bound to, query the file-identity columns: `SELECT filename, idb_path, md5, sha256 FROM welcome`.
- For audit/version checks, `idasql_version` reports the IDASQL build version: `SELECT idasql_version, filename, idb_path, md5, sha256 FROM welcome`.
- The `welcome` table contains only database metadata — no UI context.
- For UI context (focused widget, selection, code location), use `get_ui_context_json()`.

---

## Command-Line Interface

IDASQL provides SQL access to IDA databases via command line or as a server.

### Binary Provenance (Required)

When validating behavior that must match the live IDA plugin session, use SDK-path binaries:

- CLI: `%IDASDK%\src\bin\idasql.exe`
- Plugin loaded by IDA: `%IDASDK%\src\bin\plugins\idasql.dll`

Do not use test harness binaries (for example `build/idasql_tests/.../idasql.exe`) to conclude plugin behavior. Those are useful for tests, but plugin-parity checks must run against the SDK-path artifacts.

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

**4. HTTP Server Mode**
```bash
idasql -s database.i64 --http 8080
# Then query via: curl -X POST http://localhost:8080/query -d "SELECT * FROM funcs"
```

**5. Export Mode**

If the user asks to export the database as SQL, use:
```bash
idasql -s database.i64 --export dump.sql
idasql -s database.i64 --export dump.sql --export-tables=funcs,segments
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-s <file>` | IDA database (`.idb`/`.i64`) **or** raw binary (`.exe`/`.dll`/firmware/etc.) — raw binaries trigger fresh idalib analysis and string-list rebuild; legacy 32-bit `.idb` may return `status:"upgraded"` with `reopen_with` |
| `--token <token>` | Auth token for HTTP/MCP server mode |
| `-q <sql>` | Execute single SQL query |
| `-f <file>` | Execute SQL from file |
| `-i` | Interactive REPL mode |
| `-w, --write` | Save database changes on exit, including HTTP/MCP server shutdown |
| `--export <file>` | Export tables to SQL file |
| `--export-tables=X` | Tables to export: `*` (all) or `table1,table2,...` |
| `--http [port]` | Start HTTP REST server (default: 8080, local mode only) |
| `--bind <addr>` | Bind address for HTTP/MCP server (default: 127.0.0.1) |
| `--mcp [port]` | Start MCP server (default: random port, use in -i mode) |
| `--agent` | Enable AI agent mode in interactive REPL |
| `--config [path] [value]` | View/set agent configuration |
| `-h, --help` | Show help |

### REPL Commands

| Command | Description |
|---------|-------------|
| `.tables` | List all virtual tables |
| `.schema [table]` | Show table schema |
| `.info` | Show database metadata |
| `.quit` / `.exit` | Exit REPL |
| `.help` | Show available commands |
| `.http start` | Start HTTP server (reuses a pinned port when none is given) |
| `.http stop` | Stop HTTP server |
| `.http` | Show HTTP server status (start if not running) |
| `.pin set http\|mcp [bind] <port>` | Pin a server for autostart (IDB-persisted; plugin auto-starts on open) |
| `.pin on\|off http\|mcp` / `.pin clear [http\|mcp\|all]` / `.pin list` | Manage autostart pins |

### Performance Strategy

Opening a database has startup overhead (IDALib initialization and auto-analysis wait). For one query, use `-q`. For iterative work, keep one long-lived session (`-i`, `--http`, or `--mcp`) and run many queries against it.

If opening a legacy 32-bit `.idb` returns exit code `3` with stdout JSON
`status:"upgraded"`, repeat the same requested command with the JSON
`reopen_with` path. HTTP/MCP server modes exit before binding in this case.

**Single queries:** Use `-q` directly.
```bash
idasql -s database.i64 -q "SELECT COUNT(*) FROM funcs"
```

**Multiple queries / exploration:** Start a server once, then query repeatedly over HTTP.

Opening an IDA database has startup overhead (idalib initialization, auto-analysis). If you plan to run many queries—exploring the database, experimenting with different queries, or iterating on analysis—avoid re-opening the database each time.

**Recommended workflow for iterative analysis:**
```bash
# Terminal 1: Start server (opens database once)
idasql -s database.i64 --http 8080

# Terminal 2: Query repeatedly via HTTP (instant responses)
curl -X POST http://localhost:8080/query -d "SELECT * FROM funcs LIMIT 5"
curl -X POST http://localhost:8080/query -d "SELECT * FROM strings WHERE content LIKE '%error%'"
curl -X POST http://localhost:8080/query -d "SELECT name, size FROM funcs ORDER BY size DESC"
# ... as many queries as needed, no startup cost
```

This approach is significantly faster for iterative analysis since the database remains open and queries go directly through the already-initialized session.
Use `-w` for long-lived HTTP/MCP write sessions when edits should be saved on shutdown; otherwise writes are visible in the current process but must be flushed with `SELECT save_database()`.

### Runtime Controls (SQL)

`idasql` exposes runtime settings through pragmas:

```sql
PRAGMA idasql.query_timeout_ms;                  -- get current query timeout
PRAGMA idasql.query_timeout_ms = 60000;          -- set timeout (0 disables)
PRAGMA idasql.queue_admission_timeout_ms = 120000;
PRAGMA idasql.max_queue = 64;                    -- 0 = unbounded
PRAGMA idasql.hints_enabled = 1;                 -- 1/0, on/off
PRAGMA idasql.enable_idapython = 1;              -- 1/0, enable SQL Python execution
PRAGMA idasql.timeout_push = 15000;              -- push old timeout, set new
PRAGMA idasql.timeout_pop;                       -- restore previous timeout
```

Recommended defaults for agent harnesses that issue concurrent requests:

```sql
PRAGMA idasql.max_queue = 0;                     -- unbounded queue
PRAGMA idasql.queue_admission_timeout_ms = 0;    -- wait in queue until completion
PRAGMA idasql.query_timeout_ms = 60000;          -- still cap execution time
```

When a `SELECT` times out, partial rows may be returned with `warnings` and `timed_out=true`.
For decompiler-heavy queries, `idasql` emits warnings that suggest adding `WHERE func_addr = ...`.

---

## Tables Reference

### Debugger Tables (Full CRUD)

#### breakpoints
Debugger breakpoints with full CRUD. Persist in the IDB even without an active debugger session. Schema, all 19 columns, and worked examples: see the `debugger` skill.

### Entity Tables

Entity tables expose IDA's core program objects (functions, names, segments, imports, strings, xrefs, blocks, instructions).
Some tables support write operations; when they do, the section includes RW columns and examples.

#### funcs
All detected functions in the binary. Writable: `name`, `prototype`, `comment`, `rpt_comment`, `flags`, `folder_path`. `folder_path` is relative to the Function window root; `NULL` or `''` moves a function back to root. `full_path` is read-only and includes the final function name. Schema (basic + prototype + folder columns), and worked examples: see the `disassembly` and `annotations` skills.

```sql
INSERT INTO dirtree_folders(tree, path) VALUES ('funcs', 'idasql/review');
UPDATE funcs SET folder_path = 'idasql/review' WHERE address = 0x401000;
SELECT address, name, folder_path, full_path FROM funcs WHERE folder_path LIKE 'idasql/%';
```

#### segments
Memory segments. Writable: `name`, `class`, `perm`. Schema and examples: see the `disassembly` skill.

#### names
All named locations (functions, labels, data). Full CRUD on `name` keyed by `address`; writable `folder_path` organizes names in IDA's Names tree and `full_path` is read-only. Schema and examples: see the `annotations` and `disassembly` skills.

#### entries
Entry points (exports, program entry, TLS callbacks). Columns: `ordinal`, `address`, `name`. See the `disassembly` skill.

#### imports
Imported functions from external libraries. Columns include `address`, `name`, `module`, `ordinal`, writable `folder_path`, and read-only `full_path`. Import folder moves do not change module/name/ordinal metadata. See the `analysis` and `xrefs` skills.

#### strings
String literals found in the binary. Columns: `address`, `length`, `type`,
`type_name`, `width`, `width_name`, `layout`, `layout_name`, `encoding`,
`content`. Run `SELECT rebuild_strings()` once if the count is empty. Full
schema, encoding bit layout, and worked queries live in the `data` skill.

```sql
SELECT COUNT(*) AS strings FROM strings;
SELECT content, printf('0x%X', address) AS addr FROM strings WHERE content LIKE '%error%';
```

#### xrefs
Cross-references — the canonical surface for code/data relationships. Columns: `from_ea`, `to_ea`, `type`, `is_code`. Filter by `to_ea` (incoming refs) or `from_ea` (outgoing refs). Schema, encoding details, and recovery patterns: see the `xrefs` skill.

#### blocks
Basic blocks within functions. Columns: `func_ea`, `start_ea`, `end_ea`, `size`. **`WHERE func_ea = X` is the optimized path** — without it the table scans all functions. See the `disassembly` skill.

### Dirtree Folder Tables

IDA's directory-tree API backs function folders, local type folders, names, imports, breakpoints, and bookmark trees. Prefer object-table `folder_path` columns for normal organization (`funcs`, `types`, `names`, `imports`, `bookmarks`, `breakpoints`, `local_type_bookmarks`); use generic dirtree tables for browsing and folder lifecycle.

#### dirtree_entries
Read-only raw dirtree listing. Columns: `tree`, `path`, `parent_path`, `name`, `is_dir`, `is_file`, `inode`, `rank`, `attrs`, `depth`, `orderable`. Use `tree = 'funcs'` or another standard tree when possible; `path LIKE '/prefix/%'`, `parent_path`, `inode`, `is_dir`, and `is_file` push down.

```sql
SELECT name, inode
FROM dirtree_entries
WHERE tree = 'imports' AND parent_path = '/KERNEL32';

SELECT f.address, f.name, e.path
FROM funcs f
JOIN dirtree_entries e ON e.tree = 'funcs' AND e.inode = f.address
WHERE e.path LIKE '/idasql/%';
```

#### dirtree_folders
Writable empty-folder lifecycle for all standard trees: `funcs`, `local_types`, `names`, `imports`, `idaplace_bookmarks`, `bpts`, and `ltypes_bookmarks`. `INSERT` creates folders, `UPDATE path` renames/moves folders, and `DELETE` removes only empty folders.

Folder paths use `/` separators. Object-table `folder_path` values are relative paths such as `idasql/network`; `NULL` or `''` means root. Invalid components (`.`, `..`, duplicate separators, backslashes) are rejected on writes. Renaming a folder to an existing file/folder path is rejected so IDASQL does not inherit IDA's ambiguous raw "move into existing folder" behavior.
`dirtree_entries` is read-only diagnostics; recursive delete and raw recovery/link operations are not exposed through SQL.

```sql
INSERT INTO dirtree_folders(tree, path) VALUES ('funcs', 'idasql/network');
UPDATE dirtree_folders SET path = 'idasql/net'
WHERE tree = 'funcs' AND path = 'idasql/network';
DELETE FROM dirtree_folders WHERE tree = 'funcs' AND path = 'idasql/net';
```

### Convenience Views

Pre-built views for common xref analysis patterns. These simplify caller/callee queries.

#### callers
Who calls each function. Columns: `func_addr`, `caller_addr`, `caller_name`, `caller_func_addr`. Filter `WHERE func_addr = X`. See the `xrefs` skill.

#### callees
What each function calls. Columns: `func_addr`, `func_name`, `callee_addr`, `callee_name`. Inverse of `callers`. See the `xrefs` skill.

#### String References (explicit join pattern)

Use `strings + xrefs + funcs` directly. This is the canonical pattern.

```sql
-- Find call sites/functions referencing error-like strings
SELECT
    s.content as string_value,
    printf('0x%X', x.from_ea) as ref_addr,
    (SELECT name FROM funcs WHERE x.from_ea >= address AND x.from_ea < end_ea LIMIT 1) as func_name
FROM strings s
JOIN xrefs x ON x.to_ea = s.address
WHERE s.content LIKE '%error%' OR s.content LIKE '%fail%'
ORDER BY func_name, ref_addr;

-- Functions with most string references
SELECT
    (SELECT name FROM funcs WHERE x.from_ea >= address AND x.from_ea < end_ea LIMIT 1) as func_name,
    COUNT(*) as string_refs
FROM strings s
JOIN xrefs x ON x.to_ea = s.address
GROUP BY func_name
ORDER BY string_refs DESC
LIMIT 10;
```

### Instruction Tables

#### instructions

The disassembly table. **`WHERE func_addr = X` is the fast path**;
without it the table scans all code heads. Supports DELETE (converts
to unexplored bytes) and operand-representation updates via the
writable `operand0..7_format_spec` columns. Specs (all
disassembly-level, no IDAPython): `hex`/`dec`/`oct`/`bin`, `char`,
`float`, `offset[:base]`, `enum:NAME[::MEMBER]`,
`stroff:TYPE[/NESTED][,delta=N]`, `sizeof:STRUCT` (renders
`size STRUCT`), `segment`, `stkvar`, `forced:TEXT`, `clear`; plus
`,signed`/`,unsigned`/`,bnot`/`,nobnot` modifiers. Full schema (all
60+ operand columns), worked examples, and representation-spec
syntax: see the `disassembly` skill.

#### instruction_operands

One row per decoded non-void operand. **Performance:** `WHERE address = X` decodes one instruction; `WHERE func_addr = X` uses O(function_size) iteration. Without one of these, the table scans everything. Schema, joinable patterns, and worked examples: see the `disassembly` skill.

#### disasm_calls
All call instructions with resolved targets and optional call-site prototype overrides.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function containing the call |
| `ea` | INT | Call instruction address |
| `callee_addr` | INT | Target address (0 if unknown) |
| `callee_name` | TEXT | Target name |
| `callee_type` | TEXT | RW nullable call-site prototype; `UPDATE` applies/replaces, `NULL` or empty clears |

```sql
-- Functions that call malloc
SELECT DISTINCT (SELECT name FROM funcs WHERE func_addr >= address AND func_addr < end_ea LIMIT 1) as caller
FROM disasm_calls WHERE callee_name LIKE '%malloc%';

-- Apply or clear an indirect/direct call-site prototype
UPDATE disasm_calls
SET callee_type = 'int (__fastcall *)(const char *path)'
WHERE ea = 0x401234;
UPDATE disasm_calls SET callee_type = NULL WHERE ea = 0x401234;
```

### Database Modification

Most write examples are documented next to their tables (`breakpoints`, `segments`, `names`, `instructions`, `types*`, `applied_types`, `disasm_calls`, `dirtree_folders`, `bookmarks`, `comments`, `ctree_lvars`, `ctree_labels`, `netnode_kv`).
Quick capability matrix:

| Table | INSERT | UPDATE columns | DELETE |
|-------|--------|---------------|--------|
| `breakpoints` | Yes | `enabled`, `type`, `size`, `flags`, `pass_count`, `condition`, `group`, `folder_path` | Yes |
| `funcs` | Yes | `name`, `prototype`, `comment`, `rpt_comment`, `flags`, `folder_path` | Yes |
| `names` | Yes | `name`, `folder_path` | Yes |
| `comments` | Yes | `comment`, `rpt_comment` | Yes |
| `bookmarks` | Yes | `description`, `folder_path` | Yes |
| `segments` | — | `name`, `class`, `perm` | Yes |
| `instructions` | — | `operand0_format_spec` .. `operand7_format_spec` | Yes |
| `bytes` | — | `value`, `word`, `dword`, `qword` | Yes (revert patch) |
| `types` | Yes | `name`, `folder_path`, plus type-table write columns | Yes |
| `imports` | — | `folder_path` | — |
| `local_type_bookmarks` | `ordinal`, `description` | `description`, `folder_path` | yes |
| `dirtree_folders` | Yes (all standard dirtrees) | `path` rename/move | Yes, empty folders only |
| `types_members` | Yes | Yes | Yes |
| `types_enum_values` | Yes | Yes | Yes |
| `applied_types` | Yes | `decl` | Yes |
| `disasm_calls` | — | `callee_type` | — |
| `ctree_lvars` | — | `name`, `type`, `comment` | — |
| `netnode_kv` | Yes | `value` | Yes |

Write support is covered by the project's integration and end-to-end test suite.

Type/decompiler write examples:
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
-- Rename a local variable
UPDATE ctree_lvars SET name = 'buffer_size' WHERE func_addr = 0x401000 AND idx = 2;

-- Change variable type
UPDATE ctree_lvars SET type = 'char *'
WHERE func_addr = 0x401000 AND idx = 2;
```

### Persistence and Lifecycle Semantics

Writes are visible immediately within the current process, but they are not flushed to the IDB file until an explicit save path is used.

**CLI mode (`idasql.exe`):**
- Session opens one database, serves queries, then closes on exit.
- HTTP `POST /shutdown` cleanly stops the server and closes the session.
- Temporary unpacked IDA side files (`.id0/.id1/.id2/.nam/.til`) may appear while the DB is open and are expected to be removed on clean close.
- Changes are not persisted by default unless you call `save_database()` or run with `-w/--write`.

**Plugin mode (`idasql_plugin`):**
- Plugin stays alive for the IDA database/plugin lifetime.
- HTTP/MCP servers are stopped on plugin teardown/unload.
- Plugin unload is the lifecycle boundary for final cleanup.

**To persist changes explicitly:**
```sql
SELECT save_database();
```

`save_database()` can be costly. Prefer batching writes and saving once at an intentional boundary.

**CLI flag for save-on-exit:**
```bash
idasql -s db.i64 -q "UPDATE funcs SET name='main' WHERE address=0x401000" -w
```

**Best practice for batch operations:**
```sql
UPDATE funcs SET name = 'init_config' WHERE address = 0x401000;
UPDATE names SET name = 'g_settings' WHERE address = 0x402000;
SELECT save_database();
```

> Agent rule: never assume writes are persisted unless `save_database()` or `-w` is explicitly used.

### Decompiler Tables (Hex-Rays Required)

**CRITICAL:** Always filter by `func_addr`. Without constraint, these tables will decompile EVERY function - extremely slow!

#### pseudocode
Structured line-by-line pseudocode with writable comments. **Use `decompile(addr)` to view pseudocode; use this table only for surgical comment edits or structured line queries.** Writable columns: `comment`, `comment_placement` (placements: `semi`, `block1`, `block2`, `curly1`, `curly2`, `colon`, `case`, `else`, `do`). Filter by `func_addr` (fast) or `ea` (decompiles the containing function). Schema, comment-anchor resolution patterns, and write recipes: see the `decompiler` skill (with the `annotations` skill for the comment-mutation loop).

#### ctree
Full AST of decompiled code. Filter `WHERE func_addr = X`. Schema (15 columns including parent/child IDs, op_name, obj/num/str values) and worked patterns: see the `decompiler` skill.

#### ctree_lvars
Local variables from decompilation. Writable: `name`, `type`, `comment`. Filter by `func_addr`, key updates on `idx`. Schema, mutation guidance, and examples: see the `decompiler` skill.

#### ctree_call_args
Flattened call arguments for join-friendly querying. Columns: `func_addr`, `call_item_id`, `call_ea`, `call_obj_name`, `call_helper_name`, `arg_idx`, `arg_item_id`, `arg_op`, `arg_var_name`, `arg_var_is_stk`, `arg_num_value`, `arg_str_value`. See the `decompiler` skill.

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

Return statements with classification (`return_op`, `return_num`, `return_str`, `return_var`, `returns_arg`, `returns_call_result`). Filter by `func_addr`. Worked patterns (return-zero, error-sentinel, pass-through): see the `decompiler` skill.

### Type Tables

#### types
Local type definitions (structs, unions, enums, typedefs, funcs). Full CRUD: INSERT creates a struct/union/enum, UPDATE the `name` and `folder_path`, DELETE removes. `folder_path` is relative to the Local Types tree root; `full_path` is read-only. Columns + flag semantics: see the `types` skill.

```sql
INSERT INTO dirtree_folders(tree, path) VALUES ('local_types', 'idasql/types/recovered');
UPDATE types SET folder_path = 'idasql/types/recovered' WHERE name = 'MY_HEADER';
SELECT ordinal, name, folder_path FROM types WHERE folder_path LIKE 'idasql/types/%';
```

#### types_members
Struct/union members keyed by `type_ordinal`. Full CRUD. Columns + worked examples: see the `types` skill.

#### types_enum_values
Enum constant values keyed by `type_ordinal`. Full CRUD. Columns + examples: see the `types` skill.

#### types_func_args
Function prototype arguments with type classification. `arg_index = -1` is the return type; `arg_index >= 0` are positional args. Includes **surface-level** (`is_ptr`, `is_int`, `is_integral`, `is_float`, `is_void`, `is_struct`, `is_array`, `ptr_depth`, `base_type`) and **resolved** (`*_resolved` after typedef expansion) classification columns. Full schema and worked examples (integer-returners loose vs strict, pointer-args grouping, typedef-hidden pointers): see the `types` skill.

#### applied_types
Applied C declarations at mapped addresses. Use this to read, apply, replace, or clear function/data type information.

| Column | Type | Description |
|--------|------|-------------|
| `address` | INT | Mapped EA |
| `decl` | TEXT | RW nullable C declaration at the address |
| `ordinal` | INT | Local type ordinal when the applied type is ordinal-backed |
| `type_name` | TEXT | Local type name when available |

```sql
-- Apply or replace a declaration; address can be an EA, numeric string, or symbol name
INSERT INTO applied_types(address, decl)
VALUES (0x401000, 'int __fastcall sub_401000(void);');

UPDATE applied_types
SET decl = 'int __fastcall dispatch(command_t *cmd);'
WHERE address = 'dispatch';

-- Clear the declaration/type at the address
DELETE FROM applied_types WHERE address = 0x401000;
UPDATE applied_types SET decl = NULL WHERE address = 0x401000;

-- Join ordinal-backed applied types back to local types
SELECT a.address, a.type_name, t.kind
FROM applied_types a
JOIN types t ON t.ordinal = a.ordinal
WHERE a.ordinal IS NOT NULL;
```

Point lookup is write-friendly: `WHERE address = X` returns one mapped row even when no type is currently applied, with `decl`, `ordinal`, and `type_name` as `NULL`. Range scans return only addresses that currently have applied type information.

### Type Views

Convenience views for filtering types:

| View | Description |
|------|-------------|
| `types_v_structs` | `SELECT * FROM types WHERE is_struct = 1` |
| `types_v_unions` | `SELECT * FROM types WHERE is_union = 1` |
| `types_v_enums` | `SELECT * FROM types WHERE is_enum = 1` |
| `types_v_typedefs` | `SELECT * FROM types WHERE is_typedef = 1` |
| `types_v_funcs` | `SELECT * FROM types WHERE is_func = 1` |

### Extended Tables

#### bytes
Pure mapped-byte program view with patch support. One row per mapped
byte address. Writable: `value`, `word`, `dword`, `qword` (little-
endian patches). Hidden inputs `start_ea` and `n` pair up for bounded
reads of N consecutive bytes (`SELECT hex(blob_concat(value)) FROM
bytes WHERE start_ea = X AND n = N ORDER BY ea`). `start_ea` is
deliberately a separate hidden column from the visible `ea` so any
user predicate on `ea` (joins, compound `WHERE`) stays enforceable.
`WHERE is_patched = 1` enumerates patches fast. DELETE reverts a
patch. Item metadata (size/type/flags/disasm) lives in `heads`. Read
shapes: see `data`; patch workflow: see `debugger`.

#### bookmarks
User-defined bookmarks. Full CRUD on `description` keyed by `slot`; writable `folder_path` organizes IDA-place bookmarks and `full_path` is read-only. See the `annotations` skill.

#### netnode_kv
Persistent key-value store backed by IDA netnodes; saved inside the IDB automatically. Columns: `key` (RO PK), `value` (RW). Full CRUD; O(1) lookup via `WHERE key = '...'`. See the `storage` skill.

#### heads
All defined items (code/data heads). Columns: `address`, `size`, `flags`. `WHERE address = X` and range filters are optimized; next/previous navigation uses `ORDER BY address [DESC] LIMIT 1`. Schema in `disassembly/references/disassembly-tables.md`.

#### fixups
Relocation/fixup rows. Columns: `address`, `type`, `target`. See `disassembly/references/disassembly-tables.md`.

#### hidden_ranges
Collapsed/hidden code regions. Columns: `start_ea`, `end_ea`, `description`, `visible`. See `disassembly/references/disassembly-tables.md`.

#### problems
IDA analysis problems/warnings. Columns: `address`, `type`, `description`. See `disassembly/references/disassembly-tables.md`.

#### fchunks
Function chunks (non-contiguous code, e.g. exception handlers). Columns: `func_addr`, `start_ea`, `end_ea`, `size`. See `disassembly/references/disassembly-tables.md`.

#### signatures
FLIRT signature matches. Columns: `address`, `name`, `library`. See `disassembly/references/disassembly-tables.md`.

#### mappings
Memory mappings for debugging. Columns: `from_ea`, `to_ea`, `size`. See `disassembly/references/disassembly-tables.md`.

### Metadata Tables

#### db_info
Database-level metadata as `key`/`value` rows. See `disassembly/references/disassembly-tables.md`.

#### ida_info
IDA processor and analysis info as `key`/`value` rows (e.g. `key = 'procname'`). See `disassembly/references/disassembly-tables.md`.

### Disassembly Tables

#### disasm_loops
Detected loops in disassembly. Columns: `func_addr`, `loop_start`, `loop_end`. Filter `WHERE func_addr = X`. See `disassembly/references/disassembly-tables.md`.

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
SELECT (SELECT name FROM funcs WHERE func_addr >= address AND func_addr < end_ea LIMIT 1) as func, callee_name
FROM disasm_v_calls_in_loops;
```

---

## SQL Functions

### Disassembly
| Function | Description |
|----------|-------------|
| `disasm_at(addr)` | Canonical listing line for containing head (works for code/data) |
| `disasm_at(addr, n)` | Canonical listing line with +/- `n` neighboring heads |
| `disasm(addr)` | Single disassembly line at address |
| `disasm(addr, n)` | Next N instructions from address (count-based, not boundary-aware) |
| `disasm_range(start, end)` | All disassembly lines in address range [start, end) |
| `disasm_func(addr)` | Full disassembly of function containing address |

#### Disassembly Examples

```sql
-- Canonical single-EA disassembly (safe for code or data)
SELECT disasm_at(0x401000);

-- Canonical context window (+/- 2 heads)
SELECT disasm_at(0x401000, 2);

-- Fallback for older runtimes without disasm_at():
SELECT printf('%llx', address) || ': ' || disasm
FROM heads
WHERE address <= 0x401000 AND address + size > 0x401000
LIMIT 1;
-- Note: this fallback may decode some data heads as code; prefer disasm_at when available.

-- Full function disassembly (resolves boundaries via get_func)
SELECT disasm_func(address) FROM funcs WHERE name = '_main';

-- Disassemble a specific address range
SELECT disasm_range(address, end_ea) FROM funcs WHERE name = '_main';
SELECT disasm_range(0x401000, 0x401100);

-- Disassemble all functions in a segment
SELECT name, disasm_func(address) FROM funcs
WHERE address >= (SELECT start_ea FROM segments WHERE name = '.text')
  AND address <  (SELECT end_ea FROM segments WHERE name = '.text');

-- Force instruction decode from EA (useful for code-only workflows)
SELECT disasm(0x401000);

-- Sliding window: next 5 instructions from an address
SELECT disasm(0x401000, 5);

-- Structured analysis: filter instructions by mnemonic
SELECT address, disasm FROM instructions
WHERE func_addr = 0x401000 AND mnemonic = 'call';
```

### Byte Access and Patching
**All byte access — reads and patches — is done through the `bytes` table.**
Reads use the bounded shape `WHERE start_ea = X AND n = N` (or a two-sided
`WHERE ea BETWEEN A AND B`); writes use UPDATE; reverts use DELETE. There
are no `bytes(addr, n)` / `bytes_raw(addr, n)` scalars, and no `patch_*` /
`revert_byte` / `get_original_byte` either — the table is the single source
of truth.

The hidden `start_ea` + `n` columns pair up to request exactly N consecutive
bytes from X. They are deliberately distinct from the visible `ea` column
so any user predicate on `ea` (e.g. inside a JOIN) stays enforceable by
SQLite. `blob_concat(value)` is a libxsql aggregate that assembles row
values into one BLOB; `hex()` is the SQLite built-in BLOB→hex helper.

| Operation | SQL |
|-----------|-----|
| Read 1 byte | `SELECT value FROM bytes WHERE ea = addr` |
| Read N bytes as hex | `SELECT hex(blob_concat(value)) FROM bytes WHERE start_ea = addr AND n = N ORDER BY ea` |
| Read N bytes as BLOB | `SELECT blob_concat(value) FROM bytes WHERE start_ea = addr AND n = N ORDER BY ea` |
| Read a range | `SELECT value FROM bytes WHERE ea >= A AND ea < B ORDER BY ea` |
| Patch 1 byte | `UPDATE bytes SET value = v WHERE ea = addr` |
| Patch 2/4/8 bytes (LE) | `UPDATE bytes SET word\|dword\|qword = v WHERE ea = addr` |
| Original byte | `SELECT original_value FROM bytes WHERE ea = addr` |
| List patches (fast) | `SELECT ea FROM bytes WHERE is_patched = 1` |
| Revert one / all | `DELETE FROM bytes WHERE ea = addr` / `WHERE is_patched = 1` |

**Unbounded-range warning:** `WHERE ea > X` *without* an upper bound or
`LIMIT` walks every mapped byte from X to end-of-image — millions of rows,
seconds of wall time. Always pair the read with one of `start_ea = X AND
n = N`, `AND ea < B`, or an outer `LIMIT`.

```sql
-- Read 16 bytes as hex
SELECT hex(blob_concat(value))
FROM bytes WHERE start_ea = 0x401000 AND n = 16 ORDER BY ea;

-- Read 64 bytes as BLOB
SELECT blob_concat(value)
FROM bytes WHERE start_ea = 0x401000 AND n = 64 ORDER BY ea;

-- Patch one byte (example: NOP) and a 4-byte little-endian value
UPDATE bytes SET value = 0x90 WHERE ea = 0x401000;
UPDATE bytes SET dword = 0x90909090 WHERE ea = 0x401000;

-- Verify current vs original
SELECT value AS current, original_value AS original
FROM bytes WHERE ea = 0x401000;

-- Revert patch
DELETE FROM bytes WHERE ea = 0x401000;

-- Persist patches explicitly
SELECT save_database();
```

### Binary Search
Use the `byte_search` table for raw bytes/opcodes. It requires `WHERE pattern = ...`; `matched_hex` is an output column, not the search input.

| Column | Description |
|--------|-------------|
| `address` | Match address |
| `matched_hex` | Matched bytes rendered as hex text |
| `matched_bytes` | Matched bytes as a BLOB |
| `size` | Match size in bytes |
| `pattern` | Hidden required IDA byte pattern input |
| `start_ea` | Hidden optional inclusive lower bound |
| `end_ea` | Hidden optional exclusive upper bound |
| `max_results` | Hidden optional generator cap |

**Pattern syntax (IDA native):**
- `"48 8B 05"` - Exact bytes (hex, space-separated)
- `"48 ? 05"` or `"48 ?? 05"` - `?` = any byte wildcard (whole byte only)
- `"(01 02 03)"` - Alternatives (match any of these bytes)

**Note:** Nibble wildcards and regex are not supported in byte patterns.

**Example:**
```sql
-- Find all matches for a pattern
SELECT address, matched_hex, size
FROM byte_search
WHERE pattern = '48 8B ? 00'
LIMIT 10;

-- First match only
SELECT printf('0x%llX', address) AS addr
FROM byte_search
WHERE pattern = 'CC CC CC'
ORDER BY address
LIMIT 1;

-- Search with alternatives
SELECT address, matched_hex
FROM byte_search
WHERE pattern = 'E8 (01 02 03 04)'
LIMIT 20;
```

**Optimization Pattern: Find functions using specific instruction**

To answer "How many functions use RDTSC instruction?" efficiently:
```sql
-- Count unique functions containing RDTSC (opcode: 0F 31)
SELECT COUNT(DISTINCT f.address) as count
FROM byte_search b
JOIN funcs f ON b.address >= f.address AND b.address < f.end_ea
WHERE b.pattern = '0F 31';

-- List those functions with names
SELECT DISTINCT
    f.address as func_ea,
    f.name as func_name
FROM byte_search b
JOIN funcs f ON b.address >= f.address AND b.address < f.end_ea
WHERE b.pattern = '0F 31';
```

This is **much faster** than scanning all disassembly lines because:
- `byte_search` uses IDA's native binary search
- the containment join uses the compact `funcs` table instead of scanning every instruction

### Names & Functions
Use table lookups for address and containing-function metadata. Resolve symbol names to integer EAs before using these patterns.

| Pattern | Description |
|---------|-------------|
| `SELECT name FROM names WHERE address = :ea LIMIT 1` | Name at address |
| `SELECT name FROM funcs WHERE :ea >= address AND :ea < end_ea LIMIT 1` | Function containing address |
| `SELECT address FROM funcs WHERE :ea >= address AND :ea < end_ea LIMIT 1` | Start of containing function |
| `SELECT end_ea FROM funcs WHERE :ea >= address AND :ea < end_ea LIMIT 1` | End of containing function |

Function count and index lookup are table-driven:

```sql
SELECT COUNT(*) AS function_count FROM funcs;
SELECT address FROM funcs WHERE rowid = 0;
```

### Cross-References
Use the `xrefs` table for incoming, outgoing, and function-scoped edge queries:

```sql
SELECT from_ea, to_ea, type, is_code, from_func
FROM xrefs
WHERE to_ea = 0x401000;

SELECT from_ea, to_ea, type, is_code, from_func
FROM xrefs
WHERE from_ea = 0x401000;

SELECT from_ea, to_ea, type, is_code, from_func
FROM xrefs
WHERE from_func = 0x401000;
```

### Navigation
Use `heads` ordering for defined-item navigation, and SQLite formatting functions for display strings. Address equality/range filters are optimized; `ORDER BY address` or `ORDER BY address DESC` is consumed for next/previous-item lookups.

```sql
-- Next defined item
SELECT address
FROM heads
WHERE address > 0x401000
ORDER BY address
LIMIT 1;

-- Previous defined item
SELECT address
FROM heads
WHERE address < 0x401000
ORDER BY address DESC
LIMIT 1;

-- Nullable scalar shape for callers that need one column and one row
SELECT (
  SELECT address
  FROM heads
  WHERE address > 0x401000
  ORDER BY address
  LIMIT 1
) AS next_address;

-- Old IDASQL-style lowercase 0x-prefixed hex formatting
SELECT printf('0x%llx', address) AS address_hex
FROM heads
LIMIT 10;
```

Segment lookup is table-driven:

```sql
SELECT name
FROM segments
WHERE 0x401000 >= start_ea
  AND 0x401000 < end_ea
LIMIT 1;
```

### Comments
Read address comments through the `comments` table. For a single-query "comment-or-rpt_comment" lookup, use a scalar subquery with COALESCE:

```sql
SELECT (
  SELECT COALESCE(NULLIF(comment, ''), NULLIF(rpt_comment, ''))
  FROM comments
  WHERE address = 0x401000
  LIMIT 1
) AS comment;
```

Write address comments through the table:

```sql
INSERT INTO comments(address, comment) VALUES (0x401000, 'regular comment');
INSERT INTO comments(address, rpt_comment) VALUES (0x401000, 'repeatable comment');
-- Replace an existing comment in place
UPDATE comments SET comment = 'revised comment' WHERE address = 0x401000;
-- Remove a comment
DELETE FROM comments WHERE address = 0x401000;
```

Note: for both `names` and `comments`, `INSERT` at an EA that already has a value **replaces** it (IDA permits one name/one comment-slot per address); `UPDATE` is equivalent. For `names`, `SN_CHECK` may auto-disambiguate globally conflicting names (`foo` → `foo_0`) — read back the row to see what was stored.

### Modification
| Surface | Description |
|---------|-------------|
| `applied_types(address, decl, ordinal, type_name)` | Read, apply, replace, or clear C declarations at addresses. `address` accepts EA integers, numeric strings, and symbol names for equality writes/filters. |
| `parse_decls(text)` | Import C declarations (struct/union/enum/typedef) into local types |

Preferred SQL write surface for function metadata:
- `UPDATE funcs SET name = '...', prototype = '...' WHERE address = ...`
- `INSERT INTO names(address, name) VALUES (..., '...')` or `UPDATE names SET name = '...' WHERE address = ...`
- `prototype` maps to `applied_types` behavior and invalidates decompiler cache.

### Python Execution
| Function | Description |
|----------|-------------|
| `idapython_snippet(code[, sandbox])` | Execute Python snippet and return captured output text |
| `idapython_file(path[, sandbox])` | Execute Python file and return captured output text |

Runtime guard:

```sql
PRAGMA idasql.enable_idapython = 1;
```

Examples:

```sql
SELECT idapython_snippet('print("hello from idapython")');
SELECT idapython_file('C:/temp/script.py');
SELECT idapython_snippet('counter = globals().get("counter", 0) + 1; print(counter)', 'alpha');
```

Notes:
- disabled by default until pragma is enabled
- Python exceptions propagate as SQL errors
- `sandbox` isolates/persists Python globals by sandbox key

### Context Awareness (Plugin UI)
| Function | Description |
|----------|-------------|
| `get_ui_context_json()` | Return current UI/widget/context JSON for context-aware prompts (registered everywhere; real UI state in the GUI plugin, a `source:"cli"` stub under idalib/CLI; in the plugin executes through the same queued main-thread path and timeout behavior as other SQL functions) |

```sql
SELECT get_ui_context_json();
```

### Item Analysis
Use `heads` for item classification, size, and raw flags:

```sql
SELECT address, size, type, flags, disasm
FROM heads
WHERE address = 0x401000;

SELECT address, disasm
FROM heads
WHERE type = 'code'
ORDER BY address
LIMIT 10;
```

### Instruction Details
Use `instructions` and `instruction_operands` for decoded instruction facts:

```sql
-- Instruction type and mnemonic for filtering
SELECT address, itype, mnemonic
FROM instructions
WHERE func_addr = 0x401000
LIMIT 10;

-- Operand type/value details for one instruction
SELECT opnum, text, type_code, type_name, value
FROM instruction_operands
WHERE address = 0x401000
ORDER BY opnum;

-- Full decoded instruction row shape
SELECT i.address, i.itype, i.mnemonic, i.size, o.opnum, o.text, o.type_name, o.value
FROM instructions i
LEFT JOIN instruction_operands o
  ON o.address = i.address AND o.address = 0x401000
WHERE i.address = 0x401000
ORDER BY o.opnum;
```

### Decompilation

**When to use `decompile()` vs `pseudocode` table:**
- **Read/show pseudocode** → always start with `SELECT decompile(addr)`. It returns the full function as one text block with per-line prefixes (`/* <ea> */` when available, `/*          */` when no line anchor exists).
- **Local declaration hints** → declaration lines include compact local-variable index hints (`[lv:N]`) so rename operations can target `UPDATE ctree_lvars ... WHERE func_addr = ... AND idx = N` safely.
- **Need fresh output after edits** → use `SELECT decompile(addr, 1)` to force re-decompilation.
- **Need structured line access or comment CRUD** → query/update the `pseudocode` table.

| Function | Description |
|----------|-------------|
| `decompile(addr)` | **PREFERRED** — Full pseudocode with line prefixes (`addr` may be EA, numeric string, or symbol name; available when decompiler surfaces are enabled) |
| `decompile(addr, 1)` | Same output but forces re-decompilation (use after writes/renames) |
| `set_union_selection(func_addr, ea, path)` | Set/clear union selection path at EA (`[0,1]` or `0,1`) |
| `set_union_selection_item(func_addr, item_id, path)` | Set/clear union selection path by `ctree.item_id` |
| `set_union_selection_ea_arg(func_addr, ea, arg_idx, path[, callee])` | **PREFERRED** call-arg targeting helper; resolves to item id or errors with hint |
| `call_arg_item(func_addr, ea, arg_idx[, callee])` | Resolve call-arg coordinate to explicit `arg_item_id` |
| `ctree_item_at(func_addr, ea[, op_name[, nth]])` | Resolve generic expression coordinate to explicit `ctree.item_id` |
| `set_union_selection_ea_expr(func_addr, ea, path[, op_name[, nth]])` | Set/clear union selection via generic expression coordinate |
| `get_union_selection(func_addr, ea)` | Read union selection path JSON at EA |
| `get_union_selection_item(func_addr, item_id)` | Read union selection path JSON by `ctree.item_id` |
| `get_union_selection_ea_arg(func_addr, ea, arg_idx[, callee])` | Read union selection JSON via call-arg coordinate |
| `get_union_selection_ea_expr(func_addr, ea[, op_name[, nth]])` | Read union selection JSON via generic expression coordinate |
| `set_numform(func_addr, ea, opnum, spec)` | Set/clear numform directly by EA + operand index |
| `get_numform(func_addr, ea, opnum)` | Read numform JSON directly by EA + operand index |
| `set_numform_item(func_addr, item_id, opnum, spec)` | Set/clear numform by explicit ctree item id |
| `get_numform_item(func_addr, item_id, opnum)` | Read numform JSON by explicit ctree item id |
| `set_numform_ea_arg(func_addr, ea, arg_idx, opnum, spec[, callee])` | Set/clear numform via call-arg coordinate |
| `get_numform_ea_arg(func_addr, ea, arg_idx, opnum[, callee])` | Read numform JSON via call-arg coordinate |
| `set_numform_ea_expr(func_addr, ea, opnum, spec[, op_name[, nth]])` | Set/clear numform via generic expression coordinate |
| `get_numform_ea_expr(func_addr, ea, opnum[, op_name[, nth]])` | Read numform JSON via generic expression coordinate |

Targeting guidance:
- Use `*_ea_arg` helpers for repeated callees and call-site arguments.
- Use `ctree_item_at(..., op_name, nth)` plus `*_ea_expr` helpers for non-call expressions and assignment-side struct/union population stores.
- Verify success by recovered member paths and fewer bad casts/temp locals; constants may still render as named objects instead of quoted literals.

#### Runtime Capability Profile (Do This First)

Do **not** start with broad `pragma_*` discovery unless debugging the tool itself.
Start with documented surfaces and probe availability directly:

1. Baseline decompiler surface:
```sql
SELECT decompile(0x401000);
```

2. Baseline mutation surfaces (must exist in all supported plugin runtimes):
```sql
-- INSERT acts as upsert at the EA; UPDATE names SET name = ... WHERE address = ... is equivalent.
INSERT INTO names(address, name) VALUES (0x401000, 'my_func');
UPDATE ctree_lvars SET name = 'arg0' WHERE func_addr = 0x401000 AND idx = 0;
UPDATE ctree_lvars SET comment = 'seed comment' WHERE func_addr = 0x401000 AND idx = 0;
```

3. Advanced expression/representation helpers (optional in older/minimal runtimes):
```sql
SELECT call_arg_item(0x401000, 0x401020, 0);
SELECT ctree_item_at(0x401000, 0x401030, 'cot_asg', 0);
SELECT set_union_selection_ea_expr(0x401000, 0x401030, '', 'cot_asg', 0);
SELECT set_numform_ea_expr(0x401000, 0x401030, 0, 'clear', 'cot_asg', 0);
```

If any call returns `no such function`, treat that primitive as unavailable in this runtime and switch to fallback workflows below.

#### Mandatory Mutation Loop

For every write, use this loop:

1. Read current state (`ctree_lvars`, `pseudocode`, etc.) for the exact target.
2. Apply structural typing first: `parse_decls`, prototypes, `ctree_lvars.type`, global types.
3. Force refresh with `SELECT decompile(func_addr, 1)`.
4. Apply rename/label/union-selection/numform/comment cleanup against the refreshed rows.
5. Refresh and verify both structured row state and rendered pseudocode.

#### Local Type Seeding (Works Even In Minimal Runtimes)

When advanced numform/union helpers are unavailable, aggressively improve pseudocode via local type seeding:

```sql
-- Change local/arg type and optional comment
UPDATE ctree_lvars
SET type = 'unsigned __int64',
    comment = 'my comment here'
WHERE func_addr = 0x401000 AND idx = 18;

-- Refresh and verify effect in pseudocode
SELECT decompile(0x401000, 1);
SELECT idx, name, type, comment
FROM ctree_lvars
WHERE func_addr = 0x401000 AND idx = 18;
```

Use this to reduce noisy casts and surface meaningful field access when paired with function prototype/type improvements.

#### Fallback Path (When Advanced Helpers Are Missing)

If `set_union_selection*` / `set_numform*` / `ctree_item_at` are unavailable:

- Use `UPDATE funcs SET prototype = ...` for function-level typing.
- Use `UPDATE ctree_lvars SET type/comment = ...` for local shaping.
- Use `UPDATE ctree_lvars SET name = ...` after selecting a deterministic `idx`.
- Use `UPDATE pseudocode SET comment = ...` for stable semantic breadcrumbs.
- Keep constants readable via comments when enum rendering primitives are unavailable.
- Explicitly note unavailable primitives in your response so follow-up runs don't waste queries.

```sql
-- Decompile a function (PREFERRED way to view pseudocode)
SELECT decompile(0x401000);

-- After modifying comments or variables, re-decompile to see changes
SELECT decompile(0x401000, 1);

-- Get all local variables in a function
SELECT idx, name, type, comment, size, is_arg, is_result, stkoff, mreg FROM ctree_lvars WHERE func_addr = 0x401000 ORDER BY idx;

-- Rename by index (canonical, deterministic)
UPDATE ctree_lvars SET name = 'buffer_size' WHERE func_addr = 0x401000 AND idx = 2;

-- Rename by current name: inspect/select one idx first, then update by idx
UPDATE ctree_lvars SET name = 'buffer_size'
WHERE func_addr = 0x401000
  AND idx = (
    SELECT idx FROM ctree_lvars
    WHERE func_addr = 0x401000 AND name = 'v2'
    ORDER BY idx LIMIT 1
  );

-- If you discovered the target via stack slot or another query, resolve idx first
UPDATE ctree_lvars SET name = 'ctx'
WHERE func_addr = 0x401000
  AND idx = (
    SELECT idx
    FROM ctree_lvars
    WHERE func_addr = 0x401000 AND stkoff = 32
    ORDER BY idx
    LIMIT 1
  );

-- Set local-variable comment by index
UPDATE ctree_lvars SET comment = 'points to decrypted buffer' WHERE func_addr = 0x401000 AND idx = 2;

-- Simple current-row UPDATE path for rename
UPDATE ctree_lvars SET name = 'buffer_size'
WHERE func_addr = 0x401000 AND idx = 2;

-- Equivalent UPDATE path for comments
UPDATE ctree_lvars SET comment = 'points to decrypted buffer'
WHERE func_addr = 0x401000 AND idx = 2;

-- Fallback when direct UPDATE comment write fails on a specific lvar
-- (some runtimes can return "SQL logic error" for particular slots):
UPDATE ctree_lvars SET comment = 'points to decrypted buffer' WHERE func_addr = 0x401000 AND idx = 2;

-- Mandatory verification loop after rename
SELECT idx, name, type, comment, size, is_arg, is_result, stkoff, mreg FROM ctree_lvars WHERE func_addr = 0x401000 ORDER BY idx;
SELECT decompile(0x401000, 1);

-- Import declarations + apply prototype to improve decompilation quality
SELECT parse_decls('
#pragma pack(push, 1)
typedef struct _iobuf FILE;
typedef enum operations_e { op_empty=0, op_open=11, op_read=22, op_close=1, op_seek=2, op_read4=3 } operations_e;
typedef struct open_t { const char* filename; const char* mode; FILE** fp; } open_t;
typedef struct close_t { FILE* fp; } close_t;
typedef struct read_t { FILE* fp; void* buf; unsigned __int64 size; } read_t;
typedef struct seek_t { FILE* fp; __int64 offset; int whence; } seek_t;
typedef struct read4_t { FILE* fp; __int64 seek; int val; } read4_t;
typedef struct command_t { operations_e cmd_id; union { open_t open; read_t read; read4_t read4; seek_t seek; close_t close; } ops; unsigned __int64 ret; } command_t;
#pragma pack(pop)
');
UPDATE funcs
SET name = 'exec_command',
    prototype = 'void __fastcall exec_command(command_t *cmd);'
WHERE address = 0x140001BD0;
SELECT decompile(0x140001BD0, 1);

-- Hybrid call-arg targeting (recommended): line 0x140001C3E has multiple casted args.
-- Callee is optional. If used, pass exact name from ctree_call_args
-- (for imports this is commonly "__imp_fread", not "fread").
SELECT set_union_selection_ea_arg(0x140001BD0, 0x140001C3E, 0, '[1]');
SELECT get_union_selection_ea_arg(0x140001BD0, 0x140001C3E, 0);

-- If helper returns ambiguity/no-match, resolve explicitly:
SELECT call_item_id, arg_idx, arg_item_id, call_ea AS ea,
       COALESCE(NULLIF(call_obj_name,''), call_helper_name, '') AS callee
FROM ctree_call_args
WHERE func_addr = 0x140001BD0 AND call_ea = 0x140001C3E AND arg_idx = 0
ORDER BY call_item_id, arg_idx;

-- Fallback with explicit item id:
SELECT set_union_selection_item(0x140001BD0, 42, '[1]');

-- Inspect persisted path
SELECT get_union_selection_item(0x140001BD0, 42);

-- Clear selection
SELECT set_union_selection_item(0x140001BD0, 42, '');

-- Optional bridge when you want hybrid lookup + explicit item workflow:
SELECT call_arg_item(0x140001BD0, 0x140001C3E, 0);

-- Assignment-side stores often need generic expression targeting.
-- This is the right fix when a wrong union arm creates casts or temp locals.
SELECT ctree_item_at(0x140001BD0, 0x140001C49, 'cot_asg', 0);
SELECT set_union_selection_ea_expr(0x140001BD0, 0x140001C49, '[0]', 'cot_asg', 0);
SELECT set_numform_ea_expr(0x140001BD0, 0x140001C49, 0, 'clear', 'cot_asg', 0);

-- Enum constant rendering in comparisons (e.g., fdwReason == 1 → DLL_PROCESS_ATTACH):
-- PREFERRED: retype the variable to an enum type — the decompiler infers constants automatically
SELECT parse_decls('typedef enum { DLL_PROCESS_DETACH=0, DLL_PROCESS_ATTACH=1 } fdw_reason_t;');
UPDATE ctree_lvars SET type = 'fdw_reason_t' WHERE func_addr = 0x180001050 AND idx = 1;
SELECT decompile(0x180001050, 1);  -- verify enum names appear

-- Non-call expression workflow — advanced per-operand numform control:
-- 1) resolve expression item deterministically by ea + op_name + nth
SELECT ctree_item_at(0x140001BD0, 0x140001CBB, 'cot_eq', 0);
-- 2) apply/read via generic expression helpers (opnum = disassembly operand index)
SELECT set_numform_ea_expr(0x140001BD0, 0x140001CBB, 0, 'enum:operations_e', 'cot_eq', 0);
SELECT get_numform_ea_expr(0x140001BD0, 0x140001CBB, 0, 'cot_eq', 0);
SELECT set_numform_ea_expr(0x140001BD0, 0x140001CBB, 0, 'clear', 'cot_eq', 0);

-- Assignment-style expression (not a call): target with cot_asg
SELECT ctree_item_at(0x140001BD0, 0x140001C49, 'cot_asg', 0);
SELECT set_union_selection_ea_expr(0x140001BD0, 0x140001C49, '', 'cot_asg', 0);
```

Decompiler local and label mutation is table-driven:
- List locals with `ctree_lvars WHERE func_addr = ... ORDER BY idx`.
- Rename/comment locals with `UPDATE ctree_lvars` using `func_addr + idx`.
- Rename labels with `UPDATE ctree_labels` using `func_addr + label_num`.

### File Generation
| Function | Description |
|----------|-------------|
| `gen_listing(path)` | Generate full-database listing output (LST) to `path` |

```sql
-- Whole database listing export
SELECT gen_listing('C:/tmp/full.lst');
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

### Entity Search (grep)
| Surface | Description |
|---------|-------------|
| `grep` table | Structured rows for composable SQL search |

Searches functions, labels, segments, structs, unions, enums, members, and enum members.
Pattern rules:
- Plain text = case-insensitive contains (`pattern = 'main'`)
- `%` / `_` wildcards supported (`pattern = 'sub%'`)
- `*` is accepted and normalized to `%`

```sql
-- Structured table search: prefix
SELECT name, kind, address
FROM grep
WHERE pattern = 'sub%'
LIMIT 10;

-- Structured table search: contains
SELECT name, kind, full_name
FROM grep
WHERE pattern = 'main'
LIMIT 20;

-- Pagination is ordinary SQL
SELECT name, kind, address
FROM grep
WHERE pattern = 'init' AND kind = 'function'
ORDER BY kind, name
LIMIT 50 OFFSET 0;
```

### String List Surfaces

IDA maintains a cached list of strings. Use `rebuild_strings()` to detect and cache strings, `COUNT(*) FROM strings` for the current count, and `strings` for row-level analysis.

| Surface | Description |
|---------|-------------|
| `rebuild_strings()` | Rebuild with ASCII + UTF-16, minlen 5 (default) |
| `rebuild_strings(minlen)` | Rebuild with custom minimum length |
| `rebuild_strings(minlen, types)` | Rebuild with custom length and type mask |
| `SELECT COUNT(*) FROM strings` | Current string-list count (optimized without row materialization) |

**Type mask values:**
- `1` = ASCII only (STRTYPE_C)
- `2` = UTF-16 only (STRTYPE_C_16)
- `4` = UTF-32 only (STRTYPE_C_32)
- `3` = ASCII + UTF-16 (default)
- `7` = All types

```sql
-- Check current string count
SELECT COUNT(*) AS strings FROM strings;

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

## Entity Search Table (grep)

The `grep` virtual table is the primary structured entity-search surface.

### Usage

```sql
-- Basic search
SELECT * FROM grep WHERE pattern = 'sub%' LIMIT 10;

-- Filter by kind
SELECT * FROM grep WHERE pattern = 'EH%' AND kind = 'struct';

-- JOIN with other tables
SELECT g.name, f.size
FROM grep g
LEFT JOIN funcs f ON g.address = f.address
WHERE g.pattern = 'sub%' AND g.kind = 'function';
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `pattern` | Search pattern (required) |

### Columns

| Column | Type | Description |
|--------|------|-------------|
| `name` | TEXT | Entity name |
| `kind` | TEXT | function/label/segment/struct/union/enum/member/enum_member |
| `address` | INT | Address (for functions, labels, segments) |
| `ordinal` | INT | Type ordinal (for types, members) |
| `parent_name` | TEXT | Parent type (for members) |
| `full_name` | TEXT | Fully qualified name |

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
SELECT address
FROM funcs
WHERE rowid = ABS(RANDOM()) % (SELECT COUNT(*) FROM funcs);
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
SELECT DISTINCT (SELECT name FROM funcs WHERE from_ea >= address AND from_ea < end_ea LIMIT 1) as caller
FROM xrefs
WHERE to_ea = (SELECT address FROM imports WHERE name = 'CreateFileW');
```

### String Cross-Reference Analysis

```sql
SELECT s.content, (SELECT name FROM funcs WHERE x.from_ea >= address AND x.from_ea < end_ea LIMIT 1) as used_by
FROM strings s
JOIN xrefs x ON s.address = x.to_ea
WHERE s.content LIKE '%password%';
```

### Function Complexity (by Block Count)

```sql
SELECT (SELECT name FROM funcs WHERE func_ea >= address AND func_ea < end_ea LIMIT 1) as name, COUNT(*) as block_count
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
SELECT (SELECT name FROM funcs WHERE func_addr >= address AND func_addr < end_ea LIMIT 1) as func, printf('0x%X', ea) as addr
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
SELECT (SELECT name FROM funcs WHERE c.func_addr >= address AND c.func_addr < end_ea LIMIT 1) as func, a.arg_num_value as size
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
SELECT DISTINCT (SELECT name FROM funcs WHERE func_addr >= address AND func_addr < end_ea LIMIT 1) as name FROM ctree_v_returns
WHERE return_op = 'cot_num' AND return_num = 0;

-- Functions that return -1 (error sentinel)
SELECT DISTINCT (SELECT name FROM funcs WHERE func_addr >= address AND func_addr < end_ea LIMIT 1) as name FROM ctree_v_returns
WHERE return_op = 'cot_num' AND return_num = -1;

-- Functions that return a specific constant
SELECT DISTINCT (SELECT name FROM funcs WHERE func_addr >= address AND func_addr < end_ea LIMIT 1) as name FROM ctree_v_returns
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
SELECT (SELECT name FROM funcs WHERE func_addr >= address AND func_addr < end_ea LIMIT 1) as caller, MIN(depth) as distance
FROM callers
GROUP BY func_addr
ORDER BY distance, caller;
```

### Window Functions

```sql
-- Rank functions by size within each segment
SELECT
    s.name as seg,
    f.name,
    f.size,
    ROW_NUMBER() OVER (PARTITION BY s.start_ea ORDER BY f.size DESC) as rank
FROM funcs f
JOIN segments s
  ON f.address >= s.start_ea
 AND f.address < s.end_ea
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
    s.name as segment,
    (SELECT COUNT(*) FROM blocks WHERE func_ea = f.address) as block_count,
    (SELECT COUNT(*) FROM disasm_calls WHERE func_addr = f.address) as outgoing_calls,
    (SELECT COUNT(*) FROM xrefs WHERE to_ea = f.address AND is_code = 1) as incoming_calls,
    (SELECT COUNT(*) FROM ctree_lvars WHERE func_addr = f.address) as local_vars
FROM funcs f
JOIN segments s
  ON f.address >= s.start_ea
 AND f.address < s.end_ea
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
SELECT 'dangerous_func' as check_type, (SELECT name FROM funcs WHERE func_addr >= address AND func_addr < end_ea LIMIT 1) as location, callee_name as detail
FROM disasm_calls
WHERE callee_name IN ('strcpy', 'strcat', 'sprintf', 'gets', 'scanf')

UNION ALL

SELECT 'crypto_usage', (SELECT name FROM funcs WHERE func_addr >= address AND func_addr < end_ea LIMIT 1), callee_name
FROM disasm_calls
WHERE callee_name LIKE '%Crypt%' OR callee_name LIKE '%AES%' OR callee_name LIKE '%RSA%'

UNION ALL

SELECT 'network_call', (SELECT name FROM funcs WHERE func_addr >= address AND func_addr < end_ea LIMIT 1), callee_name
FROM disasm_calls
WHERE callee_name IN ('socket', 'connect', 'send', 'recv', 'WSAStartup')

UNION ALL

SELECT 'registry_access', (SELECT name FROM funcs WHERE func_addr >= address AND func_addr < end_ea LIMIT 1), callee_name
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
- **Invalid address:** Containing-function table lookups return no row; use a scalar subquery when you need a nullable scalar result
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
SELECT DISTINCT (SELECT name FROM funcs WHERE func_addr >= address AND func_addr < end_ea LIMIT 1) FROM disasm_calls
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

-- Full disassembly
SELECT disasm_func(0x401000);

-- Decompile (if Hex-Rays available)
SELECT decompile(0x401000);

-- Local variables
SELECT name, type, size FROM ctree_lvars WHERE func_addr = 0x401000;

-- What it calls
SELECT callee_name FROM disasm_calls WHERE func_addr = 0x401000;

-- What calls it
SELECT (SELECT name FROM funcs WHERE from_ea >= address AND from_ea < end_ea LIMIT 1) FROM xrefs WHERE to_ea = 0x401000 AND is_code = 1;
```

### "Find all uses of a string"

```sql
SELECT s.content, (SELECT name FROM funcs WHERE x.from_ea >= address AND x.from_ea < end_ea LIMIT 1) as function, printf('0x%X', x.from_ea) as location
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
| View function disassembly | `disasm_func(addr)` or `disasm_range(start, end)` |
| View decompiled code | `decompile(addr)` |
| UI/screen context questions | `get_ui_context_json()` (live UI in the GUI plugin; CLI returns a stub) |
| Edit decompiler comments | `Resolve writable pseudocode anchor, then UPDATE pseudocode SET comment = '...' WHERE func_addr = X AND ea = Y` |
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
| Store custom key-value data | `netnode_kv` (full CRUD, persists in IDB) |
| Entity search (structured) | `grep WHERE pattern = '...'` |

**Remember:** Always use `func_addr = X` constraints on instruction and decompiler tables for acceptable performance.

---

## Server Modes

IDASQL supports HTTP-based server modes for remote queries: **HTTP REST** and **MCP** (both over HTTP/SSE).

---

### HTTP REST Server (Recommended)

Standard REST API that works with curl, any HTTP client, or LLM tools.

**Starting the server:**
```bash
# Default port 8080
idasql -s database.i64 --http

# Custom port and bind address
idasql -s database.i64 --http 9000 --bind 0.0.0.0

# With authentication
idasql -s database.i64 --http 8080 --token mysecret
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
curl http://localhost:8080/help

# Execute SQL query
curl -X POST http://localhost:8080/query -d "SELECT name, size FROM funcs LIMIT 5"

# With authentication
curl -X POST http://localhost:8080/query \
     -H "Authorization: Bearer mysecret" \
     -d "SELECT * FROM funcs"

# Check status
curl http://localhost:8080/status
```

**Response Format (JSON envelope; single statement = array of one):**
```json
{"success": true, "statement_count": 1,
 "results": [{"statement_index": 0, "success": true,
   "columns": ["name", "size"], "rows": [["main", "500"]],
   "row_count": 1, "elapsed_ms": 8, "error": null}],
 "row_count_total": 1, "elapsed_ms_total": 8, "first_error_index": null}
```
On failure a result's `"success"` is `false` and `"error"` carries the message.

### Output guidance

Showing data serves the user's intent — it is not automatic. Keep three concerns separate:

- **Selection** — *whether/how much* to surface is a judgment driven by intent. Answer
  questions directly ("biggest is `main`, 500 bytes"); show supporting rows only when they
  help the user verify; don't dump full tables unprompted; never show data fetched only as
  an intermediate step.
- **Fidelity** — when you *do* present code/data, show the real artifact (decompilation,
  rows), never a paraphrase.
- **Mechanics** — consume this JSON envelope directly and render in your reply. Do **not**
  pipe responses through `python`/`jq`/`awk` to pre-render a table — that discards
  `success`/`elapsed_ms`/`error` and makes you reason over a lossy view. Reserve `jq`/`python`
  for extracting a value to feed a later query. The CLI (`-c`/`-f`) already prints a table.
  For direct terminal/pipe use the server can emit `?format=text|csv|tsv`, but as an agent,
  consume `json`.
