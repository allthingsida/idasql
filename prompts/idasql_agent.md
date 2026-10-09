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
Everything in a binary has an **address** - a memory location where code or data lives. IDA uses `ea_t` (effective address) as unsigned 64-bit integers. SQL shows these as integers; use `printf('0x%X', addr)` for hex display.

Address-taking SQL functions accept integer EAs (`0x401000`), numeric
strings (`'0x401000'`), and global symbol names (`'DriverEntry'`); symbol
names resolve via `get_name_ea`. Table predicates compare address columns
to integer EAs (e.g. `WHERE addr = 0x401000`). Unresolved symbols
return `Could not resolve name to address: <name>`.

```sql
SELECT decompile('DriverEntry');
UPDATE applied_types
SET decl = 'NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING);'
WHERE addr = 'DriverEntry';
SELECT (SELECT comment FROM comments WHERE addr = 0x401000 LIMIT 1);
```

#### High addresses (>= 2^63)
SQLite integers are signed, so an address at or above `0x8000000000000000`
(kernel images: `0xFFFFF800...`, `0xFFFFFFFF8...`) is a **negative INTEGER** in
every `addr`-like column, and `ORDER BY addr` puts the high half **first**
(most negative first), then `0`, then the low half. Every table returns and
orders such rows the way SQLite would.

- Write a high address as a **hex literal** (`0xFFFFF80000100000`) or its
  negative decimal (`-8796091973632`). **Never** as a decimal >= 2^63
  (`18446735277617577984`): SQLite reads that as a REAL, which no address
  equals, so the query silently matches nothing.
- `addr >= 0xFFFFF80000000000` also matches **every low-half address**
  (they are signed-greater). For the high half only, write
  `addr BETWEEN 0xFFFFF80000000000 AND -1` (or add `AND addr < 0`).
- Display with `printf('0x%X', addr)`, which prints the unsigned form.
- The top of the address space is `0xFFFFFFFFFFFFFFFE`; `-1` (BADADDR) is
  never an address (a segment `end_addr` of `-1` is rejected).

```sql
SELECT printf('0x%X', addr), size, type FROM heads
WHERE addr BETWEEN 0xFFFFF80000000000 AND -1 ORDER BY addr LIMIT 20;
```

### Functions
IDA groups code into **functions** with:
- `addr` / `start_addr` - Where the function begins (its entry point)
- `end_addr` - Where the function's **entry chunk** ends (not the end of the whole function; see below)
- `name` - Assigned or auto-generated name (e.g., `main`, `sub_401000`)
- `size` - Total bytes in the function, summed over all of its chunks
- `chunk_count` - Number of chunks (1 for a contiguous function)

#### Functions are not always contiguous
A function can own **tail chunks**: address ranges outside its entry chunk (exception
handlers, cold paths, code the compiler or linker placed elsewhere). One tail can be owned
by several functions at once. So `addr`..`end_addr` covers only the entry chunk, and an
address-range check against `funcs.addr`/`funcs.end_addr` is **not** a check for "X is in
function f": it misses every tail. Use these instead:

| Question | Query |
|----------|-------|
| Function(s) containing raw address X | `SELECT name FROM func_at(X)` (one row per owner; no rows outside any function) |
| Same, as a correlated scalar | `(SELECT name FROM func_at(x.from_addr) LIMIT 1)` |
| Name of a function whose entry you already have (`func_addr`, `from_func`, `callee_addr`) | `(SELECT name FROM funcs WHERE addr = X)` |
| Does function f contain X? | `EXISTS (SELECT 1 FROM func_at(X) WHERE func_addr = f.addr)` |
| Rows belonging to f | join on the owner column: `ON b.func_addr = f.addr` (`blocks`, `instructions`, `disasm_calls`), `ON x.from_func = f.addr` (`xrefs`) |
| f's chunks | `SELECT * FROM function_chunks WHERE func_addr = f.addr` |
| f's full listing | `disasm_func(f.addr)` walks every chunk; `disasm_range(addr, end_addr)` covers the entry chunk only |

```sql
-- Which function owns this address (works inside tail chunks too)?
SELECT printf('0x%X', func_addr) AS func, name, is_tail FROM func_at(0x401000);

-- Non-contiguous functions, most fragmented first
SELECT name, chunk_count, size FROM funcs WHERE chunk_count > 1 ORDER BY chunk_count DESC LIMIT 20;
```

There will be addresses and disassembly listing not belonging to a function. IDASQL can still get the bytes, disassembly listing ranges, etc.
For single-EA disassembly (code or data), prefer `disasm_at(addr[, context])` over function-scoped queries.

### Cross-References (xrefs)
Binary analysis is about understanding **relationships**:
- **Code xrefs** - Function calls, jumps between code
- **Data xrefs** - Code reading/writing data locations, or data referring to other data (pointers)
- `from_addr` → `to_addr` represents "address X references address Y"
Use table: `xrefs(from_addr, to_addr, type, is_code, from_func, kind)`. `kind`
names the type: `call`, `jump` or `code` for code xrefs; `read`, `write`, `offset`,
`text`, `info` or `data` for data xrefs (so "who calls X" is `kind = 'call'`, which
leaves out jumps).
The table contains **real references only** — ordinary fall-through flow edges
(instruction → next instruction, like IDA's Ctrl-X view) are excluded on every
path, so counts reflect calls/jumps/data refs, not instruction adjacency.

### Segments

Use table: `segments(start_addr, end_addr, name, class, perm, bitness)`.
The address columns are **writable**: `UPDATE segments SET start_addr = …` rebases
(moves) a segment, `end_addr` resizes it.

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
Use table: `blocks(start_addr, end_addr, func_addr, size)`.

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
  - Use for line-level filtering (`func_addr`, `addr`, `line_num`) and comment writes.
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
- `binary` is a key/value table — `(key TEXT, value TEXT, type TEXT)`, one row per
  metadata fact, `type ∈ {string, hex, bool, int}`. The same shape and key names work
  across the whole tool family.
- Use `SELECT * FROM binary` for a quick database overview (the `summary` row is first;
  processor, bitness, addr range, entry point, and counts follow as fact rows).
- Fetch one fact with `SELECT value FROM binary WHERE key = 'processor'`; fetch several
  with `SELECT key, value FROM binary WHERE key IN ('filename','idb_path','md5','sha256')`
  to confirm which binary/instance this connection is bound to.
- For audit/version checks, the `idasql_version` (and canonical `tool_version`) key
  reports the IDASQL build version: `SELECT value FROM binary WHERE key = 'idasql_version'`.
- Canonical keys: `tool_name`, `tool_version`, `processor`, `filetype`, `image_base`,
  `entry_point`, `min_addr`, `max_addr`, `is_64bit`, `bits`, `endianness`, `filename`,
  `summary`, `md5`, `sha256`. idasql extras: `idasql_version`, `entry_name`,
  `funcs_count`, `segments_count`, `names_count`, `strings_count`, `input_file_path`,
  `idb_path`.
- The `binary` table contains only database metadata — no UI context.
- For UI context (focused widget, selection, code location), use `get_ui_context_json()`.

---

## Command-Line Interface

IDASQL provides SQL access to IDA databases via command line or as a server.

### Binary Provenance (Required)

When validating behavior that must match the live IDA plugin session, use SDK-path binaries:

- CLI: `%IDASDK%\src\bin\idasql.exe`
- Plugin loaded by IDA: `%IDASDK%\src\bin\plugins\idasql.dll`

Do not infer plugin behavior from a separately-built test-harness binary; plugin-parity checks must run against the SDK-path artifacts above (`%IDASDK%\src\bin\idasql.exe` and the IDA-loaded `plugins\idasql.dll`).

### Invocation Modes

**1. Single Query (Local)**
```bash
idasql -s database.i64 -q "SELECT * FROM funcs LIMIT 10"
idasql -s database.i64 -q "SELECT COUNT(*) FROM funcs"
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
# Then query via: curl -X POST http://localhost:8080/query --data-binary "SELECT * FROM funcs"
# /query returns a JSON envelope by default; append ?format=text|csv|tsv for a
# rendered table (e.g. .../query?format=csv) when driving the server from a shell.
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
| `--token <token>` | Auth token for `--http` server mode (MCP has no auth); clients send `Authorization: Bearer <token>` or `X-XSQL-Token: <token>` |
| `-q <sql>` | Execute a SQL query or semicolon-separated script: each statement's results print, and the first failing statement stops it with its error (exit 1) |
| `-f <file>` | Execute SQL from file: each statement's results print, and the first failing statement stops the script with its error (exit 1) after the results before it |
| `-i` | Interactive REPL mode |
| `-w, --write` | Save database changes on exit, including HTTP/MCP server shutdown |
| `--export <file>` | Export tables to SQL file |
| `--export-tables=X` | Tables to export: `*` (all) or `table1,table2,...` |
| `--http [port]` | Start HTTP REST server (default: 8080, local mode only) |
| `--bind <addr>` | Bind address for HTTP/MCP server (default: 127.0.0.1) |
| `--mcp [port]` | Start MCP server (default: random port, use in -i mode) |
| `-h, --help` | Show help |
| `--version` | Show version |
| `link <verb>` | IDA 9.4 builds: `ida://` deep links, no database needed — `open [--no-launch] [--pid N] -- <uri>`, `list`, `status`, `register` (idasql becomes the `ida://` handler; a replaced handler such as hcli's is saved), `unregister` (restores it), `source add\|list\|remove`, `config`. `open` launches IDA on the database when none has it open |

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
| `.pin http\|mcp [bindinterface] [port]` | Pin a server for autostart (IDB-persisted; plugin auto-starts on open). **Omit the port → fresh random port each launch** (stored as `0`, not "unset"); give a port for a fixed one. `.pin set ...` is the explicit form. |
| `.pin on\|off http\|mcp` / `.pin clear [http\|mcp\|all]` / `.pin status` | Manage autostart pins; `.pin status` shows `<random port each launch>` for a port-omitted pin |

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
curl -X POST http://localhost:8080/query --data-binary "SELECT * FROM funcs LIMIT 5"
curl -X POST http://localhost:8080/query --data-binary "SELECT * FROM strings WHERE content LIKE '%error%'"
curl -X POST http://localhost:8080/query --data-binary "SELECT name, size FROM funcs ORDER BY size DESC"
# ... as many queries as needed, no startup cost
```

This approach is significantly faster for iterative analysis since the database remains open and queries go directly through the already-initialized session.
Use `-w` for long-lived HTTP/MCP write sessions when edits should be saved on shutdown; otherwise writes are visible in the current process but must be flushed with `SELECT save_database()`.

### Runtime Controls (SQL)

Runtime settings live in the **writable** `runtime_settings` table. Read with
`SELECT`, change with `UPDATE`. The only PRAGMAs are the two imperative timeout-stack
verbs (`timeout_push`/`timeout_pop`):

```sql
-- read
SELECT value FROM runtime_settings WHERE key='query_timeout_ms';
SELECT key, value, type, scope, kind, settable FROM runtime_settings;   -- discover every setting

-- change (UPDATE is the only writer)
UPDATE runtime_settings SET value='60000'  WHERE key='query_timeout_ms';            -- 0 disables
UPDATE runtime_settings SET value='120000' WHERE key='queue_admission_timeout_ms';
UPDATE runtime_settings SET value='64'     WHERE key='max_queue';                   -- 0 = unbounded
UPDATE runtime_settings SET value='1'      WHERE key='hints_enabled';               -- 1/0, on/off
UPDATE runtime_settings SET value='1'      WHERE key='enable_idapython';            -- enable SQL Python
UPDATE runtime_settings SET value='0'      WHERE key='idapython_output_max';        -- cap bytes (0 = unbounded)
UPDATE runtime_settings SET value='1'      WHERE key='enable_deep_link_navigation'; -- let ida_open_link() steer IDA (IDA 9.4 builds; ON in the plugin, OFF in the CLI)
UPDATE runtime_settings SET value='statement' WHERE key='auto_checkpoint';          -- 'statement': an undo checkpoint per writing statement; 'off' (default)

-- timeout_push/timeout_pop are the only PRAGMAs (imperative stack verbs)
PRAGMA idasql.timeout_push = 15000;              -- push old timeout, set new (stack bounded to 64)
PRAGMA idasql.timeout_pop;                       -- restore previous timeout
```

The `timeout_push` stack is bounded to **64** entries; a 65th push is rejected
(guards against unbounded client-driven growth). Always pair each push with a
`timeout_pop`.

`runtime_settings` lists each setting as `key`/`value`/`type`/`scope`/`kind`/`settable`. Its `value`
column is **writable** for value settings via `UPDATE ... WHERE key='<key>'`;
`key`/`type`/`scope`, the read-only rows (`timeout_stack_depth`,
`max_timeout_stack_depth`), and the action verbs (`timeout_push`/`timeout_pop`) reject
writes, and `INSERT`/`DELETE` are rejected.

Recommended defaults for agent harnesses that issue concurrent requests:

```sql
UPDATE runtime_settings SET value='0'     WHERE key='max_queue';                   -- unbounded queue
UPDATE runtime_settings SET value='0'     WHERE key='queue_admission_timeout_ms';  -- wait until completion
UPDATE runtime_settings SET value='60000' WHERE key='query_timeout_ms';            -- still cap execution time
```

When a `SELECT` times out, partial rows may be returned with `warnings` and `timed_out=true`.
For decompiler-heavy queries, `idasql` emits warnings that suggest adding `WHERE func_addr = ...`.

---

## Tables Reference

### Debugger Tables (Full CRUD)

#### breakpoints
Debugger breakpoints with full CRUD. Persist in the IDB even without an active debugger session. Schema, all 21 columns, and worked examples: see the `debugger` skill.

### Entity Tables

Entity tables expose IDA's core program objects (functions, names, segments, imports, strings, xrefs, blocks, instructions).
Some tables support write operations; when they do, the section includes RW columns and examples.

#### funcs
All detected functions in the binary. Writable: `name`, `prototype`, `comment`, `rpt_comment`, `flags`, `folder_path`. `INSERT INTO funcs(addr[, name, prototype, comment, flags])` creates a function; a value IDA refuses (an invalid name, an unparsable prototype) fails the whole INSERT and no function is left behind. Renaming a function, or changing its no-return flag, refreshes the pseudocode of every function that calls it or takes its address. `folder_path` is relative to the Function window root; `NULL` or `''` moves a function back to root. `full_path` is read-only and includes the final function name. Schema (basic + prototype + folder columns), and worked examples: see the `disassembly` and `annotations` skills.

```sql
INSERT INTO dirtree_folders(tree, path) VALUES ('funcs', 'idasql/review');
UPDATE funcs SET folder_path = 'idasql/review' WHERE addr = 0x401000;
SELECT addr, name, folder_path, full_path FROM funcs WHERE folder_path LIKE 'idasql/%';
```

`size` is the total over all chunks and `chunk_count` (read-only, last column) counts them;
`end_addr` is the end of the **entry chunk** only. For a function's full extent use
`function_chunks`; for "which function owns X" use `func_at(X)` (see "Functions are not
always contiguous").

#### segments
Memory segments. Columns `start_addr`, `end_addr`, `name`, `class`, `perm`, `bitness`
(16/32/64, read-only). Full CRUD: INSERT a region, DELETE it, UPDATE `start_addr`
(rebase/move), `end_addr` (resize), `name`, `class`, `perm`. An INSERT takes the
database's addressing (64-bit on a 64-bit database) and a flat base unless it names a
`bitness`; addresses may be integers, `'0x...'` text or names; an overlap or a bad `perm`
is refused with the reason. Schema and examples: see the `disassembly` skill.

#### names
All named locations (functions, labels, data). Full CRUD on `name` keyed by `addr`; writable `folder_path` organizes names in IDA's Names tree and `full_path` is read-only. A refused name says why (inside an item, already used at another address, not a valid name). Schema and examples: see the `annotations` and `disassembly` skills.

#### entries
Entry points / exports (exported symbols, program entry, TLS callbacks). Columns: `ordinal`, `addr`, `name`. See the `disassembly` skill.

#### imports
Imported functions from external libraries. Columns include `addr`, `name`, `module`, `ordinal`, writable `folder_path`, and read-only `full_path`. Import folder moves do not change module/name/ordinal metadata. See the `analysis` and `xrefs` skills.

#### strings
String literals found in the binary. Columns: `addr`, `length`, `type`,
`type_name`, `width`, `width_name`, `layout`, `layout_name`, `encoding`,
`content`. Run `SELECT rebuild_strings()` once if the count is empty. Full
schema, encoding bit layout, and worked queries live in the `data` skill.

```sql
SELECT COUNT(*) AS strings FROM strings;
SELECT content, printf('0x%X', addr) AS addr FROM strings WHERE content LIKE '%error%';
```

#### xrefs
Cross-references — the canonical surface for code/data relationships. Columns: `from_addr`, `to_addr`, `type`, `is_code`, `from_func` (NULL when the source is outside any function), `kind` (`call` / `jump` / `code`, or `read` / `write` / `offset` / `text` / `info` / `data`). Filter by `to_addr` (incoming refs) or `from_addr` (outgoing refs) — both are direct fast paths. Ordinary fall-through flow edges are excluded on every path (matches IDA's Ctrl-X). A reference from a tail chunk shared by several functions is one row per owning function (`from_func`), so row counts can exceed IDA's Ctrl-X count there; `callers`, `callees`, `call_graph` and `func_summary.callers` count every owner the same way (`func_summary.call_sites_in` counts each call site once). The `string_refs` view (strings joined to their referencing functions) rides these fast paths and is cheap even at full scan. Schema, encoding details, and recovery patterns: see the `xrefs` skill.

#### data_refs
Data (non-code) cross-references with their containing function, from every head of the function body (inline data such as jump and pointer tables included), cached for whole-program aggregates. Columns: `from_addr`, `to_addr`, `from_func_addr`, `from_func_name`, `ref_type`, `kind` (`read` / `write` / `offset` / `text` / `info` / `data`). See the `xrefs` skill.

```sql
-- Globals a function writes
SELECT DISTINCT printf('0x%X', to_addr) AS target FROM data_refs
WHERE from_func_addr = 0x401000 AND kind = 'write';
```

#### blocks
Basic blocks within functions. Columns: `func_addr`, `start_addr`, `end_addr`, `size`. **`WHERE func_addr = X` is the optimized path** — without it the table scans all functions. See the `disassembly` skill.

#### function_chunks
Every chunk of every function, **one row per owner**: a tail chunk shared by several functions appears under each of them. Columns: `func_addr`, `chunk_start`, `chunk_end`, `block_count` (blocks in this chunk), `total_size` (bytes in this chunk), `is_tail` (0 = entry chunk), `flags` (the chunk's 64-bit IDA function flags). **`WHERE func_addr = X` is the optimized path** — it charts only that function's chunks. See the `disassembly` skill.

```sql
SELECT printf('0x%X', chunk_start) AS start_hex, printf('0x%X', chunk_end) AS end_hex,
       is_tail, block_count, total_size
FROM function_chunks
WHERE func_addr = 0x401000
ORDER BY is_tail, chunk_start;
```

#### func_at
Table-valued function: which function(s) own an address. `func_at(addr)` returns `func_addr`, `name`, `chunk_start`, `chunk_end` (the chunk containing `addr`), and `is_tail`. One row per owning function (a shared tail yields several); **no rows** when `addr` is outside every function. The `addr` argument is required. See the `disassembly` skill.

```sql
SELECT name FROM func_at(0x401000);

-- Owning function of every call site of a target
SELECT printf('0x%X', x.from_addr) AS site, fa.name
FROM xrefs x JOIN func_at(x.from_addr) fa
WHERE x.to_addr = 0x401000 AND x.is_code = 1;
```

### Dirtree Folder Tables

IDA's directory-tree API backs function folders, local type folders, names, imports, breakpoints, and bookmark trees. Prefer object-table `folder_path` columns for normal organization (`funcs`, `types`, `names`, `imports`, `bookmarks`, `breakpoints`, `local_type_bookmarks`); use generic dirtree tables for browsing and folder lifecycle.

#### dirtree_entries
Read-only raw dirtree listing. Columns: `tree`, `path`, `parent_path`, `name`, `is_dir`, `is_file`, `inode`, `rank`, `attrs`, `depth`, `orderable`. Use `tree = 'funcs'` or another standard tree when possible; `path LIKE '/prefix/%'`, `parent_path`, `inode`, `is_dir`, and `is_file` push down. Entry paths are absolute (`/idasql/review`) and compare exactly like SQL: `path = 'idasql/review'` or `path LIKE 'idasql%'` (no leading `/`) match nothing.

```sql
SELECT name, inode
FROM dirtree_entries
WHERE tree = 'imports' AND parent_path = '/KERNEL32';

SELECT f.addr, f.name, e.path
FROM funcs f
JOIN dirtree_entries e ON e.tree = 'funcs' AND e.inode = f.addr
WHERE e.path LIKE '/idasql/%';
```

#### dirtree_folders
Writable empty-folder lifecycle for all standard trees: `funcs`, `local_types`, `names`, `imports`, `idaplace_bookmarks`, `bpts`, and `ltypes_bookmarks`. `INSERT` creates folders, `UPDATE path` renames/moves folders, and `DELETE` removes only empty folders.

Folder paths use `/` separators. `dirtree_folders.path` and object-table `folder_path` values are relative paths such as `idasql/network` (a `WHERE path = ...` compares exactly, so `'/idasql/network'` matches nothing); `NULL` or `''` means root. Invalid components (`.`, `..`, duplicate separators, backslashes) are rejected on writes. Renaming a folder to an existing file/folder path is rejected so IDASQL does not inherit IDA's ambiguous raw "move into existing folder" behavior.
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

#### func_summary
One triage row per function from decompiler-free tables: `func_addr`, `name`, `size`, `chunk_count`, `block_count`, `edge_count`, `cyclomatic` (edges - blocks + 2), `call_sites_out`, `callees` (distinct), `call_sites_in`, `callers` (distinct calling functions; calls only, not jumps), `loop_count`, `switch_count`, `data_reads`, `data_writes`, `frame_size`, `uses_chkstk`. Rank and triage with it instead of decompiling. `WHERE func_addr = X` costs one function; a full scan takes seconds even on a large database. String references per function: the `string_refs` view. See the `analysis` skill.

```sql
SELECT name, size, cyclomatic, call_sites_out, callers, loop_count
FROM func_summary ORDER BY cyclomatic DESC LIMIT 20;
```

#### String References (explicit join pattern)

Use `strings + xrefs + funcs` directly. This is the canonical pattern.

```sql
-- Find call sites/functions referencing error-like strings
SELECT
    s.content as string_value,
    printf('0x%X', x.from_addr) as ref_addr,
    (SELECT name FROM func_at(x.from_addr) LIMIT 1) as func_name
FROM strings s
JOIN xrefs x ON x.to_addr = s.addr
WHERE s.content LIKE '%error%' OR s.content LIKE '%fail%'
ORDER BY func_name, ref_addr;

-- Functions with most string references
SELECT
    (SELECT name FROM func_at(x.from_addr) LIMIT 1) as func_name,
    COUNT(*) as string_refs
FROM strings s
JOIN xrefs x ON x.to_addr = s.addr
GROUP BY func_name
ORDER BY string_refs DESC
LIMIT 10;
```

### Instruction Tables

#### instructions

The disassembly table. **`WHERE func_addr = X` is the fast path**;
without it the table scans all code heads. Supports DELETE (converts
to unexplored bytes; an instruction that code still flows into is
re-created by auto-analysis at once, so that DELETE fails and says so:
delete the whole range or function instead) and operand-representation updates via the
writable `operand0..7_format_spec` columns. Specs (all
disassembly-level, no IDAPython): `hex`/`dec`/`oct`/`bin`, `char`,
`float`, `offset[:base]`, `enum:NAME[::MEMBER]`,
`stroff:TYPE[/NESTED][,delta=N]`, `sizeof:STRUCT` (renders
`size STRUCT`), `segment`, `stkvar`, `forced:TEXT`, `clear`; plus
`,signed`/`,unsigned`/`,bnot`/`,nobnot` modifiers. `func_addr` is NULL for
code outside every function (a tail shared by functions is one row per owner).
Full schema (all 60+ operand columns), worked examples, and representation-spec
syntax: see the `disassembly` skill.

#### instruction_operands

One row per decoded non-void operand. `func_addr` is NULL outside every function. **Performance:** `WHERE addr = X` decodes one instruction; `WHERE func_addr = X` uses O(function_size) iteration. Without one of these, the table scans everything. Schema, joinable patterns, and worked examples: see the `disassembly` skill.

#### switch_tables
Reconstructed switch/case jump tables (via `get_switch_info`). Columns: `func_addr`, `instr_addr`, `table_addr` (NULL when no standard table address is available), `min_case`, `max_case` (both NULL when labels cannot be recovered), `case_count` (the number of non-default case labels), `default_addr` (NULL when no default). Canonical cross-tool schema (aligned with ghidrasql). Filter by an exact function-start `func_addr` (filter_eq pushdown). See the `disassembly` skill.

#### switch_cases
Per-case detail for reconstructed switches (via the kernel `calc_switch_cases`): one row per case value → target. Columns: `func_addr`, `switch_instr_addr` (joins `switch_tables.instr_addr`), `case_index`, `case_value` (NULL on the default row), `target_addr`, `is_default`. Multiple case labels sharing a target each get their own row. Filter by an exact function-start `func_addr` (filter_eq pushdown). See the `disassembly` skill.

#### function_frames
Per-function stack-frame layout from IDA's frame APIs (decompiler-free). Columns: `func_addr`, `frame_size` (locals + saved registers + return address + purged arguments), `arg_size` (the stack-argument area: every stack argument, whatever the calling convention), `local_size`, `saved_reg_size`, `stack_base_reg` (the program's stack-pointer register: `rsp` in x64, `esp` in 32-bit x86), `has_frame_pointer`, then `func_name` and `uses_chkstk` (1 when a call in the function reaches a stack-probe helper such as `__chkstk` or `__alloca_probe`, directly, through a thunk or through an import slot: the compiler's mark of a frame larger than a page; computed only when read), and `purged_size` (bytes the function pops on return: the argument bytes of a `__stdcall` function, 0 for `__cdecl`). The first seven columns are the canonical cross-tool schema (aligned with ghidrasql). Filter by `func_addr` for an O(1) single-function read. See the `disassembly` skill.

#### data_items
Defined data items (data heads — `is_data(get_flags)`). Columns: `addr`, `name`, `data_type` (applied tinfo, else flag class), `size`, `value_repr` (string contents / scalar hex, best-effort), `segment_name`, `is_string` (1 for strlits), `is_initialized` (0 for BSS/unmapped). Canonical cross-tool schema (aligned with ghidrasql). Full-scan generator; `WHERE addr = X` is an O(1) exact-head lookup (an interior address matches no row). See the `disassembly` skill.

#### dominators / post_dominators / loops
Canonical cross-tool CFG-graph tables (aligned with ghidrasql). Each maps a function's `qflow_chart_t` basic blocks onto opaque node ids and runs the generic `xsql::graph` module (dominance / natural loops); filter by `func_addr` for one function.
- **dominators**: `func_addr`, `node_addr`, `idom_addr` (NULL for the entry), `depth` (in the dominator tree, entry=0), `is_entry`.
- **post_dominators**: `func_addr`, `node_addr`, `ipdom_addr` (NULL when the node post-dominates straight to an exit), `depth`, `is_exit` (block has no CFG successors).
- **loops**: `func_addr`, `header_addr`, `latch_addr`, `start_addr` (min body-block start), `end_addr` (max body-block end; `start_addr`..`end_addr` is an address hull, which for a loop spanning chunks includes code outside it), `depth` (loop nesting, outermost=1), `loop_kind` (`natural`), `block_count`. A self-loop is a legitimate 1-block loop (header == latch). See the `disassembly` skill.

#### disasm_calls
The call instructions of functions (a call outside every function has no row), with resolved targets and optional call-site prototype overrides.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT | Function containing the call |
| `addr` | INT | Call instruction address |
| `callee_addr` | INT | Target address (0 if unknown) |
| `callee_name` | TEXT | Target name |
| `callee_type` | TEXT | RW nullable call-site prototype; `UPDATE` applies/replaces, `NULL` or empty clears |

```sql
-- Functions that call malloc
SELECT DISTINCT (SELECT name FROM funcs WHERE addr = func_addr) as caller
FROM disasm_calls WHERE callee_name LIKE '%malloc%';

-- Apply or clear an indirect/direct call-site prototype
UPDATE disasm_calls
SET callee_type = 'int (*)(const char *path)'
WHERE addr = 0x401234;
UPDATE disasm_calls SET callee_type = NULL WHERE addr = 0x401234;
```

The prototype must fit the arguments the call passes: IDA refuses one that does not
(the error names the address), e.g. a 32-bit `__fastcall` prototype whose arguments all
go in registers at a call that pushes one. Leave the calling convention out unless the
callee really uses another one.

### Database Modification

Most write examples are documented next to their tables (`breakpoints`, `segments`, `names`, `instructions`, `types*`, `applied_types`, `disasm_calls`, `dirtree_folders`, `bookmarks`, `comments`, `ctree_lvars`, `ctree_labels`, `decompiler_splits`, `netnode_kv`).
Integer values are exact on every write (INSERT, UPDATE, and scalar-function arguments): `16`, `16.0` and `'16'` are 16; a fraction, a blob, `NULL` or text such as `'0x10'` is refused with the column named, never truncated (write hex as an unquoted literal, `0x10`). An INSERT's address column also takes `'0x...'` text or a name.
Quick capability matrix:

| Table | INSERT | UPDATE columns | DELETE |
|-------|--------|---------------|--------|
| `breakpoints` | Yes | `enabled`, `type`, `size`, `flags`, `pass_count`, `condition`, `group`, `folder_path` | Yes |
| `funcs` | Yes | `name`, `prototype`, `comment`, `rpt_comment`, `flags`, `folder_path` | Yes |
| `names` | Yes | `name`, `folder_path` | Yes |
| `comments` | Yes | `comment`, `rpt_comment` | Yes |
| `bookmarks` | Yes | `description`, `folder_path` | Yes |
| `segments` | Yes | `start_addr` (rebase), `end_addr` (resize), `name`, `class`, `perm` | Yes |
| `instructions` | — | `operand0_format_spec` .. `operand7_format_spec` | Yes |
| `bytes` | — | `value`, `word`, `dword`, `qword` | Yes (revert patch) |
| `types` | Yes | `name`, `folder_path`, `is_fixed`/`size` (fixed structs), `is_bitmask`/`size` (enums), plus type-table write columns | Yes |
| `imports` | — | `folder_path` | — |
| `local_type_bookmarks` | `ordinal`, `description` | `description`, `folder_path` | yes |
| `dirtree_folders` | Yes (all standard dirtrees) | `path` rename/move | Yes, empty folders only |
| `types_members` | Yes | `member_name`, `member_type`, `offset`, `offset_bits`, `comment` | Yes |
| `types_enum_values` | Yes | `value_name`, `value`, `comment` | Yes |
| `applied_types` | Yes | `decl` | Yes |
| `disasm_calls` | — | `callee_type` | — |
| `ctree_lvars` | — | `name`, `type`, `comment` | — |
| `ctree_labels` | — | `name` | — |
| `decompiler_splits` | Yes (`addr`, `piece_size`; `func_addr` optional) | `piece_size` | Yes (unsplits) |
| `pseudocode` | — | `comment`, `comment_placement` | — |
| `pseudocode_orphan_comments` | — | `orphan_comment` (delete-only: set NULL/'' to remove) | — |
| `netnode_kv` | Yes | `value` | Yes |
| `runtime_settings` | — | `value` (per-key session/config settings; `key`/`type`/`scope` read-only) | — |
| `notepad` | — | `text` (the database notepad; one row) | Yes (clears it) |
| `signatures` | Yes (`name`: applies a FLIRT signature) | — | Yes, planned entries only |
| `ida_config` | — | `value` (applies `KEY=VALUE`; only `persisted = 1` keys are saved with the database) | — |
| `checkpoints` | Yes (`label`, optional) | `state`: `'undone'` rolls back to it, `'live'` redoes it | — (refused) |

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

-- Refine an existing struct member in place, preserving the parent type ordinal
UPDATE types_members SET member_name = 'payload_len'
WHERE type_ordinal = 42 AND member_name = 'len';
UPDATE types_members SET member_type = 'unsigned int', comment = 'decoded length'
WHERE type_ordinal = 42 AND member_name = 'payload_len';

-- Verify compound references still point at the same local type ordinal
SELECT member_name, member_type_ordinal
FROM types_members
WHERE type_name = 'packet_t' AND member_name = 'header';

-- Add an enum value
INSERT INTO types_enum_values (type_ordinal, value_name, value) VALUES (15, 'FLAG_ACTIVE', 1);

-- Add an enum value with comment
INSERT INTO types_enum_values (type_ordinal, value_name, value, comment)
VALUES (15, 'FLAG_HIDDEN', 2, 'not visible in UI');

-- Edit enum constants in place instead of redeclaring a used enum
UPDATE types_enum_values SET value_name = 'FLAG_VISIBLE', value = 4, comment = 'shown in UI'
WHERE type_ordinal = 15 AND value_name = 'FLAG_HIDDEN';

-- Rename a local variable
UPDATE ctree_lvars SET name = 'buffer_size' WHERE func_addr = 0x401000 AND idx = 2;

-- Change variable type (scalars, pointers, and array types all apply)
UPDATE ctree_lvars SET type = 'char *'
WHERE func_addr = 0x401000 AND idx = 2;

-- Array types are supported, e.g. retyping a wide stack string
UPDATE ctree_lvars SET type = 'WCHAR[6]'
WHERE func_addr = 0x401000 AND idx = 17;
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
idasql -s db.i64 -q "UPDATE funcs SET name='main' WHERE addr=0x401000" -w
```

**Best practice for batch operations:**
```sql
UPDATE funcs SET name = 'init_config' WHERE addr = 0x401000;
UPDATE names SET name = 'g_settings' WHERE addr = 0x402000;
SELECT save_database();
```

> Agent rule: never assume writes are persisted unless `save_database()` or `-w` is explicitly used.

### Undo Checkpoints

A checkpoint is a named IDA undo point. Take one before a batch of edits, roll back to it if
the edits were wrong, redo if the rollback was. It works headless (CLI, `--http`, `--mcp`) and
in the GUI, needs no IDAPython, and covers every idasql write (names, comments, prototypes,
types, members, enums, folders, segments, bytes, operand formats, `make_code`, netnodes, lvars,
pseudocode comments, callee types, split expressions, the notepad, inf-backed `ida_config` keys).

```sql
INSERT INTO checkpoints(label) VALUES ('before renames');      -- label optional: 'checkpoint N'
UPDATE funcs SET name = 'parse_header' WHERE addr = 0x401000;
SELECT label, kind, writes_since, state FROM checkpoints;      -- writes_since > 0: something to undo
UPDATE checkpoints SET state = 'undone' WHERE label = 'before renames';   -- rolls back, newer ones too
UPDATE checkpoints SET state = 'live'   WHERE label = 'before renames';   -- redo (next undone one only)
SELECT * FROM undo_state;                                      -- IDA's next undo/redo, redo_safe
```

- **Session-scoped.** Checkpoints live in IDA's undo history: they survive `save_database()`, not
  closing the database. They need a long-lived session (plugin, `--http`, `--mcp`, `-i`); a one-shot
  `idasql -q` has nothing to return to.
- **Rollback** undoes everything since the checkpoint, including GUI or IDAPython edits made in
  between (`undo_state.last_rollback_foreign` counts them). An UPDATE that matches no row undoes
  nothing; a checkpoint IDA no longer has (history trimmed by `UNDO_MAXSIZE`/`UNDO_DEPTH`, or undone
  outside idasql) fails and leaves the database as it was.
- **Redo** restores one checkpoint at a time, oldest first, and is **refused after any newer write**
  (table, scalar function, IDAPython or GUI): IDA would re-apply the old step and silently drop the
  newer change. Reads, decompiling included, do not count. `undo_state.redo_safe` says whether a
  redo would be accepted.
- **Not SQLite transactions.** `ROLLBACK` does not undo IDA writes and does not remove a checkpoint.
- **Not session settings.** `ida_config` keys with `persisted = 0` and `runtime_settings` are not
  database state and are not rolled back.
- **Per-statement undo:** with `auto_checkpoint = 'statement'` every top-level statement that writes
  gets its own checkpoint (`kind = 'auto'`, label `auto#N`, `statement` = its SQL); SQL issued from
  Python through `import idasql` belongs to the statement that ran the Python. Labels starting with
  `auto#` are reserved. While it is on, idasql keeps one undo point ready for the next statement:
  `undo_state.next_undo_label` can name an `auto#N` not listed yet (it is listed once a statement
  writes), and a rollback past it counts it as one step.
- `DELETE FROM checkpoints` is refused (an undo point cannot be dropped). Needs IDA 9.0 SP1 or later:
  on IDA 9.0 GA, creating a checkpoint and `auto_checkpoint = 'statement'` fail with that reason.

### Decompiler Tables (Hex-Rays Required)

**CRITICAL:** Always filter by `func_addr`. Without constraint, these tables will decompile EVERY function - extremely slow! `func_addr` is a function's **entry address** (an address inside a function matches no row, as on the disassembly tables); every row reports the entry.

#### pseudocode
Structured line-by-line pseudocode with writable comments. **Use `decompile(addr)` to view pseudocode; use this table only for surgical comment edits or structured line queries.** Writable columns: `comment`, `comment_placement` (placements: `semi`, `block1`, `block2`, `curly1`, `curly2`, `brace1`, `brace2`, `colon`, `case`, `else`, `do`, `asm`, `try`; an unrecognized placement is coerced to `semi`). Filter by `func_addr` (fast) or `addr` (decompiles the containing function; a line in a shared tail is listed under each owner). `addr` is NULL for a line with no address (the signature, a blank or comment-only line). Schema, comment-anchor resolution patterns, and write recipes: see the `decompiler` skill (with the `annotations` skill for the comment-mutation loop).

#### ctree
Full AST of decompiled code. Filter `WHERE func_addr = X`. Schema (30 columns including parent/child IDs, op_name, obj/num/str values) and worked patterns: see the `decompiler` skill.

#### ctree_lvars
Local variables from decompilation. Writable: `name`, `type`, `comment`. Filter by `func_addr`, key updates on `idx`. A `type` UPDATE is read back and fails when Hex-Rays keeps the old type, which is usual for the result variable (`is_result = 1`), whose type follows the prototype: change the return type with `UPDATE funcs SET prototype = ...`. Schema, mutation guidance, and examples: see the `decompiler` skill.

#### decompiler_splits
Hex-Rays "Split expression" without a pseudocode window (the window's Split/Unsplit expression, `vdui_t::split_item` in `hexrays.hpp`). A row keeps the decompiler from merging narrower operations into one wider one at `addr`: `*(_QWORD *)a1 = 0x600000001LL;` prints as `*(_DWORD *)a1 = 1; *((_DWORD *)a1 + 1) = 6;` with `piece_size = 4`. Columns: `func_addr`, `addr` (the merged instruction: the `addr` of the assignment in `ctree`), `piece_size` (1, 2, 4 or 8 bytes). `INSERT INTO decompiler_splits(addr, piece_size) VALUES (...)` (`func_addr` optional: the function containing `addr`), `UPDATE ... SET piece_size = ...`, `DELETE` unsplits; the next decompile shows it. IDA's window splits an 8-byte store into 4-byte pieces first, then 2, then 1. Saved with the database, stored exactly as IDA's own Split expression stores it, and undone by checkpoints. A split where nothing merges changes nothing. Refused: a piece size other than 1/2/4/8, an address that is not an instruction start or not in `func_addr`, a second INSERT at the same address (UPDATE it), IDA versions other than 9.0-9.4, and stored split data in a format it does not recognise (never rewritten). Filter by `func_addr`; a full scan reads every function's stored settings without decompiling. See the `decompiler` skill.

#### ctree_call_args
Flattened call arguments for join-friendly querying. Columns: `func_addr`, `call_item_id`, `call_addr`, `call_obj_name`, `call_helper_name`, `arg_idx`, `arg_item_id`, `arg_op`, `arg_var_name`, `arg_var_is_stk`, `arg_num_value`, `arg_str_value`. See the `decompiler` skill.

#### microcode
Hex-Rays **microcode** — the low-level 3-operand IR *below* the ctree (assembly → microcode → ctree → pseudocode), lifted at `MMAT_LVARS` by default (lvar-aware, SSA-like). One row per micro-instruction. A function Hex-Rays cannot lift has no rows on any path (a join or `IN` list over many functions keeps going); `SELECT microcode_error(func_addr)` says why, NULL when it lifts. Physical column order: `func_addr`, `block_num`, `seq`, `addr` (source EA, NULL when synthetic), `opcode` (raw `mcode_t`), `canonical_op` (cross-tool canonical P-code-style op — `INT_ADD`, `CALL`, `LOAD`, …; empty when the mcode has no clean canonical), **`maturity`**, **`stage`**, `text` (full rendered instruction), `l_text`/`r_text`/`d_text` (rendered left/right/dest operands, empty when the slot is void). **Filter by an exact function-start `func_addr`** — each query runs one `gen_microcode` per function (~3 ms), so an unfiltered scan decompiles the whole program. Read-only. See the `decompiler` skill.

**Maturity control (`WHERE maturity=…`).** `microcode` (and `ir_ops`) carry **`maturity`** — the returned Hex-Rays lifting rung (`generated`, `preoptimized`, `locopt`, `calls`, `glbopt1`, `glbopt2`, `glbopt3`, `lvars`) — and **`stage`** — the coarse cross-tool ordinal; idasql microcode emits `raw`/`optimized`/`final` (SSA-like, never the explicit-`ssa` stage). Unconstrained queries default to `lvars`/`final`. Add `AND maturity='generated'` to **re-lift the same function at a lower rung** (raw pre-optimization microcode has ~9× more ops than `lvars`). `maturity` is a **passthrough** filter (pushes down to the generator, through `ir_ops` too): `=`, `IN`, `LIKE`, `<`, `<=`, `>` and `>=` each lift exactly the rungs whose name matches (names compare as text; for ladder order use `ir_maturities.ordinal`); for `<>` or `NOT ...` list the rungs with `IN` instead (those reach the table only as the default rung); if Hex-Rays cannot return that exact rung, no non-matching rows are leaked through the equality constraint. List the ladder with **`SELECT * FROM ir_maturities`** (8 rows: `maturity`, `stage`, `ordinal`, `is_default`, `is_ssa`; `lvars` is the default, none are explicit-SSA).

#### microcode_operands
Structured operand rows for the 5-kind model (one row for every non-void `minsn_t` `l`/`r`/`d` operand, including structural control-flow operands). Columns: `func_addr`, `op_seq` (joins `microcode.seq`), `operand_index`, `role` (`in`|`out`), `kind` (`reg`|`imm`|`mem`|`var`|`result`; empty for structure such as block/case refs), `text`, `value` (NULL unless an integer immediate), `size`, `maturity`, `stage`. Same `func_addr`/`maturity` pushdown as `microcode`. Read-only.

#### ir_ops / ir_v_* / ir_operands / ir_maturities (cross-tool low-IR views)
Canonical low-IR over `microcode`: **`ir_ops`** has exactly 8 columns (`func_addr`, `seq`, `addr`, `op` = canonical P-code-style op or NULL, `native_op` = native microcode mnemonic, `is_ssa` = 0 since MMAT_LVARS is not explicit SSA, **`maturity`** = passthrough filter, **`stage`** = returned coarse classification). The portable semantic views **`ir_v_calls`** / **`ir_v_mem_writes`** / **`ir_v_mem_reads`** / **`ir_v_branches`** / **`ir_v_arith`** each keep exactly 4 columns (`func_addr`, `seq`, `addr`, `op`). **`ir_operands`** keeps exactly 8 columns (`func_addr`, `op_seq`, `operand_index`, `role`, `kind`, `text`, `value`, `size`) and is pinned to the default `lvars` rung because its portable schema has no maturity coordinate; join it to default-rung `ir_ops` on `func_addr` plus `op_seq = seq`. For a non-default rung, join native `microcode` and `microcode_operands` on `func_addr`, `seq = op_seq`, and `maturity` (plus operand coordinates as needed). **`ir_maturities`** advertises the lifting ladder (`maturity`, `stage`, `ordinal`, `is_default`, `is_ssa`). Same view names/columns hold across the family tools, so portable SQL can compare IR across engines. Filter every IR surface by an exact function-start `func_addr`; only `ir_ops` and the native tables expose optional maturity pushdown. Read-only.

### Decompiler Views

Pre-built views for common patterns:

| View | Purpose |
|------|---------|
| `ctree_v_calls` | Function calls with callee info |
| `ctree_v_indirect_calls` | Indirect calls (through register/memory) |
| `ctree_v_loops` | for/while/do loops |
| `ctree_v_ifs` | if statements |
| `ctree_v_comparisons` | Comparisons with operands |
| `ctree_v_signed_ops` | Signed comparison/arithmetic operations |
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

Lookups push down: `WHERE ordinal = ?` and `WHERE name = ?` resolve one type
directly, and `WHERE name LIKE 'prefix%'` renders only matches. Avoid
`name LIKE '%substr%'` and unfiltered `SELECT * FROM types` on large IDBs (they
render every type). A query cut off by the timeout returns cleanly and the next
query still works.

**Fixed layout (`is_fixed`, `size`).** `is_fixed = 1` (writable) freezes member
offsets. A `DELETE` leaves the slot as a gap on **any** struct — auto or fixed —
preserving the following members' offsets and the struct size (like IDA's Undefine;
it never shifts them); an `INSERT` at a gap offset absorbs it without moving
neighbors. `size` is writable on a fixed struct (pins total size; errors on an auto
struct). To compact/repack a struct (drop the gaps, may shrink), set `is_fixed = 1`
then `is_fixed = 0` — IDA repacks only on the fixed→auto transition, so a plain
`is_fixed = 0` on an already-auto struct is a no-op. Prefer this incremental flow over
`parse_decls()` rebuilds for refining a recovered struct.

#### types_members
Struct/union members keyed by `type_ordinal`. Full CRUD. Writable columns:
`member_name`, `member_type`, `offset`, `offset_bits`, and `comment`. Prefer
these targeted updates when refining an existing type: they preserve the local
type ordinal, so dependent prototypes and member type references remain attached
to the same type ID. Explicit struct offset edits fix the struct layout so IDA
preserves the requested byte offset; union member offsets remain zero. The
read-only `is_gap` column flags IDA gap placeholders (free space). On a fixed
struct, `DELETE` is non-collapsing (the slot becomes a gap) and `INSERT` at a gap
offset absorbs it; see `type_gaps` for free byte ranges. Columns + worked
examples: see the `types` skill.

#### type_gaps
Free byte ranges in a struct — where a new field can go (read-only). One row per
gap: `type_ordinal`, `type_name`, `gap_offset`, `gap_size`. **Requires a filter**
on `type_ordinal` or `type_name`. Use the flow `types` → `type_gaps` (find space)
→ `types_members` INSERT at a `gap_offset` to absorb a gap without disturbing
neighbors.
```sql
SELECT gap_offset, gap_size FROM type_gaps WHERE type_name = 'VARBIND_VARIABLE';
INSERT INTO types_members (type_ordinal, member_name, member_type, "offset")
SELECT ordinal, 'handler_cookie', 'int', 28   -- absorb the gap at offset 28
FROM types WHERE name = 'VARBIND_VARIABLE';
```

#### struct_member_xrefs
Cross-references **to a specific struct/union member** (read-only). Resolves the
member's IDA tid (`get_udm_tid`) and enumerates xrefs directly — use this instead
of `LIKE`-scanning `instructions.disasm` / `instruction_operands.text` for a field
name. **Requires a filter** on `type_ordinal`, `type_name`, or `member_id`; an
unfiltered query errors. Embedded struct/union members are expanded recursively
with a dotted `member_path` (e.g. `payload.leaf.data`). Key columns: `member_path`,
`member_id`, `xref_from`, `xref_kind` (read/write/offset/call/jump), `function_name`,
`instruction_text`, `operand_index` (the operand that lands on the member: a struct-offset
expression, or a stack variable of the structure's type), `access_offset` (byte offset of the access inside the member; 0 for a direct
field access), `access_size` (NULL when the instruction takes the member's address: an
offset-of immediate or an `lea`) and `access_root_type`
(the structure the expression starts from). A nested member's rows list every xref to
the embedded type's member; `access_root_type = type_name` keeps the accesses made
through the queried container.
Canonical discovery flow: `types` (resolve the type) → `types_members` (enumerate
members) → `struct_member_xrefs` (references for a chosen member).
```sql
SELECT member_path, xref_kind, function_name, instruction_text
FROM struct_member_xrefs
WHERE type_name = '_EH3_EXCEPTION_REGISTRATION' AND member_name = 'TryLevel';
```

#### types_enum_values
Enum constant values keyed by `type_ordinal`. Full CRUD. Columns + examples: see the `types` skill.
**Bitfield enums:** mark an enum as a bitmask via writable `types.is_bitmask` (set its
width with writable `types.size` = 1/2/4/8); flag members are added normally (flat —
value is its own mask). A combined operand value then renders as OR'd flags
(`A or B` in disasm, `A | B` in pseudocode) once the enum is applied to the operand
via the existing `operandN_format_spec = 'enum:NAME'` (`op_enum`).

#### types_func_args
Function prototype arguments with type classification. `arg_index = -1` is the return type; `arg_index >= 0` are positional args. Includes **surface-level** (`is_ptr`, `is_int`, `is_integral`, `is_float`, `is_void`, `is_struct`, `is_array`, `ptr_depth`, `base_type`) and **resolved** (`*_resolved` after typedef expansion) classification columns. Full schema and worked examples (integer-returners loose vs strict, pointer-args grouping, typedef-hidden pointers): see the `types` skill.

#### applied_types
Applied C declarations at mapped addresses. Use this to read, apply, replace, or clear function/data type information.

| Column | Type | Description |
|--------|------|-------------|
| `addr` | INT | Mapped EA |
| `decl` | TEXT | RW nullable C declaration at the address |
| `ordinal` | INT | Local type ordinal when the applied type is ordinal-backed |
| `type_name` | TEXT | Local type name when available |

```sql
-- Apply or replace a declaration; address can be an EA, numeric string, or symbol name
INSERT INTO applied_types(addr, decl)
VALUES (0x401000, 'int __fastcall sub_401000(void);');

UPDATE applied_types
SET decl = 'void __fastcall exec_command(command_t *cmd);'
WHERE addr = 'exec_command';

-- Clear the declaration/type at the address
DELETE FROM applied_types WHERE addr = 0x401000;
UPDATE applied_types SET decl = NULL WHERE addr = 0x401000;

-- Join ordinal-backed applied types back to local types
SELECT a.addr, a.type_name, t.kind
FROM applied_types a
JOIN types t ON t.ordinal = a.ordinal
WHERE a.ordinal IS NOT NULL;
```

Point lookup is write-friendly: `WHERE addr = X` returns one mapped row even when no type is currently applied, with `decl`, `ordinal`, and `type_name` as `NULL`. Range scans return only addresses that currently have applied type information.

### Type Views

Convenience views for filtering types:

| View | Description |
|------|-------------|
| `types_v_structs` | `SELECT * FROM types WHERE is_struct = 1` |
| `types_v_unions` | `SELECT * FROM types WHERE is_union = 1` |
| `types_v_enums` | `SELECT * FROM types WHERE is_enum = 1` |
| `types_v_typedefs` | `SELECT * FROM types WHERE is_typedef = 1` |
| `types_v_funcs` | `SELECT * FROM types WHERE is_func = 1` |
| `types_v_inheritance` | Base/derived type relationships (`derived_ordinal`, `base_type_name`, `base_offset`) |

### Extended Tables

#### bytes
Pure mapped-byte program view with patch support. One row per mapped
byte address. Writable: `value`, `word`, `dword`, `qword` (little-
endian patches). Hidden inputs `start_addr` and `n` pair up for bounded
reads of N consecutive bytes (`SELECT hex(blob_concat(value)) FROM
bytes WHERE start_addr = X AND n = N ORDER BY addr`). `start_addr` is
deliberately a separate hidden column from the visible `addr` so any
user predicate on `addr` (joins, compound `WHERE`) stays enforceable.
A write needs an exact integer (`144`, `0x90`, `'144'`, `144.0`):
`'0x90'` as text, `144.5` or a blob is refused, and a qword above 0x7FFFFFFFFFFFFFFF is
written as hex (`0xFFFFFFFFFFFFFFFF`) or signed (`-1`).
`WHERE is_patched = 1` enumerates patches fast. `is_initialized` is 1 for
loaded bytes and 0 for uninitialized/BSS bytes (where `value` reads back
NULL); `WHERE is_initialized = 1` is the initialized-only view. DELETE
reverts a patch. Item metadata (size/type/flags/disasm) lives in `heads`.
Read shapes: see `data`; patch workflow: see `debugger`.

#### bookmarks
User-defined bookmarks. Full CRUD on `description` keyed by `slot`; writable `folder_path` organizes IDA-place bookmarks and `full_path` is read-only. See the `annotations` skill.

#### netnode_kv
Persistent key-value store backed by IDA netnodes; saved inside the IDB automatically. Columns: `key` (RO PK), `value` (RW). Full CRUD; O(1) lookup via `WHERE key = '...'`. See the `storage` skill.

#### heads
All defined items (code/data heads). Columns: `addr`, `size`, `type`, `flags`, `disasm`. `WHERE addr = X` and range filters are optimized; next/previous navigation uses `ORDER BY addr [DESC] LIMIT 1`. Schema in `disassembly/references/disassembly-tables.md`.

#### fixups
Relocation/fixup rows. Columns: `addr`, `type`, `target`. See `disassembly/references/disassembly-tables.md`.

#### hidden_ranges
Collapsed/hidden code regions. Columns: `start_addr`, `end_addr`, `description`, `visible`. See `disassembly/references/disassembly-tables.md`.

#### problems
IDA analysis problems/warnings. Columns: `addr`, `type`, `description`. See `disassembly/references/disassembly-tables.md`.

#### fchunks
Raw IDA chunk list, one row per chunk. Columns: `owner`, `start_addr`, `end_addr`, `size`, `flags` (64-bit), `is_tail`. `owner` is the chunk's **primary** owner only: a tail shared by several functions lists just one of them. For complete ownership use `function_chunks` (one row per owner) or `func_at(addr)`. See `disassembly/references/disassembly-tables.md`.

#### signatures
The database's FLIRT signature list. Columns: `idx` (position; it shifts after a DELETE), `name` (as IDA stores it: a short name or an absolute path), `title` (the library's name; NULL when the file is gone), `state` (`applied`, `current`, `planned`), `matches` (library functions it recognized), `optlibs`. `INSERT INTO signatures(name) VALUES ('vc32rtf')` applies a signature (a short name from IDA's sig folders for this processor, or a `.sig` path) and returns when analysis has applied it; the matched functions are renamed and flagged as library code (`funcs WHERE flags & 4`). Refused with the reason: no such file, not a signature file, another processor's signature, already in the list. `DELETE` removes a planned entry; an applied one is refused (IDA cannot unapply a signature): take a checkpoint before applying (`INSERT INTO checkpoints`) and roll back with `UPDATE checkpoints`.

```sql
INSERT INTO signatures(name) VALUES ('vc32rtf');
SELECT name, title, state, matches FROM signatures;
SELECT name FROM funcs WHERE flags & 4;               -- library code: skip it in triage
```

#### available_signatures
The `.sig` files IDA would find for this database's processor (IDAUSR, `$IDASGN`, then IDA's own `sig` folder; the first of a name wins). Columns: `name` (what INSERT takes), `title`, `path`, `source` (`idausr` / `idasgn` / `idadir`), `is_startup` (a startup signature, used to pick runtime libraries), `modules`, `in_list`.

```sql
INSERT INTO signatures(name)
SELECT name FROM available_signatures WHERE name LIKE 'vc32%' AND title LIKE 'Microsoft VisualC%' AND NOT in_list AND NOT is_startup;
```

#### mappings
Memory mappings for debugging. Columns: `from_addr`, `to_addr`, `size`. See `disassembly/references/disassembly-tables.md`.

### Metadata Tables

#### db_info
Database-level metadata as `key`/`value`/`type` rows (e.g. `processor`, `filetype`, `sdk_version`). The processor name is `db_info` key `processor`. See `disassembly/references/disassembly-tables.md`.

#### ida_info
IDA analysis-flag info as `key`/`value`/`type` rows (e.g. `show_auto`, `show_void`, `wide_hbf`, `demnames`). See `disassembly/references/disassembly-tables.md`.

#### runtime_settings
Writable discovery view over the runtime controls. Columns: `key`, `value`, `type` (`int`/`bool`/`string`), `scope`, `kind` (`value`/`action`), `settable` (1 only when `UPDATE` is accepted — `scope` cannot answer that, since tunable and read-only keys are both `common`). One row per setting — the shared keys `query_timeout_ms`, `queue_admission_timeout_ms`, `max_queue`, `hints_enabled`, `timeout_stack_depth`, `max_timeout_stack_depth` (scope `common`), `timeout_push`, `timeout_pop` (scope `action`), plus idasql-only `enable_idapython`, `idapython_output_max`, `auto_checkpoint` (`off` or `statement`; scope `idasql`), and on IDA 9.4 builds `enable_deep_link_navigation` (scope `idasql`; ON in the GUI plugin, OFF under the CLI). `SELECT * FROM runtime_settings` enumerates the surface; **change a value setting with `UPDATE runtime_settings SET value='...' WHERE key='<key>'`**. `key`/`type`/`scope`, the read-only rows (`timeout_stack_depth`, `max_timeout_stack_depth`), and the action verbs reject writes; `INSERT`/`DELETE` are rejected. `timeout_push`/`timeout_pop` are PRAGMAs (imperative stack verbs).

#### checkpoints
Named undo checkpoints over IDA's undo engine (see "Undo Checkpoints" under Database Modification). Columns: `seq` (creation order; the rowid), `label`, `created_at`, `kind` (`user` or `auto`), `writes_since` (changes made after it that are still applied; a count of changes, not rows), `statement` (the SQL that wrote, for `auto`; NULL for `user`), `state` (`live` or `undone`). `INSERT INTO checkpoints(label) VALUES (...)` creates one (empty, duplicate and `auto#` labels are refused); `UPDATE ... SET state = 'undone'` rolls back to it, `'live'` redoes the next undone one. Rows for undone checkpoints stay until a new checkpoint ends IDA's redo branch.

#### undo_state
One read-only row: `next_undo_label` and `next_redo_label` (IDA's own, so GUI and IDAPython steps show too), `redo_safe` (1 when a redo would be accepted), `last_rollback_steps` and `last_rollback_foreign` (IDA undo steps the last rollback took, and how many of them idasql did not create).

#### notepad
The database notepad (IDA's "Database notepad" window): one row, saved inside the IDB. Columns: `text` (line ends shown as `\n`), `size` (bytes as stored, CRLF line ends, without the NUL). `UPDATE notepad SET text = '...'` replaces it, written with CRLF line ends like the window; append with `UPDATE notepad SET text = text || char(10) || '...'`. `DELETE FROM notepad` clears it (the row stays, empty). Text above 1,024,000 bytes with CRLF line ends and the NUL (what the window can hold) is refused, as are NULL and NUL bytes; `INSERT` is refused. In the GUI an open notepad window shows the new text at IDA's next UI refresh (about a tenth of a second) and drops text typed there but not yet saved; the window stores its typing when it closes or loses focus and when the database is saved, so one that closes before that refresh writes its own text back over the UPDATE. See the `annotations` skill.

#### ida_config
IDA's configuration keys (`LOOKBACK`, `MAX_AUTONAME_LEN`, `SHOW_XREFS`, the decompiler's `hexrays.cfg` keys, ...), listed from the option files IDA reads: `ida.cfg` (the current processor's section), `hexrays.cfg`, `idagui.cfg` and the user's `idauser.cfg`. Columns: `key`, `file` (the file that sets it), `value` (in `.cfg` syntax: numbers, `YES`/`NO`, quoted strings), `value_source`, `writable`, `persisted`, `message`. `value_source` says where the value comes from: `runtime` (IDA reports it), `inf` (stored in the database), `session` (IDA cannot report it; the value this session applied) or `file` (IDA cannot report it; the files' value). `UPDATE ida_config SET value = '88' WHERE key = 'LOOKBACK'` applies `LOOKBACK=88` and reads it back; `YES`/`NO` keys also take `1`/`0`/`on`/`off`, and string keys are quoted for you. A value IDA clamps is applied and its warning lands in `message` (`LOOKBACK=9999` gives 256, "too high"; for a key IDA cannot report, `value` shows the bound IDA applied); a value IDA rejects fails the UPDATE with IDA's message. **Only `persisted = 1` keys (the database's own settings) are saved with the database; every other change lasts until the database is closed.** To keep one across databases, put it in your `idauser.cfg` or pass `-D KEY=VALUE` to IDA: nothing writes `.cfg` files. `writable = 0` marks `idagui.cfg` keys outside the GUI and decompiler keys without the decompiler. No `INSERT`/`DELETE`. See the `connect` skill.

### Disassembly Tables

#### disasm_loops
Natural loops in disassembly: one row per back edge whose header dominates its latch (the `loops` table's loops; address order is not used). Columns: `func_addr`, `loop_id` (the header's block index), `header_addr`, `header_end_addr`, `back_edge_block_addr`, `back_edge_block_end`. Filter `WHERE func_addr = X` (a function's entry address). See `disassembly/references/disassembly-tables.md`.

### Disassembly Views

Views for disassembly-level analysis (no Hex-Rays required):

| View | Description |
|------|-------------|
| `disasm_v_leaf_funcs` | Functions with no outgoing calls |
| `disasm_v_call_chains` | Call chain paths (recursive CTE) |
| `disasm_v_calls_in_loops` | Calls between a loop's header and its latch (an address range; a loop spanning chunks is approximate) |
| `disasm_v_funcs_with_loops` | Functions containing loops |

```sql
-- Find functions that don't call anything
SELECT * FROM disasm_v_leaf_funcs LIMIT 10;

-- Find hotspot calls (inside loops)
SELECT (SELECT name FROM funcs WHERE addr = func_addr) as func, callee_name
FROM disasm_v_calls_in_loops;
```

### Deep Links (IDA 9.4 builds)

These surfaces exist only when idasql was built for IDA 9.4 or later; if `deep_links` is absent from `pragma_table_list`, emit no links.

#### deep_links
Generator: give `resource` plus the target in `WHERE` and get one link back. The target is `addr` (or `rva`), or `name` for `resource = 'types'`. Outputs:
- `uri`: the `ida://` link. Everything before its last parameter is byte-identical to IDA's own Copy Link; the last, `idb_path`, is the database's full path (IDA ignores it; idasql's click handler uses it to launch IDA on the right file).
- `valid` / `diagnostic`: when the target does not resolve, `valid = 0` with IDA's reason and a NULL `uri`.

Optional inputs: `view` (when omitted: `pseudocode` for functions, `disasm` without a decompiler and for every other resource with an address, `types` for types), `idb_name` (`''` = IDB-less), `source`, and `addr_mode` (`auto`/`rva`/`ea`). An unconstrained scan is refused. JOIN it per row:

```sql
SELECT f.name, printf('0x%X', f.addr) AS addr, dl.uri
FROM funcs f
JOIN deep_links dl ON dl.resource = 'functions' AND dl.addr = f.addr AND dl.view = 'pseudocode'
ORDER BY f.size DESC LIMIT 10;
```

#### deep_link_parse
`WHERE uri = '<ida:// link>'` gives the link's parts, `valid` / `diagnostic` (IDA's parsing rules), and `ida_uri`, the exact string handed to IDA. A link whose decoded parts hold a control character (`%00`, `%0A`, ...) or a types name IDA cannot receive (`&`, `#`, `%`) is invalid.

**Rendering rule:**
- Write each link as `[exact_name_from_the_row](uri)` in prose, a list or a table cell, never inside a code block or backticks: only markdown links are clickable.
- Links open code: `view = 'pseudocode'` for functions (`disasm` without a decompiler), `disasm` for addresses, call sites and data; a list window (`functions`, `strings`, `imports`) only when the user asks for it.
- Link what the answer is about, not every row.
- Navigate only when asked (`ida_open_link`).

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
| `disasm_func(addr)` | Full disassembly of the function containing address: every chunk, entry chunk first, with a `; ---------- tail chunk <start>-<end> (of <name>) ----------` line before each tail |
| `make_code(addr)` | Force-convert bytes at `addr` into a code instruction |
| `make_code_range(start, end)` | Force-convert the byte range [start, end) into code |

#### Disassembly Examples

```sql
-- Canonical single-EA disassembly (safe for code or data)
SELECT disasm_at(0x401000);

-- Canonical context window (+/- 2 heads)
SELECT disasm_at(0x401000, 2);

-- Fallback for older runtimes without disasm_at():
SELECT printf('%llx', addr) || ': ' || disasm
FROM heads
WHERE addr <= 0x401000 AND addr + size > 0x401000
LIMIT 1;
-- Note: this fallback may decode some data heads as code; prefer disasm_at when available.

-- Full function disassembly: all chunks, entry chunk first, tails after a separator line
SELECT disasm_func(addr) FROM funcs WHERE name = '_main';

-- Disassemble a specific address range
SELECT disasm_range(0x401000, 0x401100);

-- Disassemble all functions in a segment
SELECT name, disasm_func(addr) FROM funcs
WHERE addr >= (SELECT start_addr FROM segments WHERE name = '.text')
  AND addr <  (SELECT end_addr FROM segments WHERE name = '.text');

-- Force instruction decode from EA (useful for code-only workflows)
SELECT disasm(0x401000);

-- Sliding window: next 5 instructions from an address
SELECT disasm(0x401000, 5);

-- Structured analysis: filter instructions by mnemonic
SELECT addr, disasm FROM instructions
WHERE func_addr = 0x401000 AND mnemonic = 'call';
```

### Byte Access and Patching
**All byte access — reads and patches — is done through the `bytes` table.**
Reads use the bounded shape `WHERE start_addr = X AND n = N` (or a two-sided
`WHERE addr BETWEEN A AND B`); writes use UPDATE; reverts use DELETE. There
are no `bytes(addr, n)` / `bytes_raw(addr, n)` scalars, and no `patch_*` /
`revert_byte` / `get_original_byte` either — the table is the single source
of truth.

The hidden `start_addr` + `n` columns pair up to request exactly N consecutive
bytes from X. They are deliberately distinct from the visible `addr` column
so any user predicate on `addr` (e.g. inside a JOIN) stays enforceable by
SQLite. `blob_concat(value)` is a built-in aggregate that assembles row
values into one BLOB; `hex()` is the SQLite built-in BLOB→hex helper.

| Operation | SQL |
|-----------|-----|
| Read 1 byte | `SELECT value FROM bytes WHERE addr = <addr>` |
| Read N bytes as hex | `SELECT hex(blob_concat(value)) FROM bytes WHERE start_addr = <addr> AND n = <N> ORDER BY addr` |
| Read N bytes as BLOB | `SELECT blob_concat(value) FROM bytes WHERE start_addr = <addr> AND n = <N> ORDER BY addr` |
| Read a range | `SELECT value FROM bytes WHERE addr >= <A> AND addr < <B> ORDER BY addr` |
| Patch 1 byte | `UPDATE bytes SET value = <v> WHERE addr = <addr>` |
| Patch 2/4/8 bytes (LE) | `UPDATE bytes SET word\|dword\|qword = <v> WHERE addr = <addr>` |
| Original byte | `SELECT original_value FROM bytes WHERE addr = <addr>` |
| List patches (fast) | `SELECT addr FROM bytes WHERE is_patched = 1` |
| Revert one / all | `DELETE FROM bytes WHERE addr = <addr>` / `WHERE is_patched = 1` |

**Unbounded-range warning:** `WHERE addr > X` *without* an upper bound or
`LIMIT` walks every mapped byte from X to end-of-image — millions of rows,
seconds of wall time. Always pair the read with one of `start_addr = X AND
n = N`, `AND addr < B`, or an outer `LIMIT`.

```sql
-- Read 16 bytes as hex
SELECT hex(blob_concat(value))
FROM bytes WHERE start_addr = 0x401000 AND n = 16 ORDER BY addr;

-- Read 64 bytes as BLOB
SELECT blob_concat(value)
FROM bytes WHERE start_addr = 0x401000 AND n = 64 ORDER BY addr;

-- Patch one byte (example: NOP) and a 4-byte little-endian value
UPDATE bytes SET value = 0x90 WHERE addr = 0x401000;
UPDATE bytes SET dword = 0x90909090 WHERE addr = 0x401000;

-- Verify current vs original
SELECT value AS current, original_value AS original
FROM bytes WHERE addr = 0x401000;

-- Revert patch
DELETE FROM bytes WHERE addr = 0x401000;

-- Persist patches explicitly
SELECT save_database();
```

### Binary Search
Use the `byte_search` table for raw bytes/opcodes. It requires `WHERE pattern = ...`; `matched_hex` is an output column, not the search input.

| Column | Description |
|--------|-------------|
| `addr` | Match address |
| `matched_hex` | Matched bytes rendered as hex text |
| `matched_bytes` | Matched bytes as a BLOB |
| `size` | Match size in bytes |
| `pattern` | Hidden required IDA byte pattern input |
| `start_addr` | Hidden optional inclusive lower bound |
| `end_addr` | Hidden optional exclusive upper bound |
| `max_results` | Hidden optional generator cap |

**Pattern syntax (IDA native):**
- `"48 8B 05"` - Exact bytes (hex, space-separated)
- `"48 ? 05"` or `"48 ?? 05"` - `?` = any byte wildcard (whole byte only)
- `"(01 02 03)"` - Alternatives (match any of these bytes)

**Note:** Nibble wildcards and regex are not supported in byte patterns.

**Example:**
```sql
-- Find all matches for a pattern
SELECT addr, matched_hex, size
FROM byte_search
WHERE pattern = '48 8B ? 00'
LIMIT 10;

-- First match only
SELECT printf('0x%llX', addr) AS addr
FROM byte_search
WHERE pattern = 'CC CC CC'
ORDER BY byte_search.addr
LIMIT 1;

-- Search with alternatives
SELECT addr, matched_hex
FROM byte_search
WHERE pattern = 'E8 (01 02 03 04)'
LIMIT 20;
```

**Optimization Pattern: Find functions using specific instruction**

To answer "How many functions use RDTSC instruction?" efficiently:
```sql
-- Count unique functions containing RDTSC (opcode: 0F 31)
SELECT COUNT(DISTINCT fa.func_addr) as count
FROM byte_search b
JOIN func_at(b.addr) fa
WHERE b.pattern = '0F 31';

-- List those functions with names
SELECT DISTINCT
    fa.func_addr,
    fa.name as func_name
FROM byte_search b
JOIN func_at(b.addr) fa
WHERE b.pattern = '0F 31';
```

This is **much faster** than scanning all disassembly lines because:
- `byte_search` uses IDA's native binary search
- `func_at` resolves each hit's owning function(s) directly, tail chunks included, instead of scanning every instruction

### Names & Functions
Use table lookups for address and containing-function metadata. Resolve symbol names to integer EAs before using these patterns.

| Pattern | Description |
|---------|-------------|
| `SELECT name FROM names WHERE addr = :addr LIMIT 1` | Name at address |
| `SELECT name FROM func_at(:addr)` | Function(s) containing address (tail chunks included; one row per owner) |
| `SELECT func_addr FROM func_at(:addr)` | Entry address of the containing function(s) |
| `SELECT chunk_start, chunk_end, is_tail FROM func_at(:addr)` | The chunk containing the address |
| `SELECT chunk_count, size FROM funcs WHERE addr = :func` | Chunk count and total size of a function |
| `SELECT * FROM function_chunks WHERE func_addr = :func` | Every chunk of a function |

Function count and index lookup are table-driven:

```sql
SELECT COUNT(*) AS function_count FROM funcs;
SELECT addr FROM funcs WHERE rowid = 0;
```

### Cross-References
Use the `xrefs` table for incoming, outgoing, and function-scoped edge queries:

```sql
SELECT from_addr, to_addr, type, is_code, from_func
FROM xrefs
WHERE to_addr = 0x401000;

SELECT from_addr, to_addr, type, is_code, from_func
FROM xrefs
WHERE from_addr = 0x401000;

SELECT from_addr, to_addr, type, is_code, from_func
FROM xrefs
WHERE from_func = 0x401000;
```

### Navigation
Use `heads` ordering for defined-item navigation, and SQLite formatting functions for display strings. Address equality/range filters are optimized; `ORDER BY addr` or `ORDER BY addr DESC` is consumed for next/previous-item lookups.

```sql
-- Next defined item
SELECT addr
FROM heads
WHERE addr > 0x401000
ORDER BY addr
LIMIT 1;

-- Previous defined item
SELECT addr
FROM heads
WHERE addr < 0x401000
ORDER BY addr DESC
LIMIT 1;

-- Nullable scalar shape for callers that need one column and one row
SELECT (
  SELECT addr
  FROM heads
  WHERE addr > 0x401000
  ORDER BY addr
  LIMIT 1
) AS next_address;

-- Old IDASQL-style lowercase 0x-prefixed hex formatting
SELECT printf('0x%llx', addr) AS address_hex
FROM heads
LIMIT 10;
```

Segment lookup is table-driven:

```sql
SELECT name
FROM segments
WHERE 0x401000 >= start_addr
  AND 0x401000 < end_addr
LIMIT 1;
```

### Comments
Read address comments through the `comments` table. For a single-query "comment-or-rpt_comment" lookup, use a scalar subquery with COALESCE:

```sql
SELECT (
  SELECT COALESCE(NULLIF(comment, ''), NULLIF(rpt_comment, ''))
  FROM comments
  WHERE addr = 0x401000
  LIMIT 1
) AS comment;
```

Write address comments through the table:

```sql
INSERT INTO comments(addr, comment) VALUES (0x401000, 'regular comment');
INSERT INTO comments(addr, rpt_comment) VALUES (0x401000, 'repeatable comment');
-- Replace an existing comment in place
UPDATE comments SET comment = 'revised comment' WHERE addr = 0x401000;
-- Remove a comment
DELETE FROM comments WHERE addr = 0x401000;
```

Note: for both `names` and `comments`, `INSERT` at an EA that already has a value **replaces** it (IDA permits one name/one comment-slot per address); `UPDATE` is equivalent. For `names`, `SN_CHECK` may auto-disambiguate globally conflicting names (`foo` → `foo_0`) — read back the row to see what was stored.

### Modification
| Surface | Description |
|---------|-------------|
| `applied_types(addr, decl, ordinal, type_name)` | Read, apply, replace, or clear C declarations at addresses. `addr` accepts EA integers, numeric strings, and symbol names for equality writes/filters. |
| `parse_decls(text)` | Import C declarations (struct/union/enum/typedef) into local types |

Preferred SQL write surface for function metadata:
- `UPDATE funcs SET name = '...', prototype = '...' WHERE addr = ...`
- `INSERT INTO names(addr, name) VALUES (..., '...')` or `UPDATE names SET name = '...' WHERE addr = ...`
- `prototype` maps to `applied_types` behavior and invalidates decompiler cache.

### Python Execution
| Function | Description |
|----------|-------------|
| `idapython_snippet(code[, sandbox])` | Execute Python snippet and return captured output text |
| `idapython_file(path[, sandbox])` | Execute Python file and return captured output text |

Runtime guard:

```sql
UPDATE runtime_settings SET value='1' WHERE key='enable_idapython';
```

Examples:

```sql
SELECT idapython_snippet('print("hello from idapython")');
SELECT idapython_file('C:/temp/script.py');
SELECT idapython_snippet('counter = globals().get("counter", 0) + 1; print(counter)', 'alpha');
```

Notes:
- disabled by default until `enable_idapython` is set
- Python exceptions propagate as SQL errors
- `sandbox` isolates/persists Python globals by sandbox key

### Calling idasql from Python (`import idasql`)

Python running in IDA (the console, a script or plugin, or `idapython_snippet`) can query the open
database directly; no server is involved. idasql does not link Python: the module is injected
through IDAPython, and without IDAPython every SQL surface works as before.

```python
import idasql
idasql.available()                                   # True when an idasql engine is loaded
n = idasql.scalar("SELECT COUNT(*) FROM funcs")      # first cell, typed (int here), or None
r = idasql.query("SELECT addr, name FROM funcs WHERE size > ?", 100)   # or (sql, [100])
for f in r:                                          # rows are tuples with attribute access
    print(hex(f.addr), f.name)
r.columns, r.rows, r.warnings, r.elapsed_ms, r.timed_out, r.dicts()
idasql.rows("SELECT * FROM segments")                # list of dicts
idasql.script("SELECT 1; SELECT 2")                  # one Result per statement
try:
    idasql.query("SELECT * FROM nope")
except idasql.Error as e:                            # e.message, e.sql
    print(e)
```

- Cells are typed (INTEGER `int`, REAL `float`, BLOB `bytes`, NULL `None`, TEXT `str`). `?`
  parameters are bound by SQLite, inline or as one list/tuple; text keeps embedded NULs.
- **Main thread only.** In the GUI a call from another thread is forwarded to the main thread and
  waits for it; under idalib (CLI, `--http`, `--mcp`) it fails at once with `idasql.Error`.
- **Nesting.** Python that idasql runs (`idapython_snippet`) can query again (SQL -> Python -> SQL);
  the inner query shares the outer statement's deadline. Running Python again from such a query
  (`idapython_*` inside SQL issued through `idasql`) is refused: IDAPython is not re-entrant there.
- **Settings from Python** follow SQL transactions: an `UPDATE runtime_settings` issued under a
  read-only statement takes effect at once; under a statement that writes, or inside `BEGIN`, it takes
  effect when that commits.
- When the engine goes away (database closed, plugin unloaded), a kept reference raises
  `idasql.Error`. A different module already imported as `idasql` is never replaced.

### Context Awareness (Plugin UI)
| Function | Description |
|----------|-------------|
| `get_ui_context_json()` | Return current UI/widget/context JSON for context-aware prompts (registered everywhere; real UI state in the GUI plugin, a `source:"cli"` stub under idalib/CLI; in the plugin executes through the same queued main-thread path and timeout behavior as other SQL functions) |

```sql
SELECT get_ui_context_json();
```

### Deep Links (IDA 9.4 builds)
| Function | Description |
|----------|-------------|
| `ida_open_link(uri)` | Open an `ida://` link: in-process in the GUI plugin, otherwise in the running IDA 9.4 that has the database open (over IDA's own IPC endpoint). The exact `idb_path` wins; a same-named copy only when that file is not on this machine. Returns 1, or an error with IDA's reason. Gated by `enable_deep_link_navigation`. Never launches IDA (`idasql link open` does) |

Links come from the `deep_links` table (see "Deep Links" under Tables Reference), never from a function.

### Item Analysis
Use `heads` for item classification, size, and raw flags:

```sql
SELECT addr, size, type, flags, disasm
FROM heads
WHERE addr = 0x401000;

SELECT addr, disasm
FROM heads
WHERE type = 'code'
ORDER BY addr
LIMIT 10;
```

### Instruction Details
Use `instructions` and `instruction_operands` for decoded instruction facts:

```sql
-- Instruction type and mnemonic for filtering
SELECT addr, itype, mnemonic
FROM instructions
WHERE func_addr = 0x401000
LIMIT 10;

-- Operand type/value details for one instruction
SELECT operand_index, text, type_code, type_name, value
FROM instruction_operands
WHERE addr = 0x401000
ORDER BY operand_index;

-- Full decoded instruction row shape
SELECT i.addr, i.itype, i.mnemonic, i.size, o.operand_index, o.text, o.type_name, o.value
FROM instructions i
LEFT JOIN instruction_operands o
  ON o.addr = i.addr AND o.addr = 0x401000
WHERE i.addr = 0x401000
ORDER BY o.operand_index;
```

### Decompilation

**When to use `decompile()` vs `pseudocode` table:**
- **Read/show pseudocode** → always start with `SELECT decompile(addr)`. It returns the full function as one text block with per-line prefixes (`/* <addr> */` when available, `/*          */` when no line anchor exists).
- **Local declaration hints** → declaration lines include compact local-variable index hints (`[lv:N]`) so rename operations can target `UPDATE ctree_lvars ... WHERE func_addr = ... AND idx = N` safely.
- **Need fresh output after edits** → use `SELECT decompile(addr, 1)` to force re-decompilation.
- **Need structured line access or comment CRUD** → query/update the `pseudocode` table.

| Function | Description |
|----------|-------------|
| `decompile(addr)` | **PREFERRED** — Full pseudocode with line prefixes (`addr` may be EA, numeric string, or symbol name; available when decompiler surfaces are enabled) |
| `decompile(addr, 1)` | Same output but forces re-decompilation (use after writes/renames) |
| `microcode_error(func_addr[, maturity])` | Why Hex-Rays cannot lift the function to microcode (at `maturity`, default `lvars`), or NULL when it can; such a function has no `microcode` rows |
| `call_arg_addrs(call_addr)` | Return the argument EAs for the call at `call_addr` (Hex-Rays required) |
| `set_union_selection(func_addr, addr, path)` | Set/clear union selection path at EA (`[0,1]` or `0,1`) |
| `set_union_selection_item(func_addr, item_id, path)` | Set/clear union selection path by `ctree.item_id` |
| `set_union_selection_addr_arg(func_addr, addr, arg_idx, path[, callee])` | **PREFERRED** call-arg targeting helper; resolves to item id or errors with hint |
| `call_arg_item(func_addr, addr, arg_idx[, callee])` | Resolve call-arg coordinate to explicit `arg_item_id` |
| `ctree_item_at(func_addr, addr[, op_name[, nth]])` | Resolve generic expression coordinate to explicit `ctree.item_id` |
| `set_union_selection_addr_expr(func_addr, addr, path[, op_name[, nth]])` | Set/clear union selection via generic expression coordinate |
| `get_union_selection(func_addr, addr)` | Read union selection path JSON at EA |
| `get_union_selection_item(func_addr, item_id)` | Read union selection path JSON by `ctree.item_id` |
| `get_union_selection_addr_arg(func_addr, addr, arg_idx[, callee])` | Read union selection JSON via call-arg coordinate |
| `get_union_selection_addr_expr(func_addr, addr[, op_name[, nth]])` | Read union selection JSON via generic expression coordinate |
| `set_numform(func_addr, addr, opnum, spec)` | Set/clear numform directly by EA + operand index |
| `get_numform(func_addr, addr, opnum)` | Read numform JSON directly by EA + operand index |
| `set_numform_item(func_addr, item_id, opnum, spec)` | Set/clear numform by explicit ctree item id |
| `get_numform_item(func_addr, item_id, opnum)` | Read numform JSON by explicit ctree item id |
| `set_numform_addr_arg(func_addr, addr, arg_idx, opnum, spec[, callee])` | Set/clear numform via call-arg coordinate |
| `get_numform_addr_arg(func_addr, addr, arg_idx, opnum[, callee])` | Read numform JSON via call-arg coordinate |
| `set_numform_addr_expr(func_addr, addr, opnum, spec[, op_name[, nth]])` | Set/clear numform via generic expression coordinate |
| `get_numform_addr_expr(func_addr, addr, opnum[, op_name[, nth]])` | Read numform JSON via generic expression coordinate |

Targeting guidance:
- Use `*_addr_arg` helpers for repeated callees and call-site arguments.
- Use `ctree_item_at(..., op_name, nth)` plus `*_addr_expr` helpers for non-call expressions and assignment-side struct/union population stores.
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
-- INSERT acts as upsert at the EA; UPDATE names SET name = ... WHERE addr = ... is equivalent.
INSERT INTO names(addr, name) VALUES (0x401000, 'my_func');
UPDATE ctree_lvars SET name = 'arg0' WHERE func_addr = 0x401000 AND idx = 0;
UPDATE ctree_lvars SET comment = 'seed comment' WHERE func_addr = 0x401000 AND idx = 0;
```

3. Advanced expression/representation helpers (optional in older/minimal runtimes):
```sql
SELECT call_arg_item(0x401000, 0x401020, 0);
SELECT ctree_item_at(0x401000, 0x401030, 'cot_asg', 0);
SELECT set_union_selection_addr_expr(0x401000, 0x401030, '', 'cot_asg', 0);
SELECT set_numform_addr_expr(0x401000, 0x401030, 0, 'clear', 'cot_asg', 0);
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
WHERE addr = 0x140001BD0;
SELECT decompile(0x140001BD0, 1);

-- Hybrid call-arg targeting (recommended): line 0x140001C3E has multiple casted args.
-- Callee is optional. If used, pass exact name from ctree_call_args
-- (for imports this is commonly "__imp_fread", not "fread").
SELECT set_union_selection_addr_arg(0x140001BD0, 0x140001C3E, 0, '[1]');
SELECT get_union_selection_addr_arg(0x140001BD0, 0x140001C3E, 0);

-- If helper returns ambiguity/no-match, resolve explicitly:
SELECT call_item_id, arg_idx, arg_item_id, call_addr AS addr,
       COALESCE(NULLIF(call_obj_name,''), call_helper_name, '') AS callee
FROM ctree_call_args
WHERE func_addr = 0x140001BD0 AND call_addr = 0x140001C3E AND arg_idx = 0
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
SELECT set_union_selection_addr_expr(0x140001BD0, 0x140001C49, '[0]', 'cot_asg', 0);
SELECT set_numform_addr_expr(0x140001BD0, 0x140001C49, 0, 'clear', 'cot_asg', 0);

-- Enum constant rendering in comparisons (e.g., fdwReason == 1 → DLL_PROCESS_ATTACH):
-- PREFERRED: retype the variable to an enum type — the decompiler infers constants automatically
SELECT parse_decls('typedef enum { DLL_PROCESS_DETACH=0, DLL_PROCESS_ATTACH=1 } fdw_reason_t;');
UPDATE ctree_lvars SET type = 'fdw_reason_t' WHERE func_addr = 0x180001050 AND idx = 1;
SELECT decompile(0x180001050, 1);  -- verify enum names appear

-- Non-call expression workflow — advanced per-operand numform control:
-- 1) resolve expression item deterministically by addr + op_name + nth
SELECT ctree_item_at(0x140001BD0, 0x140001CBB, 'cot_eq', 0);
-- 2) apply/read via generic expression helpers (opnum = disassembly operand index)
SELECT set_numform_addr_expr(0x140001BD0, 0x140001CBB, 0, 'enum:operations_e', 'cot_eq', 0);
SELECT get_numform_addr_expr(0x140001BD0, 0x140001CBB, 0, 'cot_eq', 0);
SELECT set_numform_addr_expr(0x140001BD0, 0x140001CBB, 0, 'clear', 'cot_eq', 0);

-- Assignment-style expression (not a call): target with cot_asg
SELECT ctree_item_at(0x140001BD0, 0x140001C49, 'cot_asg', 0);
SELECT set_union_selection_addr_expr(0x140001BD0, 0x140001C49, '', 'cot_asg', 0);
```

Decompiler local and label mutation is table-driven:
- List locals with `ctree_lvars WHERE func_addr = ... ORDER BY idx`.
- Rename/comment locals with `UPDATE ctree_lvars` using `func_addr + idx`.
- Rename labels with `UPDATE ctree_labels` using `func_addr + label_num`.

### File Load
| Function | Description |
|----------|-------------|
| `load_file_bytes(path, file_offset, addr, size)` | Write `size` bytes from host file `path` (at `file_offset`) into the IDB at `addr` |
| `load_file_bytes(path, file_offset, addr, size, patchable)` | Same, with `patchable` controlling whether the write is recorded as a patch |

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
SELECT name, kind, addr
FROM grep
WHERE pattern = 'sub%'
LIMIT 10;

-- Structured table search: contains
SELECT name, kind, full_name
FROM grep
WHERE pattern = 'main'
LIMIT 20;

-- Pagination is ordinary SQL
SELECT name, kind, addr
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
LEFT JOIN funcs f ON g.addr = f.addr
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
| `addr` | INT | Address (for functions, labels, segments) |
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
| `blocks` | `func_addr = X` | O(all blocks) |
| `xrefs` | `to_addr = X` or `from_addr = X` | O(all xrefs) |
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
SELECT addr FROM funcs ORDER BY RANDOM() LIMIT 1;

-- FAST: O(1) - direct index access
SELECT addr
FROM funcs
WHERE rowid = ABS(RANDOM()) % (SELECT COUNT(*) FROM funcs);
```

---

## Common Query Patterns

### Find Most Called Functions

```sql
SELECT f.name, COUNT(*) as callers
FROM funcs f
JOIN xrefs x ON f.addr = x.to_addr
WHERE x.is_code = 1
GROUP BY f.addr
ORDER BY callers DESC
LIMIT 10;
```

### Find Functions Calling a Specific API

```sql
SELECT DISTINCT (SELECT name FROM func_at(from_addr) LIMIT 1) as caller
FROM xrefs
WHERE to_addr = (SELECT addr FROM imports WHERE name = 'CreateFileW');
```

### String Cross-Reference Analysis

```sql
SELECT s.content, (SELECT name FROM func_at(x.from_addr) LIMIT 1) as used_by
FROM strings s
JOIN xrefs x ON s.addr = x.to_addr
WHERE s.content LIKE '%password%';
```

### Function Complexity (by Block Count)

```sql
SELECT (SELECT name FROM funcs WHERE addr = func_addr) as name, COUNT(*) as block_count
FROM blocks
GROUP BY func_addr
ORDER BY block_count DESC
LIMIT 10;
```

### Find Leaf Functions (No Outgoing Calls)

```sql
SELECT f.name, f.size
FROM funcs f
LEFT JOIN disasm_calls c ON c.func_addr = f.addr
GROUP BY f.addr
HAVING COUNT(c.addr) = 0
ORDER BY f.size DESC;
```

### Functions with Deep Call Chains

```sql
SELECT f.name, MAX(cc.depth) as max_depth
FROM disasm_v_call_chains cc
JOIN funcs f ON f.addr = cc.root_func
GROUP BY cc.root_func
ORDER BY max_depth DESC
LIMIT 10;
```

### Security: Dangerous Function Calls with Stack Buffers

```sql
SELECT f.name, c.callee_name, printf('0x%X', c.addr) as addr
FROM funcs f
JOIN ctree_v_calls c ON c.func_addr = f.addr
JOIN ctree_call_args a ON a.func_addr = c.func_addr AND a.call_item_id = c.item_id
WHERE c.callee_name IN ('strcpy', 'strcat', 'sprintf', 'gets', 'memcpy')
  AND a.arg_idx = 0 AND a.arg_var_is_stk = 1
ORDER BY f.name;
```

### Find Zero Comparisons (Potential Error Checks)

```sql
SELECT (SELECT name FROM funcs WHERE addr = func_addr) as func, printf('0x%X', addr) as addr
FROM ctree_v_comparisons
WHERE op_name = 'cot_eq' AND rhs_op = 'cot_num' AND rhs_num = 0;
```

### Calls Inside Loops (Performance Hotspots)

```sql
SELECT f.name, l.callee_name, l.loop_op
FROM ctree_v_calls_in_loops l
JOIN funcs f ON f.addr = l.func_addr
ORDER BY f.name;
```

### malloc with Constant Size

```sql
SELECT (SELECT name FROM funcs WHERE addr = c.func_addr) as func, a.arg_num_value as size
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
JOIN disasm_calls dc ON dc.func_addr = f.addr
JOIN imports i ON dc.callee_addr = i.addr
GROUP BY f.addr, i.module
ORDER BY f.name, api_count DESC;
```

### Find Indirect Calls (Potential Virtual Functions/Callbacks)

```sql
-- Functions with indirect calls (call through register/memory)
SELECT f.name, COUNT(*) as indirect_calls
FROM funcs f
JOIN disasm_calls dc ON dc.func_addr = f.addr
WHERE dc.callee_addr = 0  -- Unresolved target = indirect
GROUP BY f.addr
ORDER BY indirect_calls DESC
LIMIT 20;
```

### String Format Audit (printf-style Vulnerabilities)

```sql
-- Format string usage with variable formats (potential vuln)
SELECT f.name, c.callee_name, printf('0x%X', c.addr) as addr
FROM funcs f
JOIN ctree_v_calls c ON c.func_addr = f.addr
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
LEFT JOIN allocators a ON f.addr = a.func_addr
LEFT JOIN freers r ON f.addr = r.func_addr
WHERE a.alloc_count > 0 AND COALESCE(r.free_count, 0) = 0
ORDER BY allocations DESC;
```

### Control Flow Anomalies

```sql
-- Functions with many basic blocks but few instructions (possibly obfuscated)
SELECT
    f.name,
    f.size,
    COUNT(DISTINCT b.start_addr) as blocks,
    f.size / COUNT(DISTINCT b.start_addr) as avg_block_size
FROM funcs f
JOIN blocks b ON b.func_addr = f.addr
WHERE f.size > 100
GROUP BY f.addr
HAVING COUNT(DISTINCT b.start_addr) > 10
   AND f.size / COUNT(DISTINCT b.start_addr) < 10  -- Very small blocks
ORDER BY blocks DESC;
```

### Return Value Analysis

```sql
-- Functions with multiple return statements (complex control flow)
SELECT f.name, COUNT(*) as return_count
FROM funcs f
JOIN ctree ct ON ct.func_addr = f.addr
WHERE ct.op_name = 'cit_return'
GROUP BY f.addr
HAVING COUNT(*) > 3
ORDER BY return_count DESC;

-- Functions that return 0 (common success pattern)
SELECT DISTINCT (SELECT name FROM funcs WHERE addr = func_addr) as name FROM ctree_v_returns
WHERE return_op = 'cot_num' AND return_num = 0;

-- Functions that return -1 (error sentinel)
SELECT DISTINCT (SELECT name FROM funcs WHERE addr = func_addr) as name FROM ctree_v_returns
WHERE return_op = 'cot_num' AND return_num = -1;

-- Functions that return a specific constant
SELECT DISTINCT (SELECT name FROM funcs WHERE addr = func_addr) as name FROM ctree_v_returns
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
JOIN funcs f ON f.addr = l.func_addr
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
JOIN xrefs x ON x.from_func = f.addr
JOIN segments s ON x.to_addr BETWEEN s.start_addr AND s.end_addr
WHERE s.class = 'DATA' AND x.is_code = 0
GROUP BY f.addr, s.name
ORDER BY data_refs DESC
LIMIT 20;
```

### Exception Handler Detection

```sql
-- Functions with multiple chunks (often due to exception handlers)
SELECT name, chunk_count, size AS total_size
FROM funcs
WHERE chunk_count > 1
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
JOIN malloc_callers m ON f.addr = m.func_addr
JOIN null_checkers n ON f.addr = n.func_addr;
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
    SELECT func_addr as func_addr, COUNT(*) as block_cnt
    FROM blocks
    GROUP BY func_addr
)
SELECT f.name,
       COALESCE(c.call_cnt, 0) as calls,
       COALESCE(b.block_cnt, 0) as blocks,
       COALESCE(c.call_cnt, 0) * COALESCE(b.block_cnt, 0) as complexity
FROM funcs f
LEFT JOIN call_counts c ON f.addr = c.func_addr
LEFT JOIN block_counts b ON f.addr = b.func_addr
ORDER BY complexity DESC
LIMIT 10;
```

### Recursive CTEs (Call Graph Traversal)

```sql
-- Find all functions reachable from main (up to depth 5)
WITH RECURSIVE call_graph AS (
    -- Base case: start from main
    SELECT addr as func_addr, name, 0 as depth
    FROM funcs WHERE name = 'main'

    UNION ALL

    -- Recursive case: follow calls
    SELECT f.addr, f.name, cg.depth + 1
    FROM call_graph cg
    JOIN disasm_calls dc ON dc.func_addr = cg.func_addr
    JOIN funcs f ON f.addr = dc.callee_addr
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
SELECT (SELECT name FROM funcs WHERE addr = func_addr) as caller, MIN(depth) as distance
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
    ROW_NUMBER() OVER (PARTITION BY s.start_addr ORDER BY f.size DESC) as rank
FROM funcs f
JOIN segments s
  ON f.addr >= s.start_addr
 AND f.addr < s.end_addr
WHERE f.size > 0;
```

```sql
-- Running total of function sizes
SELECT
    name,
    size,
    SUM(size) OVER (ORDER BY addr) as cumulative_size
FROM funcs
ORDER BY addr;
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
    (SELECT COUNT(*) FROM blocks WHERE func_addr = f.addr) as block_count,
    (SELECT COUNT(*) FROM disasm_calls WHERE func_addr = f.addr) as outgoing_calls,
    (SELECT COUNT(*) FROM xrefs WHERE to_addr = f.addr AND is_code = 1) as incoming_calls,
    (SELECT COUNT(*) FROM ctree_lvars WHERE func_addr = f.addr) as local_vars
FROM funcs f
JOIN segments s
  ON f.addr >= s.start_addr
 AND f.addr < s.end_addr
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
JOIN funcs f2 ON f1.size = f2.size AND f1.addr < f2.addr
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
    JOIN imports i ON dc.callee_addr = i.addr
    GROUP BY func_addr
) sub
JOIN funcs f ON f.addr = sub.func_addr
WHERE call_count > (
    SELECT AVG(cnt) FROM (
        SELECT COUNT(*) as cnt
        FROM disasm_calls dc
        JOIN imports i ON dc.callee_addr = i.addr
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
SELECT 'dangerous_func' as check_type, (SELECT name FROM funcs WHERE addr = func_addr) as location, callee_name as detail
FROM disasm_calls
WHERE callee_name IN ('strcpy', 'strcat', 'sprintf', 'gets', 'scanf')

UNION ALL

SELECT 'crypto_usage', (SELECT name FROM funcs WHERE addr = func_addr), callee_name
FROM disasm_calls
WHERE callee_name LIKE '%Crypt%' OR callee_name LIKE '%AES%' OR callee_name LIKE '%RSA%'

UNION ALL

SELECT 'network_call', (SELECT name FROM funcs WHERE addr = func_addr), callee_name
FROM disasm_calls
WHERE callee_name IN ('socket', 'connect', 'send', 'recv', 'WSAStartup')

UNION ALL

SELECT 'registry_access', (SELECT name FROM funcs WHERE addr = func_addr), callee_name
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
    JOIN strings s ON x.to_addr = s.addr
    WHERE x.from_func = f.addr
);
```

```sql
-- Functions without any calls (leaf functions, EXISTS version)
SELECT f.name, f.size
FROM funcs f
WHERE NOT EXISTS (
    SELECT 1 FROM disasm_calls dc
    WHERE dc.func_addr = f.addr
)
ORDER BY f.size DESC;
```

---

## Hex Address Formatting

IDA uses integer addresses. For display, use `printf()`:

```sql
-- 32-bit format
SELECT printf('0x%08X', addr) as addr FROM funcs;

-- 64-bit format
SELECT printf('0x%016llX', addr) as addr FROM funcs;

-- Auto-width
SELECT printf('0x%X', addr) as addr FROM funcs;
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
-- Entry points / exports
SELECT * FROM entries;

-- Imported APIs (hints at functionality)
SELECT module, name FROM imports ORDER BY module, name;

-- Interesting strings
SELECT content FROM strings WHERE length > 10 ORDER BY length DESC LIMIT 20;

-- The functions worth reading first
SELECT name, size, cyclomatic, callers FROM func_summary ORDER BY cyclomatic DESC LIMIT 10;
```

### "Find security-relevant code"

```sql
-- Dangerous string functions
SELECT DISTINCT (SELECT name FROM funcs WHERE addr = func_addr) FROM disasm_calls
WHERE callee_name IN ('strcpy', 'strcat', 'sprintf', 'gets');

-- Crypto-related
SELECT * FROM imports WHERE name LIKE '%Crypt%' OR name LIKE '%Hash%';

-- Network-related
SELECT * FROM imports WHERE name LIKE '%socket%' OR name LIKE '%connect%' OR name LIKE '%send%';
```

### "Understand a specific function"

```sql
-- Basic info
SELECT * FROM funcs WHERE addr = 0x401000;

-- Full disassembly
SELECT disasm_func(0x401000);

-- Decompile (if Hex-Rays available)
SELECT decompile(0x401000);

-- Local variables
SELECT name, type, size FROM ctree_lvars WHERE func_addr = 0x401000;

-- What it calls
SELECT callee_name FROM disasm_calls WHERE func_addr = 0x401000;

-- What calls it
SELECT (SELECT name FROM func_at(from_addr) LIMIT 1) FROM xrefs WHERE to_addr = 0x401000 AND is_code = 1;
```

### "Find all uses of a string"

```sql
SELECT s.content, (SELECT name FROM func_at(x.from_addr) LIMIT 1) as function, printf('0x%X', x.from_addr) as location
FROM strings s
JOIN xrefs x ON s.addr = x.to_addr
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
JOIN ctree_v_returns r ON r.func_addr = f.addr
WHERE r.return_num = 0;
```

**"Find functions that return -1 (error pattern)"**
```sql
SELECT DISTINCT f.name FROM funcs f
JOIN ctree_v_returns r ON r.func_addr = f.addr
WHERE r.return_num = -1;
```

**"Functions that return their input argument"**
```sql
SELECT DISTINCT f.name FROM funcs f
JOIN ctree_v_returns r ON r.func_addr = f.addr
WHERE r.returns_arg = 1;
```

**"Functions that return the result of another call (wrappers)"**
```sql
SELECT DISTINCT f.name FROM funcs f
JOIN ctree_v_returns r ON r.func_addr = f.addr
WHERE r.returns_call_result = 1;
```

**"Functions with multiple return statements"**
```sql
SELECT f.name, COUNT(*) as return_count
FROM funcs f
JOIN ctree_v_returns r ON r.func_addr = f.addr
GROUP BY f.addr
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
JOIN ctree_v_returns r ON r.func_addr = f.addr
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
| Function containing an address | `func_at(addr)` (tail chunks included) |
| Non-contiguous functions / their chunks | `funcs WHERE chunk_count > 1`, `function_chunks WHERE func_addr = X` |
| Rank or triage functions | `func_summary` |
| Find who calls what | `xrefs` with `kind = 'call'` (`is_code = 1` also includes jumps) |
| Find data references | `xrefs` with `is_code = 0`; `kind` = `read` / `write` / `offset` |
| Stack frame, stack probes | `function_frames` (`uses_chkstk`) |
| Analyze imports | `imports` |
| Find strings | `strings` |
| Configure string types | `rebuild_strings(minlen, types)` |
| Instruction analysis | `instructions WHERE func_addr = X` |
| View function disassembly | `disasm_func(addr)` (every chunk); `disasm_range(start, end)` for an arbitrary range |
| View decompiled code | `decompile(addr)` |
| UI/screen context questions | `get_ui_context_json()` (live UI in the GUI plugin; CLI returns a stub) |
| Clickable links to IDA locations (IDA 9.4) | `deep_links WHERE resource='functions' AND addr=X`, or JOIN it to `funcs`/`types`/...; render `[name](uri)` |
| Open a result in the user's IDA | `ida_open_link(uri)`, or `idasql link open -- '<uri>'` from a shell |
| Edit decompiler comments | `Resolve writable pseudocode anchor, then UPDATE pseudocode SET comment = '...' WHERE func_addr = X AND addr = Y` |
| AST pattern matching | `ctree WHERE func_addr = X` |
| Call patterns | `ctree_v_calls`, `disasm_calls` |
| Control flow | `ctree_v_loops`, `ctree_v_ifs` |
| Return value analysis | `ctree_v_returns` |
| Functions returning specific values | `ctree_v_returns WHERE return_num = 0` |
| Pass-through functions | `ctree_v_returns WHERE returns_arg = 1` |
| Wrapper functions | `ctree_v_returns WHERE returns_call_result = 1` |
| Variable analysis | `ctree_lvars WHERE func_addr = X` |
| Split a merged store ("Split expression") | `decompiler_splits` (`INSERT ... (addr, piece_size)`) |
| Type information | `types`, `types_members` |
| Function signatures | `types_func_args` (with type classification) |
| Functions by return type | `types_func_args WHERE arg_index = -1` |
| Typedef-aware type queries | `types_func_args` (surface vs resolved) |
| Hidden pointer types | `types_func_args WHERE is_ptr = 0 AND is_ptr_resolved = 1` |
| Manage breakpoints | `breakpoints` (full CRUD) |
| Modify segments | `segments` (INSERT, UPDATE start_addr rebase/end_addr resize/name/class/perm, DELETE) |
| Delete instructions | `instructions` (DELETE converts to unexplored bytes) |
| Create types | `types` (INSERT struct/union/enum) |
| Add struct members | `types_members` (INSERT) |
| Add enum values | `types_enum_values` (INSERT) |
| Modify database | `funcs`, `names`, `comments`, `bookmarks` (INSERT/UPDATE/DELETE) |
| Store custom key-value data | `netnode_kv` (full CRUD, persists in IDB) |
| Read or write the database notepad | `notepad` (`UPDATE notepad SET text = ...`) |
| Read or change IDA options | `ida_config` (`UPDATE ida_config SET value = ... WHERE key = ...`; `persisted` says what is saved) |
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
| `/` | GET | No | Server greeting |
| `/help` | GET | No | API documentation (for LLM discovery) |
| `/query` | POST | Yes* | Execute SQL (body = raw SQL) |
| `/cancel` | POST | Yes* | Cooperatively cancel the in-flight query |
| `/status` | GET | Yes* | Health check |
| `/shutdown` | POST | Yes* | Stop server |

*Auth required only if `--token` was specified.

**Example with curl:**
```bash
# Get API documentation
curl http://localhost:8080/help

# Execute SQL query
curl -X POST http://localhost:8080/query --data-binary "SELECT name, size FROM funcs LIMIT 5"

# With authentication
curl -X POST http://localhost:8080/query \
     -H "Authorization: Bearer mysecret" \
     --data-binary "SELECT * FROM funcs"

# A per-request deadline (absent or 0 = the query_timeout_ms setting)
curl -X POST http://localhost:8080/query -H "X-XSQL-Timeout: 600000" \
     --data-binary "SELECT COUNT(*) FROM ctree"

# Check status
curl http://localhost:8080/status
```

**Response Format (JSON):** the canonical script envelope; a single statement is a one-element `results[]`.
```json
{"success": true, "statement_count": 1, "results": [{"statement_index": 0, "success": true, "columns": ["name", "size"], "rows": [["main", "500"]], "row_count": 1, "elapsed_ms": 0.4, "error": null}], "row_count_total": 1, "elapsed_ms_total": 0.4, "first_error_index": null}
```
A failing statement reports in its own entry (`results[i].error`, `first_error_index`); request-level failures (empty body, bad token) are `{"success": false, "error": "..."}`:
```json
{"success": false, "statement_count": 1, "results": [{"statement_index": 0, "success": false, "columns": [], "rows": [], "row_count": 0, "elapsed_ms": 0.1, "error": "no such table: bad_table"}], "row_count_total": 0, "elapsed_ms_total": 0.1, "first_error_index": 0}
```
