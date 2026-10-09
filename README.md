# IDASQL

**Give any AI agent the ability to understand compiled binaries.**

IDASQL is a SQL interface for IDA Pro databases, created by [Elias Bachaalany](https://github.com/0xeb). It exposes 30+ virtual tables covering functions, cross-references, strings, types, imports, disassembly, and decompilation. Use `/idasql` skills from your coding agent to work fully headlessly -- the agent runs IDA in the background for you -- or open IDA's UI and collaborate with your coding agent to reverse engineer together. No IDAPython. No scripting. Just SQL.

> **Why SQL?** SQL is the universal query language that every AI agent already speaks. IDASQL is agent-agnostic: Claude, ChatGPT, Copilot, Cursor, custom agents, or no agent at all. Any tool that can issue a SQL query can analyze a binary.

- **No indexing required.** IDA already has everything indexed. Queries run instantly against the live database.
- **No scripting needed.** 30+ SQL tables replace hundreds of lines of IDAPython.
- **Headless, GUI, or both.** Run fully headlessly, inside IDA's UI, or connect multiple databases simultaneously.
- **Read and write.** IDASQL is not just a query tool. It allows reading **and writing** the most important aspects of an IDA database: decompilation comments, type recovery, type application (structure and union offsets), detecting type casts, and automatically guessing and updating the correct prototype.

IDASQL supports analyzing, cross-referencing, and transferring annotations between one or more databases at the same time. What you can do is limited only by your imagination and the power of the model you use.

## How It Works

IDA Pro already has its own database format describing functions, strings, cross-references, types, and more. IDASQL maps these internal structures to *live* [SQL virtual tables](https://github.com/0xeb/libxsql). There is no separate exporting or indexing step -- queries execute directly against IDA's database and changes are reflected live.

| Mode | How to start | Best for |
|------|-------------|----------|
| **Standalone CLI** | `idasql -s binary.i64 -i` | Direct SQL, scripting, pipelines |
| **IDA Plugin** | Select `idasql` from IDA's CLI dropdown | SQL inside the GUI, live database |
| **Skill Workflow** | `/idasql:connect` in your coding CLI | AI-driven analysis -- the agent issues SQL queries autonomously |

```
You / Agent  -->  Natural language or SQL
                        |
                  /idasql skills (LLM translates intent to SQL)
                        |
                     IDASQL  -->  IDA database(s)
                        |
                     Results  -->  LLM summarizes & reasons
```

```
$ idasql -s WerFaultTool.exe.i64 -q "SELECT * FROM funcs LIMIT 5"
Opening: WerFaultTool.exe.i64...
Database opened successfully.

+------+-------------------------------------------------+------+----------+-------+
| addr | name                                            | size | end_addr | flags |
+------+-------------------------------------------------+------+----------+-------+
| 16   | WerFaultTool.AboutForm::.ctor                   | 13   | 29       | 4096  |
| 32   | WerFaultTool.AboutForm::Dispose                 | 30   | 62       | 4096  |
| 64   | WerFaultTool.AboutForm::InitializeComponent     | 295  | 359      | 4096  |
| 400  | WerFaultTool.WerFaultGUI::.ctor                 | 936  | 1336     | 4096  |
| 1344 | WerFaultTool.WerFaultGUI::CreateDynamicControls | 231  | 1575     | 4096  |
+------+-------------------------------------------------+------+----------+-------+
5 row(s)
```
*One command. Instant results. No scripting required.*

## Quick Start

After [installing](#installation) the IDASQL CLI and plugin, start your favorite coding agent and begin reverse engineering by prompting. IDASQL runs fully headlessly -- your agent orchestrates IDA Pro: starting, analyzing, decompiling, annotating, saving -- or hosted inside the IDA GUI where you collaborate with your agent in real time.

### Getting Started

Open your favorite coding agent (e.g. Claude Code) and type:

```
/idasql:connect Please open sample_malware.exe in the background and let's analyze it together.
```

The agent starts IDASQL headlessly in the background. From this point on, chat naturally with the database. For instance:

```
/idasql:annotations Fully annotate the function I'm looking at, also use the decompiler skill.
```

The model autonomously reasons about the best approach to understand the function, fully reverse engineers it, and annotates it.

When you're done, ask the agent to save and shut down:

```
/idasql:connect Please save all databases and shut down IDASQL.
```

### Working with Multiple Databases

You can work with two or more databases simultaneously. Prompt your agent:

```
/idasql:connect In this folder, there are many *.exe files. Please use parallel agents to open IDASQL in the background and report how many functions each has.
```

Then follow up:

```
Tell me, how many strings all these databases have in common?
```

The agent works with all databases at the same time. You can cross-reference, compare, and transfer annotations between them.

### Working with IDA UI

Everything above works equally from the IDA GUI. To engage your agent with an open IDA session:

1. In IDA's `idasql>` prompt, type:

   ```
   .http start
   ```

2. IDA outputs:

   ```
   IDASQL HTTP server: http://127.0.0.1:8174
   ```

3. In your coding agent:

   ```
   /idasql:connect Let's work with this database: http://127.0.0.1:8174
   ```

Now IDASQL and your IDA UI are connected and working together.

### Deep Links (IDA 9.4)

With IDA 9.4, answers can link straight into IDA. The `deep_links` table turns any
function, address, string or type into an `ida://` link in IDA's own Copy Link format,
plus one extra parameter, `idb_path`, the database's full path. IDA ignores it; idasql's
click handler uses it to start IDA on the right database. Function links open the
decompiler (disassembly without one), other links open disassembly:

```sql
SELECT f.name, dl.uri
FROM funcs f
JOIN deep_links dl ON dl.resource = 'functions' AND dl.addr = f.addr AND dl.view = 'pseudocode'
ORDER BY f.size DESC LIMIT 5;
```

A coding agent renders these as clickable names. To make a click open IDA:

```
idasql link register        # handle ida:// links (a replaced handler, such as hcli's, is saved)
idasql link unregister      # remove it and restore the saved handler
idasql link open -- "ida:///sample.exe.i64/functions?rva=0x1130&view=pseudocode"
idasql link list            # running IDA 9.4 instances and their databases
```

`idasql link open` steers the running IDA that has the database open. The link's exact
`idb_path` wins; a running IDA with a same-named database is used only when that file
is not on this machine. If no IDA has it open, it starts IDA on the database (`.i64` or
`.idb` only), waits for analysis (`--timeout <seconds>`, 1 to 3600), then navigates. It
refuses to start a second IDA when a running instance does not answer or the database's
unpacked `.id0` exists (IDA may already have it open); `--launch-anyway` overrides that.
A link whose decoded parts hold a control character is refused. `--config <file>` goes
before the verb (`idasql link --config <file> open ...`). Inside IDA,
`SELECT ida_open_link(uri)` navigates the current session.

Whether a click reaches the handler is up to the terminal. Windows Terminal asks before
opening a custom scheme unless it is listed in its `safeUriSchemes` setting
(`"safeUriSchemes": ["ida"]`).

## Installation

### Coding Agent Plugins

IDASQL skills give your coding agent full control over IDA databases through natural language.

- **Claude Code** -- full plugin with 15 topic-focused skills, installed from the [`allthingsida/idasql-skills`](https://github.com/allthingsida/idasql-skills) marketplace.
- **GitHub Copilot CLI** -- also supports IDASQL skills via the same plugin.
- **Codex (OpenAI)** -- supports skills via the same plugin packaging. See the [idasql-skills](https://github.com/allthingsida/idasql-skills) repo for the Codex install steps.

#### Prerequisites

1. **IDA Pro** installed with its directory in your PATH (`ida.exe` on Windows, `ida` on macOS/Linux)
2. **idasql** downloaded from [Releases](https://github.com/allthingsida/idasql/releases). Choose the `ida92`, `ida93`, or `ida94` artifacts matching your IDA version:

   - `*-plugin.zip` is an HCLI-compatible plugin archive containing Windows x86-64, Linux x86-64, and macOS ARM64 binaries.
   - `*-cli-manual.zip` contains the standalone CLI executables, organized by host architecture.
   - `*-arm64-plugin-manual.zip`, available for IDA 9.3 and 9.4, contains Linux ARM64 and, for IDA 9.4, Windows ARM64 plugin binaries for manual installation.

   Plugin binaries are SDK-version-specific; do not reuse an `ida92`, `ida93`, or `ida94` build with another IDA version.
3. Verify setup: `idasql --version` should work from command line

#### Install (Claude Code)

Inside Claude Code, run:

```text
/plugin marketplace add allthingsida/idasql-skills
```

then install the `idasql` plugin from that marketplace. See the [idasql-skills README](https://github.com/allthingsida/idasql-skills#installation) for Codex and other install paths.

#### Skills

| Skill | Description |
|-------|-------------|
| `connect` | Connect to IDA databases: CLI, HTTP server, session bootstrap, skill routing, global contracts. |
| `disassembly` | Query IDA disassembly: functions, segments, instructions, blocks, operands, graphs. |
| `data` | Query IDA strings, bytes, and binary data: search, rebuild, byte patterns. |
| `xrefs` | Analyze IDA cross-references: callers, callees, imports, data refs, grep search. |
| `decompiler` | Decompile IDA functions: pseudocode, ctree AST, local variables, labels. |
| `annotations` | Edit IDA databases: comments, renames, types, bookmarks, enum/struct rendering. |
| `types` | IDA type system: create/modify/apply structs, unions, enums, typedefs, parse_decls. |
| `debugger` | IDA debugger: breakpoints, byte patching, conditions, patch inventory. |
| `storage` | Persistent key-value storage in IDA databases via netnode_kv. |
| `idapython` | Execute IDAPython via idasql: snippets, sandbox, output capture. |
| `functions` | Complete idasql SQL function reference catalog. |
| `analysis` | Analyze IDA binaries: triage, security audit, crypto/network detection, multi-table queries. |
| `resource` | Re-source IDA binaries: recursive annotation, structure recovery, type reconstruction. |
| `ui-context` | Capture live IDA UI context: screen, selection, widget focus, address anchors. |

#### Example Prompts

```
/idasql:analysis analyze this binary; tell me the most called functions.
/idasql:data find functions that reference "password" strings and rank by xrefs.
/idasql:xrefs show callers of CreateFileW and summarize error handling.
/idasql:data identify suspicious hardcoded URLs and the functions that reference them.
```

*The `/idasql` skills drive analysis from your coding CLI -- no IDAPython scripting required.*

<details>
<summary>CLI Help</summary>

```
$ idasql
Error: Database path required (-s)

idasql v0.0.19 - SQL interface to IDA databases
Copyright (c) 2024-2026 Elias Bachaalany

Usage: idasql -s <file> [-q <query>] [-f <file>] [-i] [--export <file>]

Options:
  -s <file>            IDA database (.idb/.i64) OR raw binary (.exe/.dll/firmware/etc.)
                       - raw binaries trigger fresh idalib analysis and string-list rebuild
                       - legacy 32-bit .idb files upgrade to .i64 and require an explicit reopen
  --token <token>      Auth token for HTTP server mode (MCP has no auth)
  -q <sql>             Execute SQL query or semicolon-separated script
  -f <file>            Execute SQL from file
  -i                   Interactive REPL mode
  -w, --write          Save database on exit (persist changes)
  --export <file>      Export tables to SQL file (local mode only)
  --export-tables=X    Tables to export: * (all, default) or table1,table2,...
  --http [port]        Start HTTP REST server (default: 8080, local mode only)
  --bind <addr>        Bind address for HTTP/MCP server (default: 127.0.0.1)
  --mcp [port]         Start MCP server (default: random port, use in -i mode)
                       Or use .mcp start in interactive mode
  -h, --help           Show this help
  --version            Show version

  idasql link <verb>   ida:// deep links (no database needed):
                       open <uri> | list | status | register | unregister | source | config
                       `idasql link --help` for details

Examples:
  idasql -s test.i64 -q "SELECT name, size FROM funcs LIMIT 10"
  idasql -s test.i64 -f queries.sql
  idasql -s test.i64 -i
  idasql -s test.i64 --export dump.sql
  idasql -s test.i64 --http 8080
  idasql -s sample.exe --http            # raw PE: idalib auto-analyzes, then serves SQL (default port 8080)
  idasql -s firmware.bin -q "SELECT * FROM binary"
  idasql -s test.i64 --mcp 9000
```

Legacy 32-bit `.idb` inputs are upgraded by idalib to a sibling `.i64`. When that
happens, idasql exits before serving SQL, returns exit code `3`, and prints one
JSON object to stdout with `status:"upgraded"` and `reopen_with`. Repeat the same
operation with `-s <reopen_with>`.

</details>

### Building from Source

#### Prerequisites

- CMake 3.20+
- C++20 compiler
- IDA SDK 9.0+ (set `IDASDK` environment variable)

```bash
cmake -S . -B build -DIDASQL_WITH_MCP=ON -DIDASQL_BUILD_EXAMPLES=OFF
cmake --build build --config Release
```

Useful CMake switches:

| Switch | Default | Description |
|--------|---------|-------------|
| `IDASQL_WITH_MCP` | `ON` | Build MCP server support via `fastmcpp`. Disable for a smaller/offline build or when you do not need `--mcp` / `.mcp`. |
| `IDASQL_BUILD_CLI` | `ON` | Build the standalone `idasql` command-line tool. |
| `IDASQL_BUILD_PLUGIN` | `ON` | Build the IDA plugin. |
| `IDASQL_BUILD_EXAMPLES` | `ON` | Build the example programs under `examples/`. |
| `IDASQL_TARGET_IDA_VERSION` | `>=9.0` | IDA version or range written to the generated plugin manifest. Release packaging sets an exact version such as `9.3`. |
| `IDASQL_IDA_CMAKE_GIT_TAG` | `main` | Standalone ida-cmake revision. Release CI supplies the reviewed commit SHA. |
| `IDASQL_LIBXSQL_GIT_TAG` | `main` | Standalone libxsql revision when no parent or sibling target is available. Release CI supplies the reviewed commit SHA. |
| `IDASQL_FASTMCPP_GIT_TAG` | `main` | fastmcpp revision when MCP support fetches it. Release CI supplies the reviewed commit SHA. |

Notes:

- Hex-Rays support is always compiled in and detected at runtime. If Hex-Rays is unavailable, decompiler-backed tables/functions are simply not registered.
- HTTP REST support is always compiled in; use `--http` from the CLI or `.http start` from the REPL/plugin CLI.
- IDAPython SQL execution is compiled in but disabled by default at runtime. Enable it per session with `UPDATE runtime_settings SET value='1' WHERE key='enable_idapython';`.
- `IDASQL_WITH_MCP=ON` fetches `fastmcpp`; `OFF` removes MCP support and the `--mcp` / `.mcp` commands.
- `XSQL_WITH_THINCLIENT` is forced `ON`, and `HTTPLIB_USE_OPENSSL_IF_AVAILABLE` is forced `OFF` because IDASQL uses local plain HTTP.

## Available Tables

30+ virtual tables covering functions, strings, types, cross-references, disassembly, decompilation, and more.

### Core

| Table | Description |
|-------|-------------|
| `funcs` | Functions - name, addr, size (all chunks), end addr (entry chunk), flags, chunk_count (INSERT/UPDATE/DELETE) |
| `segments` | Segments - name, start/end addr, permissions, class (INSERT/UPDATE/DELETE) |
| `names` | Named locations - addr, name, flags (INSERT/UPDATE/DELETE) |
| `entries` | Entry points / exports - export/program/tls callbacks (ordinal, addr, name) |
| `imports` | Imports - module, name, addr, ordinal |
| `xrefs` | Cross-references - from/to addr, type, is_code |
| `blocks` | Basic blocks - start/end addr, func_addr, size |
| `function_chunks` | Every chunk of every function, one row per owner (shared tails listed under each owner); fast `WHERE func_addr = X` |
| `func_at(addr)` | Table-valued: the function(s) owning an address, tail chunks included (`SELECT name FROM func_at(0x401000)`) |
| `fchunks` | Raw function chunk list - one row per chunk, `owner` = primary owner |
| `instructions` | Disassembly - addr, mnemonic, operands, itype, func_addr (UPDATE operand format_spec / DELETE) |
| `instruction_operands` | Normalized instruction operands - operand_index, text, type, value; optimized by `addr` and `func_addr` |
| `heads` | All head items (code + data) - optimized address lookup/range navigation |

### Strings & Bytes

| Table | Description |
|-------|-------------|
| `strings` | Strings - addr, content, length, type |
| `bytes` | Raw bytes - `value`/`word`/`dword`/`qword` writable (UPDATE patches, DELETE reverts), `original_value`, `is_patched` (fast patch enumeration via `WHERE is_patched = 1`) |

### Decompiler

| Table | Description |
|-------|-------------|
| `pseudocode` | Decompiled pseudocode via Hex-Rays |
| `ctree` | Hex-Rays ctree AST nodes |
| `ctree_lvars` | Local variables from Hex-Rays decompilation |
| `ctree_call_args` | Hex-Rays call argument details per call site |
| `ctree_labels` | Hex-Rays ctree labels (goto targets) |

### Types

| Table | Description |
|-------|-------------|
| `types` | Type library - structs, unions, enums with members (INSERT/UPDATE/DELETE) |
| `types_members` | Struct/union member details (INSERT/UPDATE/DELETE) |
| `types_enum_values` | Enum member values (INSERT/UPDATE/DELETE) |
| `types_func_args` | Function type argument details |
| `local_types` | Local type library entries |

### Annotations

| Table | Description |
|-------|-------------|
| `comments` | Comments - addr, regular and repeatable comments (INSERT/UPDATE/DELETE) |
| `bookmarks` | Bookmarks - slot, addr, description (INSERT/UPDATE/DELETE) |
| `breakpoints` | Breakpoints - addr, type, enabled, condition (full CRUD) |
| `hidden_ranges` | Collapsed/hidden ranges - start/end, description, header, footer |

### Search

| Table | Description |
|-------|-------------|
| `grep` | Unified entity search table (pattern, name, kind, addr, ordinal, parent_name, full_name) |

### Database Info

| Table | Description |
|-------|-------------|
| `binary` | Database summary/overview - processor, bitness, address range, counts |
| `deep_links` | IDA 9.4: `ida://` link for a resource + address, or a type name |
| `deep_link_parse` | IDA 9.4: a link's parts, validated with IDA's rules |
| `db_info` | Database metadata key-value pairs |
| `ida_info` | IDA analysis info key-value pairs |
| `problems` | IDA analysis problems/warnings |
| `signatures` | FLIRT signatures: list with match counts, `INSERT` applies one, `DELETE` removes a planned one |
| `available_signatures` | The `.sig` files IDA would find for this processor |
| `fixups` | Fixup/relocation entries |
| `mappings` | Address space mappings |

### Storage

| Table | Description |
|-------|-------------|
| `netnode_kv` | Persistent key-value storage (netnode) |

### Analysis

| Table | Description |
|-------|-------------|
| `disasm_calls` | Call graph - caller/callee pairs per function |
| `disasm_loops` | Loop detection - header blocks and back edges |

### SQL Functions

| Function | Description |
|----------|-------------|
| `decompile(addr)` | Decompile function at address (returns pseudocode) |
| `disasm_at(addr)` | Canonical disassembly listing at address |
| `disasm_func(addr)` | Full function listing - every chunk, entry chunk first, tail chunks after a separator line |
| `get_ui_context_json()` | UI context JSON: live in the GUI plugin; a "not applicable" stub under CLI/idalib |
| `ida_open_link(uri)` | IDA 9.4: open a deep link (in-process in the GUI plugin, otherwise in the running IDA that has the database open) |

### Unified Entity Search

Use the `grep` table for composable SQL searches over named functions, labels,
segments, types, and members.

```sql
-- Search anything starting with "Create"
SELECT name, kind, printf('0x%X', addr) as addr
FROM grep
WHERE pattern = 'Create%'
LIMIT 20;

-- Search anywhere in name (plain text performs a contains search)
SELECT name, kind, full_name
FROM grep
WHERE pattern = 'File'
  AND kind IN ('function', 'import')
LIMIT 20;

-- Find struct members
SELECT name, parent_name, full_name
FROM grep
WHERE pattern = 'dw%'
  AND kind = 'member';

-- Pagination
SELECT name, kind, full_name
FROM grep
WHERE pattern = 'Create%'
ORDER BY kind, name
LIMIT 20 OFFSET 20;
```

## Integration

### HTTP REST API

Stateless HTTP server for simple integration. No protocol overhead.

```bash
idasql -s database.i64 --http 8080
```

```bash
curl http://localhost:8080/status
curl -X POST http://localhost:8080/query --data-binary "SELECT name FROM funcs LIMIT 5"
curl -X POST http://localhost:8080/query --data-binary "SELECT * FROM binary; SELECT COUNT(*) FROM funcs;"
```

All `/query` responses use the canonical script envelope; a single statement is an array of one entry:

```
{
  "success": true,
  "statement_count": <N>,
  "results": [
    { "statement_index": 0, "success": true, "columns": [...], "rows": [...], "row_count": <N>, "elapsed_ms": <ms>, "error": null },
    ...
  ],
  "row_count_total": <N>,
  "elapsed_ms_total": <ms>,
  "first_error_index": null
}
```

Fail-fast is the default; pass `continue_on_error=true` (e.g. `?continue_on_error=1`) to run every statement regardless of earlier failures. Each `results[i].error` is canonical for per-statement failures; `first_error_index` points at the earliest failure or is `null`. On splitter failure (e.g. an unterminated quote) the response is `success:false`, `statement_count:0`, `results:[]`, plus a top-level `parse_error`.

For multiple databases, run separate instances:

```bash
idasql -s malware.i64 --http 8080
idasql -s kernel.i64 --http 8082
```

Endpoints: `/status`, `/help`, `/query`, `/cancel`, `/shutdown`

#### HTTP Server from REPL

Start an HTTP server interactively from the REPL or IDA plugin CLI:

```
idasql -s database.i64 -i
idasql> .http start
HTTP server started on port 8142
URL: http://127.0.0.1:8142
...
Press Ctrl+C to stop and return to REPL.
```

In IDA plugin (non-blocking):
```
idasql> .http start
HTTP server started on port 8142
idasql> .http stop
HTTP server stopped
```

The server uses a random port (8100-8999) to avoid conflicts with `--http`.

### Autostart (Pinning)

`.pin` persists a server preference in the IDB (netnode `$ idasql config`) so the
**IDA plugin auto-starts** an HTTP or MCP server whenever that database is opened,
handy for multi-instance setups where each database keeps a stable, known port.

```
idasql> .pin set http 8080        # pin HTTP at 127.0.0.1:8080 (autostart on)
idasql> .pin set mcp 0.0.0.0 9500 # bind override + port (port optional; omit or 0 = fresh random port each launch)
idasql> .pin list                 # show pinned config
idasql> .pin off http             # disable autostart but keep host/port
idasql> .pin clear all            # remove all pins
```

After pinning, reopening the database auto-starts the server; you'll see this
in the IDA output window on load:

```
IDASQL v0.0.19: Query engine initialized
IDASQL CLI: Installed
IDASQL: autostart -> IDASQL HTTP server: http://127.0.0.1:8099
Type '.http stop' to stop the server.
```

`.pin` (or `.pin list`) shows the current configuration for both services:

```
idasql> .pin
Autostart pins:
  http 127.0.0.1:8099  (autostart: on)
  mcp  (not set)
```

- **Autostart-on-load happens only in the IDA plugin.** The `.pin` command itself
  works in both the CLI and the plugin (the CLI just reads/writes the pin).
- `.http start` / `.mcp start` with **no explicit port** reuse the pinned host/port.
- From the CLI, `.pin` changes persist only when started with `-w/--write`
  (like any other IDB edit).

### MCP Server

For MCP-compatible clients (Model Context Protocol, a standard for AI tool integration):

`--mcp` and `.mcp` are available when built with `-DIDASQL_WITH_MCP=ON`, which is the default. Build with `-DIDASQL_WITH_MCP=OFF` to omit MCP support.

```bash
# Standalone mode
idasql -s database.i64 --mcp
idasql -s database.i64 --mcp 9500  # specific port

# Or in interactive mode
idasql -s database.i64 -i
.mcp start
```

Configure your MCP client:

```json
{
  "mcpServers": {
    "idasql": { "url": "http://127.0.0.1:<port>/sse" }
  }
}
```

Tools: `idasql_query` (direct SQL query or semicolon-separated script)

## The xsql family

IDASQL is part of a family of tools that expose different binary-analysis and
debug-information platforms through the **same** SQL surface, all built on the
shared [libxsql](https://github.com/0xeb/libxsql) virtual-table framework. A
query you learn against one tool largely carries over to the others: the
same `SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10` runs everywhere.

**Reverse-engineering platforms**
- **[bnsql](https://github.com/0xeb/bnsql)**: Binary Ninja databases as SQL.
- **[ghidrasql](https://github.com/0xeb/ghidrasql)**: Ghidra databases as SQL.

**Debug info & compiler data**
- **[pdbsql](https://github.com/0xeb/pdbsql)**: Windows PDB symbol files as SQL.
- **[dwarfsql](https://github.com/0xeb/dwarfsql)**: DWARF debug information as SQL.
- **[clangsql](https://github.com/0xeb/clangsql)**: Clang AST as SQL.

**Core**
- **[libxsql](https://github.com/0xeb/libxsql)**: the C++ SQLite virtual-table
  framework every tool above is built on.

## Built With

- **[libxsql](https://github.com/0xeb/libxsql)** - Header-only C++17 library for exposing C++ data structures as SQLite virtual tables. Provides the fluent builder API for defining tables, constraint pushdown, and HTTP thin-client support.

- **[fastmcpp](https://github.com/0xeb/fastmcpp)** - Optional MCP server implementation used when building with `-DIDASQL_WITH_MCP=ON`.

- **[ida-hcli](https://github.com/HexRaysSA/ida-hcli)** (MIT, Hex-Rays SA) - the `idasql link` IPC client, launch and URL-handler behavior is reimplemented in C++ from hcli's; idasql does not need hcli installed.

## License and Terms of Use

In short: you may read, build, evaluate, benchmark, package, and use unmodified idasql, including commercially, if you preserve notices and follow the license terms. You may fork or patch it to prepare bug fixes, optimizations, features, tests, or documentation improvements for contribution back within the license's contribution-purpose rules.

You may not maintain a divergent private fork, port, rebrand, clone, API-compatible replacement, competing implementation, or use idasql as AI input to recreate or improve a derivative implementation without prior written permission from Elias Bachaalany. Independent implementations that are not copied from, materially derived from, or substantially informed by idasql in the license's defined sense are not prohibited.

Permission requests: open a GitHub issue at [allthingsida/idasql/issues](https://github.com/allthingsida/idasql/issues).

If idasql materially informs a distributed project, preserve the human origin: credit idasql and Elias Bachaalany visibly in your README/docs and in About/credits UI when applicable. The license includes an examples/FAQ section for common allowed and permission-required uses. Third-party dependencies (libxsql, the IDA SDK, and their transitive dependencies) remain under their own licenses.

See the full [Human-Origin Source License v1.0](LICENSE).
