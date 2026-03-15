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

+---------+------------------------------------------------+------+--------+-------+
| address | name                                           | size | end_ea | flags |
+---------+------------------------------------------------+------+--------+-------+
| 16      | WerFaultTool.AboutForm::.ctor                  | 13   | 29     | 4096  |
| 32      | WerFaultTool.AboutForm::Dispose                | 30   | 62     | 4096  |
| 64      | WerFaultTool.AboutForm::InitializeComponent    | 295  | 359    | 4096  |
| 400     | WerFaultTool.WerFaultGUI::.ctor                | 936  | 1336   | 4096  |
| 1344    | WerFaultTool.WerFaultGUI::CreateDynamicControls | 231  | 1575   | 4096  |
+---------+------------------------------------------------+------+--------+-------+
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

## Installation

### Coding Agent Plugins

IDASQL skills give your coding agent full control over IDA databases through natural language.

- **Claude Code** -- full plugin with 14 topic-focused skills. Install via `/install-plugin` (see below).
- **GitHub Copilot CLI** -- also supports IDASQL skills. Install the same plugin.
- **Codex (OpenAI)** -- supports skills. Point Codex to the `Skills/` folder from the [idasql-skills](https://github.com/allthingsida/idasql-skills) repository.

#### Prerequisites

1. **IDA Pro** installed with its directory in your PATH (`ida.exe` on Windows, `ida` on macOS/Linux)
2. **idasql** downloaded from [Releases](https://github.com/allthingsida/idasql/releases) and placed next to the IDA binary
3. Verify setup: `idasql --version` should work from command line

#### Install

```bash
claude /install-plugin https://github.com/allthingsida/idasql-skills
```

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

idasql v0.0.12 - SQL interface to IDA databases

Usage: idasql -s <database> [-q <query>] [-f <file>] [-i] [--export <file>]

Options:
  -s <file>            IDA database file (.idb/.i64) for local mode
  --token <token>      Auth token for HTTP/MCP server mode (if server requires it)
  -q <sql>             Execute single SQL query
  -f <file>            Execute SQL from file
  -i                   Interactive REPL mode
  -w, --write          Save database on exit (persist changes)
  --export <file>      Export tables to SQL file (local mode only)
  --export-tables=X    Tables to export: * (all, default) or table1,table2,...
  --http [port]        Start HTTP REST server (default: 8080, local mode only)
  --bind <addr>        Bind address for HTTP/MCP server (default: 127.0.0.1)
  -h, --help           Show this help
  --version            Show version

Examples:
  idasql -s test.i64 -q "SELECT name, address FROM funcs LIMIT 10"
  idasql -s test.i64 -f queries.sql
  idasql -s test.i64 -i
  idasql -s test.i64 --export dump.sql
  idasql -s test.i64 --http 8080

Thank you for using IDA. Have a nice day!
```

</details>

### Building from Source

#### Prerequisites

- CMake 3.20+
- C++17 compiler
- IDA SDK 9.0+ (set `IDASDK` environment variable)

```bash
cmake -S src -B build -DIDASQL_WITH_MCP=OFF
cmake --build build --config Release
```

## Available Tables

30+ virtual tables covering functions, strings, types, cross-references, disassembly, decompilation, and more.

### Core

| Table | Description |
|-------|-------------|
| `funcs` | Functions - name, address, size, end address, flags (INSERT/UPDATE/DELETE) |
| `segments` | Segments - name, start/end address, permissions, class (UPDATE/DELETE) |
| `names` | Named locations - address, name, flags (INSERT/UPDATE/DELETE) |
| `entries` | Entry points - export/program/tls callbacks (ordinal, address, name) |
| `imports` | Imports - module, name, address, ordinal |
| `xrefs` | Cross-references - from/to address, type, is_code |
| `blocks` | Basic blocks - start/end address, func_ea, size |
| `fchunks` | Function chunks - split/tail chunks with owner |
| `instructions` | Disassembly - address, mnemonic, operands, itype, func_addr (DELETE) |
| `heads` | All head items (code + data) - address, size, type, flags, disasm |

### Strings & Bytes

| Table | Description |
|-------|-------------|
| `strings` | Strings - address, content, length, type |
| `bytes` | Raw bytes - address, value, original value, size, type, patch detection |
| `patched_bytes` | Byte patches - original vs patched values, file position |

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
| `comments` | Comments - address, regular and repeatable comments (INSERT/UPDATE/DELETE) |
| `bookmarks` | Bookmarks - slot, address, description (INSERT/UPDATE/DELETE) |
| `breakpoints` | Breakpoints - address, type, enabled, condition (full CRUD) |
| `hidden_ranges` | Collapsed/hidden ranges - start/end, description, header, footer |

### Search

| Table | Description |
|-------|-------------|
| `grep` | Unified entity search table (pattern, name, kind, address, ordinal, parent_name, full_name) |

### Database Info

| Table | Description |
|-------|-------------|
| `welcome` | Database summary/overview - processor, bitness, address range, counts |
| `db_info` | Database metadata key-value pairs |
| `ida_info` | IDA analysis info key-value pairs |
| `problems` | IDA analysis problems/warnings |
| `signatures` | FLIRT signature status |
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
| `grep(pattern, limit, offset)` | Unified entity search function (returns JSON) |
| `decompile(addr)` | Decompile function at address (returns pseudocode) |
| `disasm_at(addr)` | Canonical disassembly listing at address |
| `get_ui_context_json()` | Plugin-only UI context JSON (GUI runtime only) |

### Unified Entity Search

Use the `grep` table for composable SQL searches and `grep()` when JSON output is preferred.

```sql
-- Search anything starting with "Create"
SELECT name, kind, printf('0x%X', address) as addr
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

-- JSON form with pagination
SELECT grep('Create%', 20, 0);
```

## Integration

### HTTP REST API

Stateless HTTP server for simple integration. No protocol overhead.

```bash
idasql -s database.i64 --http 8081
```

```bash
curl http://localhost:8081/status
curl -X POST http://localhost:8081/query -d "SELECT name FROM funcs LIMIT 5"
```

For multiple databases, run separate instances:

```bash
idasql -s malware.i64 --http 8081
idasql -s kernel.i64 --http 8082
```

Endpoints: `/status`, `/help`, `/query`, `/shutdown`

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

The server uses a random port (8100-8199) to avoid conflicts with `--http`.

### MCP Server

For MCP-compatible clients (Model Context Protocol, a standard for AI tool integration):

`--mcp` and `.mcp` are available only when built with `-DIDASQL_WITH_MCP=ON` (default is `OFF`).

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

Tools: `idasql_query` (direct SQL)

## Built With

- **[libxsql](https://github.com/0xeb/libxsql)** - Header-only C++17 library for exposing C++ data structures as SQLite virtual tables. Provides the fluent builder API for defining tables, constraint pushdown, and HTTP thin-client support.

- **[fastmcpp](https://github.com/0xeb/fastmcpp)** - Optional MCP server implementation used when building with `-DIDASQL_WITH_MCP=ON`.

## License

MIT License - see [LICENSE](LICENSE) for details.
