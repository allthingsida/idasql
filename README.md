# IDASQL

**Ask your AI agent about any binary open in IDA Pro, in plain English. It answers from the live database.**

<p align="center">
  <a href="https://github.com/allthingsida/idasql/releases/latest"><img alt="Download IDASQL" src="https://img.shields.io/badge/Download-IDASQL-1e6fd9?style=for-the-badge"></a>
  <a href="https://paypal.me/EliasBachaalany"><img alt="Donate with PayPal" src="https://img.shields.io/badge/Donate-PayPal-0070e0?style=for-the-badge&logo=paypal&logoColor=white"></a>
  <a href="https://buymeacoffee.com/0xeb"><img alt="Buy Me a Coffee" src="https://img.shields.io/badge/Buy_Me_a_Coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black"></a>
  <a href="https://github.com/allthingsida/idasql"><img alt="Star IDASQL on GitHub" src="https://img.shields.io/github/stars/allthingsida/idasql?style=for-the-badge&logo=github&label=Star&color=24292f"></a>
</p>

> [!TIP]
> **You don't need to know SQL.** You ask in plain English: "who calls this function?", "rename
> these and comment them", "what does this binary do?". Your agent writes and runs the SQL for
> you. SQL is simply the language idasql speaks with the agent, one every agent already knows.
> You can type it yourself whenever you want to, but you never have to.

> [!NOTE]
> **idasql exports nothing.** Despite the "sql" in its name, idasql never converts or exports your
> IDB to a SQL database, or to anything else. It is a virtual SQL interface on top of the IDA SDK:
> every query reads your live IDB, and every change goes straight back into it.

IDASQL gives AI coding agents full, live access to IDA databases: 70+ tables covering functions,
xrefs, strings, types, pseudocode and more, all read and write. It works with Claude Code, Copilot
CLI, Codex, or any MCP (Model Context Protocol) client, or anything that speaks HTTP. It is created by
[Elias Bachaalany](https://github.com/0xeb).

<p align="center">
  <a href="https://www.youtube.com/watch?v=OSfuKLWMtAA"><img alt="Watch: Vibe Reverse Engineering #1: IDASQL &amp; the xSQL Concept" src="https://img.youtube.com/vi/OSfuKLWMtAA/hqdefault.jpg" width="480"></a><br>
  <b>▶ Watch: <a href="https://www.youtube.com/watch?v=OSfuKLWMtAA">Vibe Reverse Engineering #1: IDASQL &amp; the xSQL Concept</a></b>
</p>

## Two ways to work

Work **fully headless**, with no IDA window at all, or **right inside the IDA you already have
open**. The agent handles both.

### Headless: no IDA window needed

```
/idasql:connect Open sample.exe in the background and let's analyze it together.
```

The agent runs IDA in the background (`idasql -s`) and analyses raw binaries itself. It opens as
many databases as you like, and saves them when you say so.

### Inside IDA: just open your database

There's nothing to set up in IDA. Open your database as usual, then ask your agent. It finds your
IDA by itself:

> **You:** how many functions in target.dll?

The agent then runs:

```
$ idasql instances                        # every running IDA: target.dll.i64 is pid 4242, no SQL server
$ idasql http start 4242
remote control is off for target.dll.i64 (pid 4242)
turn it on with: idasql remote on 4242   (or .remote on in that IDA)
$ idasql remote on 4242 && idasql http start 4242
remote control on for target.dll.i64 (pid 4242)
http://127.0.0.1:8174
```

It then checks it is talking to the right database, and counts:

> **Agent:** target.dll has 812 functions. That IDA wasn't serving SQL, so I turned on its remote
> control and started an HTTP server on localhost. `idasql remote off 4242` and
> `idasql http stop 4242` undo both.

The whole exchange takes about 30 seconds. The agent switches remote control on only for the
database you asked about.

**Prefer to point the agent yourself?** The classic way works as it always has. In IDA's
`idasql>` prompt type `.http start`. IDA prints `IDASQL HTTP server: http://127.0.0.1:8174` and
copies the connection instructions to the clipboard. Then:

```
/idasql:connect Let's work with this database: http://127.0.0.1:8174
```

Run `.pin http` once, and that database starts its server every time it opens.

## What you get

- **No SQL to learn**: you write plain-language prompts, and the agent writes the queries.
- **[From binary back to source code](#back-to-source)**: take a compiled binary back to **clean, fully recompilable source code**. The agent recovers every name, type, struct and prototype, then writes out source you can build again. See real projects rebuilt this way in [vibe-re](https://github.com/0xeb/vibe-re).
- **[Headless or inside IDA](#two-ways-to-work)**: the agent runs IDA in the background, or [finds the IDA you have open](#find-and-talk-to-any-open-ida) and connects. You can also point it yourself with `/idasql:connect`.
- **[Clickable answers](#clickable-answers)**: function names are `ida://` links that jump IDA to the code (IDA 9.4+).
- **70+ live tables, read and write**: functions, xrefs, strings, types, pseudocode, ctree, microcode, comments, renames, prototypes and patches. Nothing is exported or indexed first.
- **[IDAPython on request](#idapython-by-prompt)**: the agent writes a script and runs it in the IDA you name.
- **MCP server built in**: `idasql -s db.i64 --mcp`, or `.mcp start` inside IDA, and any MCP (Model Context Protocol) client gets an `idasql_query` tool.
- **Pin it and forget it**: run `.pin http` (or `.pin mcp`) once in IDA, and that database serves every time it opens, so your agent connects with no step at all.
- **[Many databases at once](#headless-and-many-databases)**: compare, cross-reference, and move annotations between them.
- **Agent-ready**: 16 skills for Claude Code, Copilot CLI and Codex, plus HTTP and MCP servers for everything else. To see what agents build with it, check out [vibe-re](https://github.com/0xeb/vibe-re), a gallery of agentic "vibe" reverse engineering.
- **[A safety net](#rescue-and-close)**: `idasql rescue` saves the work of a frozen IDA, and `idasql close` ends one cleanly.
- **IDA 9.2 to 9.5** on Windows, Linux and macOS, x64 and ARM64.

## Common misconceptions

| You may have heard | Actually |
|---|---|
| "I have to learn SQL." | No. You ask in plain language, and the agent writes the SQL. |
| "It only reads." | It writes too: renames, comments, types, structs, prototypes, patches, bookmarks, and undo checkpoints. |
| "It exports the database first." | No. Every query runs live against the open database, and every change shows in IDA at once. |
| "It replaces IDA." | It runs on your IDA Pro (9.2 to 9.5) and your license. The pseudocode tables need the Hex-Rays decompiler. |
| "It only works headless" (or "only in the GUI"). | Either, or both, with many databases at once. |
| "It's for Claude only." | Any agent: the skills ship for Claude Code, Copilot CLI and Codex, and HTTP and MCP serve the rest. |
| "It's only for malware." | Any binary IDA opens: drivers, firmware, games, libraries. |
| "The agent will make things up." | Its answers come from queries on your database, and on IDA 9.4+ links let you click through to check each one in IDA. |
| "My binary goes to the cloud." | idasql runs on your machine and its servers listen on localhost only. Your agent's model sees what the agent reads, so pick your agent accordingly. |

## Install in 3 steps

1. **Download** the release for your IDA version from [Releases](https://github.com/allthingsida/idasql/releases) (`ida92`, `ida93`, `ida94` or `ida95`; builds are IDA-version-specific):

   | Archive | What's in it |
   |---|---|
   | `*-plugin.zip` | The HCLI-compatible plugin (Windows x64, Linux x64, macOS ARM64) |
   | `*-cli.zip` | The `idasql` command line, by host architecture |
   | `*-arm64-plugin.zip` | ARM64 plugins, installed by hand: Linux (IDA 9.3+) and Windows (IDA 9.4+) |

2. **Put `idasql` next to IDA**, with IDA's directory on your PATH, then check it with `idasql --version`.
3. **Add the skills** to your agent. In Claude Code or Copilot CLI:

   ```text
   /plugin marketplace add allthingsida/idasql-skills
   ```

   Then install `idasql` from that marketplace. For Codex, see [idasql-skills](https://github.com/allthingsida/idasql-skills#installation).

## See it work

### Find and talk to any open IDA

```
$ idasql instances
PID   HOST    IDA  SQL                    REMOTE  STATE  DATABASE
4242  gui     9.5  http://127.0.0.1:8174  on      ok     target.dll.i64
5150  gui     9.5  -                      off     ok     malware.exe.i64
6001  idalib  9.5  http://127.0.0.1:8123  -       ok     firmware.bin.i64
```

Every IDA on the machine is listed: GUI windows, `idasql -s` sessions, even IDAs without idasql
(9.4+). When one serves no SQL, the agent starts its server, using the same verbs you type in IDA:

| In IDA | From any terminal | From SQL |
|---|---|---|
| `.http start` / `.http stop` | `idasql http start <db\|pid>` / `stop` | `UPDATE ida_instances SET start = 'http' WHERE pid = N` |
| `.mcp start` / `.mcp stop` | `idasql mcp start <db\|pid>` / `stop` | `UPDATE ida_instances SET start = 'mcp' WHERE pid = N` |
| `.remote on` / `.remote off` | `idasql remote on <db\|pid>` / `off` | `UPDATE ida_instances SET remote = 1 WHERE pid = N` |

Remote control is **off by default**, and set per database. Every request appears in that IDA's
Output window with the process that asked. Servers bind to localhost, and no token is ever
handed out. Prefer to connect by hand? `.http start` and a pasted URL work just as before.

### Back to source

Take a compiled binary and get back **clean, fully recompilable source code**: real names, real
types, real structs, and code that builds again.

```
/idasql:re-source Start at the entry point and recover this binary bottom-up: name every function, rename locals, recover the structs behind the pointer arithmetic, and fix the prototypes.
/idasql:types Recover the struct this function fills in, apply it, and show me the pseudocode again.
```

The agent works through the program one function at a time:
1. it decompiles the function;
2. it renames the function and its locals, and comments it;
3. it turns `*(DWORD *)(a1 + 0x10)` patterns into real structs and enums;
4. it applies the types and prototypes, then decompiles again to check that the code reads cleanly.

Everything is saved in your IDA database as it goes. Once no `sub_*` is left, the agent writes the
program out as clean source files, with headers for the recovered types, and builds it again.
[vibe-re](https://github.com/0xeb/vibe-re) collects real binaries rebuilt this way: malware
command-and-control (C2) code, kernel drivers and their typed client libraries.

### Clickable answers

```sql
SELECT f.name, dl.uri FROM funcs f
JOIN deep_links dl ON dl.resource = 'functions' AND dl.addr = f.addr AND dl.view = 'pseudocode'
ORDER BY f.size DESC LIMIT 5;
```

The agent writes these as `[sub_401130](ida:///sample.exe.i64/functions?rva=0x1130&view=pseudocode&idb_path=...)`.
Click one and IDA jumps to its pseudocode. If no IDA has that database open, it starts one on it.
Run `idasql link register` once to handle `ida://` links. Links are for IDA windows; answers
about headless sessions use plain names.

### IDAPython by prompt

> **You:** write an IDAPython script that lists every call to CreateFileW, with the function each
> call sits in, and run it in the target database

The agent writes the script:

```python
import idautils, idc, ida_funcs

target = idc.get_name_ea_simple("CreateFileW")
for xref in idautils.XrefsTo(target):
    print(f"{xref.frm:#x}  {ida_funcs.get_func_name(xref.frm) or '?'}")
```

Then it runs the script inside that IDA through SQL:

```sql
UPDATE runtime_settings SET value = '1' WHERE key = 'enable_idapython';
INSERT INTO idapython_runs(code, show_output) VALUES ('<the script above>', 1);
SELECT success, output, error FROM idapython_runs ORDER BY id DESC LIMIT 1;
```

> **Agent:** CreateFileW is called from 6 places in 4 functions, listed with the address of each
> call. The same list is in that IDA's Output window. Running Python through idasql is off by
> default, so I turned it on for this session.

Every run is a row in `idapython_runs`, holding its output, success and error. A script file works
too (`path` instead of `code`), and a named `sandbox` keeps its globals between runs.

### Headless and many databases

One `/idasql:connect` starts the session:

```
/idasql:connect Open and analyze all the drivers in my c:\malware folder.
```

After that, just talk. You don't need `/idasql:connect` again:

- "Which of them talk to the registry?"
- "How many strings do they have in common?"
- "Rename the dispatch routines in all of them, then save all databases and shut down IDASQL."

The agent runs IDA headless (`idasql -s`), analyses raw binaries itself, and works with every
database at once: compare them, cross-reference them, or move annotations between them.

### SQL, if you want it

Everything above is SQL under the hood, and you can type it yourself too:

```
$ idasql -s target.dll.i64 -q "SELECT name, size FROM funcs ORDER BY size DESC LIMIT 10"
$ idasql -s target.dll -q "SELECT * FROM binary"         # a raw binary is analysed first
$ idasql -s target.dll.i64 -w -q "UPDATE funcs SET name = 'parse_config' WHERE addr = 0x401000"
$ idasql -s target.dll.i64 -i                             # an interactive REPL
```

Results print as tables, `-f` runs a SQL file, and `-w` saves the changes. Writes are plain SQL:
`UPDATE funcs SET name = ...`, `INSERT INTO comments ...`, `UPDATE bytes SET value = ...`.

### Rescue and close

```
$ idasql rescue demo.i64
waiting for the IDA holding ...\demo.i64 to save ...
saved: ...\demo.rescued-20261110-111807.i64

$ idasql close demo.i64 --save
```

`rescue` saves a copy of a database whose IDA has frozen and won't come back: a script stuck in
an endless loop or sleep, a plugin blocked in a call, a hung wait. Your unsaved work comes out
from another terminal while IDA stays frozen. It reaches IDA windows and `idasql -s` sessions
alike, and `--kill` then ends the frozen IDA. An IDA that is only *busy* (a script still calling
IDA, analysis running) may crash if you rescue it, so wait for it, or use `--kill`.
`close` ends a healthy IDA, with `--save` or `--discard`.

## Reference

<details>
<summary><b>Ways to run: CLI, plugin, HTTP, MCP, autostart, remote control</b></summary>

| Mode | Start it with |
|---|---|
| CLI | `idasql -s db.i64 -q "..."`, `-i` (REPL), `-f file.sql`, `-w` (save on exit) |
| Inside IDA | Choose `idasql` in the command-line dropdown, then type SQL or `.help` |
| HTTP | `idasql -s db.i64 --http 8080`, or `.http start` in IDA |
| MCP | `idasql -s db.i64 --mcp`, or `.mcp start` in IDA. The client config is `{"mcpServers": {"idasql": {"url": "http://127.0.0.1:<port>/sse"}}}`, and the tool is `idasql_query` |
| Autostart | `.pin http [bind] [port]` in IDA: the server starts every time this database opens (`.pin`, `.pin off http`, `.pin clear all`) |
| Remote control | `.remote on` in IDA, or `idasql remote on <db\|pid>`: other processes may then start and stop this database's servers |

Querying the HTTP server:

```bash
curl -X POST http://127.0.0.1:8080/query --data-binary "SELECT name FROM funcs LIMIT 5; SELECT COUNT(*) FROM strings;"
```

The other endpoints are `/status`, `/help`, `/cancel` and `/shutdown`. Every `/query` returns one
envelope: `success`, `statement_count`, and `results[]`, each with `columns`, `rows`, `row_count`,
`elapsed_ms` and `error`. Statements stop at the first failure unless you pass
`?continue_on_error=1`. A server bound beyond localhost should get `--token`.

Exit codes for `idasql http|mcp start|stop` and `idasql remote`: 0 done, 1 not found or refused,
2 usage, 3 timed out (IDA busy or frozen), 4 remote control is off. An `idasql -s --http` session
reports the URL it already serves. Other `-s` sessions can't be started from outside.

</details>

<details>
<summary><b>Deep links (IDA 9.4+)</b></summary>

- `deep_links` makes an `ida://` link for any function, address, string or type, in IDA's own
  Copy Link format plus `idb_path`, the database's full path. Function links open the
  decompiler, and the rest open disassembly. `deep_link_parse` takes a link apart.
- `idasql link open -- "<uri>"` steers the running IDA that has the database open, preferring
  the link's exact `idb_path`. If none has it open, it starts IDA (`.i64` / `.idb`), waits for
  analysis (`--timeout`), and navigates. It won't start a second IDA when one doesn't answer or
  the database's `.id0` exists, unless you pass `--launch-anyway`.
- `idasql link register` and `idasql link unregister` manage the click handler. A handler it
  replaces, such as hcli's, is saved and restored. Run `idasql link status` to see the current
  one.
- Inside IDA, `SELECT ida_open_link(uri)` navigates the current session.
- Windows Terminal asks before opening custom schemes unless you add
  `"safeUriSchemes": ["ida"]` to its settings.

</details>

<details>
<summary><b>Tables (70+)</b></summary>

Full columns, write rules and examples are in the
[schema catalog](https://github.com/allthingsida/idasql-skills/blob/main/plugins/idasql/skills/connect/references/schema-catalog.md).

| Area | Tables |
|---|---|
| Code | `funcs`, `func_at()`, `function_chunks`, `fchunks`, `blocks`, `instructions`, `instruction_operands`, `heads`, `data_items`, `segments`, `names`, `entries`, `function_frames`, `switch_tables`, `switch_cases` |
| Graphs | `xrefs`, `data_refs`, `call_graph()`, `shortest_path()`, `cfg_edges`, `dominators`, `post_dominators`, `loops`, `disasm_calls`, `disasm_loops` |
| Data | `strings`, `bytes` (patch with UPDATE), `byte_search`, `imports`, `fixups`, `mappings` |
| Decompiler | `pseudocode`, `ctree`, `ctree_lvars`, `ctree_call_args`, `ctree_labels`, `microcode`, `microcode_operands`, `decompiler_splits` |
| Types | `types`, `types_members`, `types_enum_values`, `types_func_args`, `local_types`, `applied_types`, `struct_member_xrefs`, `type_gaps` |
| Annotations | `comments`, `bookmarks`, `notepad`, `hidden_ranges`, `checkpoints`, `undo_state`, `dirtree_folders`, `dirtree_entries` |
| Search | `grep` (functions, labels, types and members by pattern) |
| IDA and sessions | `binary`, `db_info`, `ida_info`, `ida_config`, `runtime_settings`, `problems`, `signatures`, `available_signatures`, `ida_instances`, `ui_actions`, `idapython_runs`, `deep_links`, `deep_link_parse`, `breakpoints`, `netnode_kv` |

Scalars include `decompile(addr)`, `disasm_at(addr)`, `disasm_func(addr)` and `ida_open_link(uri)`.

```sql
SELECT name, kind, printf('0x%X', addr) AS addr FROM grep WHERE pattern = 'Create%' LIMIT 20;
```

</details>

<details>
<summary><b>Skills (16)</b></summary>

| Skill | For |
|---|---|
| `connect` | Sessions, servers, finding running IDAs, routing |
| `analysis` | Triage, security audit, crypto and network detection |
| `disassembly` | Functions, segments, instructions, blocks, CFG, signatures |
| `decompiler` | Pseudocode, ctree, locals, labels, cleanup |
| `xrefs` | Callers, callees, imports, call graphs |
| `data` | Strings, bytes, byte patterns |
| `types` | Structs, unions, enums, typedefs, applying types |
| `annotations` | Comments, renames, bookmarks, notepad, undo checkpoints |
| `re-source` | Recursive annotation, structure and type recovery |
| `grep` | Find anything by name pattern |
| `deep-links` | Clickable `ida://` answers (9.4+) |
| `idapython` | Run IDAPython; query SQL from IDAPython |
| `ui-context` | What's on screen and selected in IDA |
| `debugger` | Breakpoints, patching, patch inventory |
| `storage` | Key-value storage in the database |
| `functions` | The SQL function catalog |

Try `/idasql:analysis what does this binary do?` or `/idasql:xrefs who calls CreateFileW, and how are errors handled?`

</details>

<details>
<summary><b>CLI help</b></summary>

```
$ idasql --help
idasql v0.0.20 - SQL interface to IDA databases
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

Commands (no database is opened; `idasql <command> --help` for details):
  link <verb>               ida:// deep links: open | status | register | unregister | source | config
  instances [--json]        running IDA instances and the databases they have open
  rescue <db> [--kill]      save a copy of the database a stuck IDA has open
  close <db|url>            end an IDA cleanly: --save or --discard
  http start|stop <db|pid>  start or stop another IDA's HTTP server (needs remote on there)
  mcp start|stop <db|pid>   the same for its MCP server
  remote on|off <db|pid>    let other processes start/stop that IDA's servers

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

Legacy 32-bit `.idb` files are upgraded to a sibling `.i64`: idasql exits with code 3 and prints
`{"status":"upgraded","reopen_with":...}`. Reopen with `-s <reopen_with>`.

</details>

<details>
<summary><b>Building from source</b></summary>

**Prerequisites**

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
| `IDASQL_IDA_CMAKE_GIT_TAG` | Reviewed lock SHA | Standalone ida-cmake revision from `.github/release-revisions.json`. |
| `IDASQL_LIBXSQL_GIT_TAG` | Reviewed lock SHA | Standalone libxsql revision from the same lock when no parent or sibling target is available. |
| `IDASQL_FASTMCPP_GIT_TAG` | Reviewed lock SHA | fastmcpp revision from the same lock when MCP support fetches it. |

Notes:

- Hex-Rays support is always compiled in and detected at runtime. If Hex-Rays is unavailable, decompiler-backed tables/functions are simply not registered.
- HTTP REST support is always compiled in; use `--http` from the CLI or `.http start` from the REPL/plugin CLI.
- IDAPython SQL execution is compiled in but disabled by default at runtime. Enable it per session with `UPDATE runtime_settings SET value='1' WHERE key='enable_idapython';`.
- `IDASQL_WITH_MCP=ON` fetches `fastmcpp`; `OFF` removes MCP support and the `--mcp` / `.mcp` commands.
- `XSQL_WITH_THINCLIENT` is forced `ON`, and `HTTPLIB_USE_OPENSSL_IF_AVAILABLE` is forced `OFF` because IDASQL uses local plain HTTP.

</details>

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

- **[ida-hcli](https://github.com/HexRaysSA/ida-hcli)** (MIT, Hex-Rays SA) - the `idasql link` IPC client, launch and URL-handler behavior is reimplemented in C++ from hcli's; idasql does not need hcli installed. Its MIT notice is in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), also shipped in every release archive.

## Support IDASQL

IDASQL is free to use, including commercially. If it saves you time in IDA, a donation funds the next release, and a star helps other reverse engineers find it.

<p>
  <a href="https://paypal.me/EliasBachaalany"><img alt="Donate with PayPal" src="https://img.shields.io/badge/Donate-PayPal-0070e0?style=for-the-badge&logo=paypal&logoColor=white"></a>
  <a href="https://buymeacoffee.com/0xeb"><img alt="Buy Me a Coffee" src="https://img.shields.io/badge/Buy_Me_a_Coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black"></a>
  <a href="https://github.com/allthingsida/idasql"><img alt="Star IDASQL on GitHub" src="https://img.shields.io/github/stars/allthingsida/idasql?style=for-the-badge&logo=github&label=Star&color=24292f"></a>
</p>

Bug reports with a database and the exact query are just as valuable. Most fixes in this release started that way.

## License and Terms of Use

In short: you may read, build, evaluate, benchmark, package, and use unmodified idasql, including commercially, if you preserve notices and follow the license terms. You may fork or patch it to prepare bug fixes, optimizations, features, tests, or documentation improvements for contribution back within the license's contribution-purpose rules.

You may not maintain a divergent private fork, port, rebrand, clone, API-compatible replacement, competing implementation, or use idasql as AI input to recreate or improve a derivative implementation without prior written permission from Elias Bachaalany. Independent implementations that are not copied from, materially derived from, or substantially informed by idasql in the license's defined sense are not prohibited.

Permission requests: open a GitHub issue at [allthingsida/idasql/issues](https://github.com/allthingsida/idasql/issues).

If idasql materially informs a distributed project, preserve the human origin: credit idasql and Elias Bachaalany visibly in your README/docs and in About/credits UI when applicable. The license includes an examples/FAQ section for common allowed and permission-required uses. Third-party dependencies (libxsql, the IDA SDK, and their transitive dependencies) remain under their own licenses.

See the full [Human-Origin Source License v1.0](LICENSE).
