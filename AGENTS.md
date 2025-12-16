# Repository Guidelines

## Project Structure & Module Organization

- `src/lib/include/idasql/`: header-only library (IDA APIs exposed as SQLite virtual tables via `xsql::xsql`).
- `src/cli/`: standalone `idasql` command-line tool (separate CMake project; requires IDA SDK).
- `tests/`: GoogleTest suite, SQL fixtures in `tests/sql/`, sample database `tests/testdb.i64`.
- `examples/`, `experiments/`: demos and scratch/prototyping code (may require IDA/Hex-Rays).

## Build, Test, and Development Commands

Prereqs: CMake (>= 3.20; tests need >= 3.27), a C++17 toolchain, IDA SDK (`IDASDK` includes `ida-cmake`), and `xsql::xsql` (`../libxsql` or `-Dxsql_DIR=...`).

- Library target: `cmake -S . -B build` then `cmake --build build --config Release`
- CLI: `cmake -S src/cli -B build/cli` then `cmake --build build/cli --config Release`
  - Run (Windows): `set PATH=%IDASDK%\bin;%PATH%` then `build\cli\Release\idasql.exe -s tests\testdb.i64 -q "SELECT * FROM funcs LIMIT 5"`
- Tests: `cmake -S tests -B build/tests` then `cmake --build build/tests --config Release`
  - Run: `ctest --test-dir build/tests -C Release --output-on-failure`
  - Filter: `build\tests\Release\idasql_tests.exe --gtest_filter=FuncsTable*`

## Coding Style & Naming Conventions

- C++: 4-space indentation, braces on the same line, keep headers self-contained.
- Naming: prefer `snake_case` for files (`*_test.cpp`) and functions; keep public headers as `.hpp`.
- Includes: standard -> third-party -> project; avoid `using namespace` in headers.

## Testing Guidelines

- Framework: GoogleTest (via CMake `FetchContent`).
- Add tests under `tests/` and register new sources in `tests/CMakeLists.txt`.
- Prefer deterministic assertions against `tests/testdb.i64` and/or `tests/sql/*.sql`.

## Commit & Pull Request Guidelines

- Commits: short, imperative subjects (common patterns in history: `Add ...`, `Fix ...`, `Refactor ...`, `Restructure: ...`).
- PRs: explain behavior changes, list build/run steps (platform + IDA version), and include sample SQL output or screenshots for CLI-facing changes.

## Security & Configuration Tips

- Don't commit local IDA SDK installs or proprietary IDA databases; keep any new fixtures in `tests/` and update `.gitignore` if needed.
- `USE_HEXRAYS` controls decompiler-backed features when available.

## Agent Notes (Operational)

- On Windows: `$env:PATH="$env:IDASDK\bin;$env:PATH"` then run with `& "path\to\idasql.exe"` (not `.`).
- Non-fatal warning: the CLI may log `ZMQ error ... not a socket`; ignore if queries still succeed.
- Fast reconnaissance: list tables via `sqlite_master`, inspect columns with `PRAGMA table_info(<table>);`.
- Call graph: resolve `funcs.address` (names may be `_main`), then query `disasm_calls` by `func_addr` (group by `callee_name` to dedupe/count).
- Disassembly: query `instructions` by `func_addr` ordered by `address` (format with `printf('0x%08X', address)`).
- Decompilation (Hex-Rays): `SELECT decompile(<ea>);` or `SELECT line FROM pseudocode WHERE func_addr=<ea> ORDER BY line_num;`.
