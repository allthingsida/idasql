# Build Performance Benchmark

## Environment

- **OS**: Windows 11
- **CPU**: 24 logical processors
- **Compiler**: MSVC (Visual Studio 17.14)
- **CMake**: 4.0.3
- **Config**: Release
- **Features**: All ON (AI Agent, HTTP, Plugin, CLI, Examples)

## Results (clean rebuild, deps already fetched)

| Branch | Build Time | Speedup |
|--------|-----------|---------|
| `main` (baseline) | ~280 sec (4.7 min) | — |
| `build/faster-windows-build` | ~175 sec (2.9 min) | **~38% faster** |

## Changes Applied

### 1. MSVC `/MP` on dependency targets (~80-85 sec saved)
Dependency libraries (fastmcpp_core, copilot_sdk_cpp, claude_sdk, libagents) were compiling
files sequentially because IDA SDK's `/MP` flag only applies to `ida_add_plugin`/`ida_add_idalib`
targets. Adding `/MP` enables multi-processor compilation within each dependency target.

### 2. Unity build on compatible dependency targets (~20-30 sec saved)
Enabled `UNITY_BUILD` for copilot_sdk_cpp, claude_sdk, and libagents. This merges
translation units to reduce redundant header parsing.

**Note**: fastmcpp_core is excluded because its server files (stdio_server.cpp,
sse_server.cpp, streamable_http_server.cpp) use duplicate anonymous-namespace symbols
that conflict under unity builds.

### 3. Pinned dependency versions with `GIT_SHALLOW` (~5-30 sec saved on configure)
Changed `GIT_TAG main` to specific commit SHAs and added `GIT_SHALLOW TRUE` for both
libxsql and libagents. This avoids re-fetching on every configure and reduces clone size.

### 4. Excluded unused targets
The `debug` tool from claude-agent-sdk-cpp is excluded from the default build via
`EXCLUDE_FROM_ALL`.

## Not Yet Applied (potential further improvements)

- **PCH for idasql targets**: Precompiled headers for CLI/plugin/examples could save
  another ~50-60 sec by eliminating redundant IDA SDK + xsql header parsing.
- **libxsql partial de-header-only**: Moving non-template code to .cpp files would
  reduce per-TU compile cost. Requires upstream libxsql changes.
