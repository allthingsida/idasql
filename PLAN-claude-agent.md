# Implementation Plan: Natural Language Support for IDASQL

## Overview

Add Claude AI integration to idasql, enabling natural language queries that get translated to SQL and executed against IDA databases. This works at all levels:

1. **CLI parameter mode**: `idasql -s test.i64 --prompt "Find malloc calls in loops"`
2. **CLI interactive mode**: `idasql -s test.i64 -i --claude-code`
3. **IDA Plugin CLI**: Register a `cli_t` so users can type NL queries in IDA's command line
4. **Headless testing**: Test driver support for automated Claude integration testing

## 1. Add Submodule

```bash
cd idasql
git submodule add https://github.com/0xeb/claude-agent-sdk-cpp.git external/claude-agent-sdk-cpp
```

## 2. System Prompt

**Source**: `../kb-ati/idasql/idasql-agent.md` (1500+ lines)

This comprehensive document covers:
- All IDASQL tables with column definitions
- SQL functions (disasm, decompile, set_name, etc.)
- Performance rules (constraint pushdown for ctree/instructions)
- Common query patterns (security audits, call graphs, etc.)
- Advanced SQL (CTEs, window functions, recursive queries)

### Embed as C++ Header

Create a script to convert the markdown to a C++ raw string literal header:

**`scripts/embed_prompt.py`**:
```python
#!/usr/bin/env python3
"""
Converts idasql-agent.md to a C++ header with embedded raw string literal.
Run: python scripts/embed_prompt.py prompts/idasql_agent.md src/common/idasql_agent_prompt.hpp
"""

import sys
import os
from datetime import datetime

def embed_prompt(input_path: str, output_path: str):
    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Use a unique delimiter that won't appear in the markdown
    delimiter = "IDASQL_AGENT_PROMPT"

    header = f'''// Auto-generated from {os.path.basename(input_path)}
// Generated: {datetime.now().isoformat()}
// DO NOT EDIT - regenerate with: python scripts/embed_prompt.py

#pragma once

namespace idasql {{

inline constexpr const char* SYSTEM_PROMPT = R"{delimiter}(
{content}
){delimiter}";

}} // namespace idasql
'''

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(header)

    print(f"Generated {output_path} ({len(content)} bytes)")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.md> <output.hpp>")
        sys.exit(1)
    embed_prompt(sys.argv[1], sys.argv[2])
```

**Generated header** (`src/common/idasql_agent_prompt.hpp`):
```cpp
// Auto-generated from idasql_agent.md
// Generated: 2024-12-26T...
// DO NOT EDIT - regenerate with: python scripts/embed_prompt.py

#pragma once

namespace idasql {

inline constexpr const char* SYSTEM_PROMPT = R"IDASQL_AGENT_PROMPT(
# IDASQL Agent Guide

A comprehensive reference for AI agents to effectively use IDASQL...
...entire markdown content...
)IDASQL_AGENT_PROMPT";

} // namespace idasql
```

### Build Integration (Conditional Regeneration)

The script only regenerates if the `.hpp` is older than the `.md` or doesn't exist:

**`scripts/embed_prompt.py`** (updated):
```python
#!/usr/bin/env python3
"""
Converts idasql-agent.md to a C++ header with embedded raw string literal.
Only regenerates if the hpp is older than the md or doesn't exist.

Run: python scripts/embed_prompt.py prompts/idasql_agent.md src/common/idasql_agent_prompt.hpp
"""

import sys
import os
from datetime import datetime

def needs_regeneration(input_path: str, output_path: str) -> bool:
    """Check if output needs regeneration based on file timestamps."""
    if not os.path.exists(output_path):
        return True
    input_mtime = os.path.getmtime(input_path)
    output_mtime = os.path.getmtime(output_path)
    return input_mtime > output_mtime

def embed_prompt(input_path: str, output_path: str, force: bool = False):
    if not force and not needs_regeneration(input_path, output_path):
        print(f"Skipping {output_path} (up-to-date)")
        return False

    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()

    delimiter = "IDASQL_AGENT_PROMPT"

    header = f'''// Auto-generated from {os.path.basename(input_path)}
// Generated: {datetime.now().isoformat()}
// DO NOT EDIT - regenerate with: python scripts/embed_prompt.py

#pragma once

namespace idasql {{

inline constexpr const char* SYSTEM_PROMPT = R"{delimiter}(
{content}
){delimiter}";

}} // namespace idasql
'''

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(header)

    print(f"Generated {output_path} ({len(content)} bytes)")
    return True

if __name__ == "__main__":
    force = "--force" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--force"]

    if len(args) != 2:
        print(f"Usage: {sys.argv[0]} [--force] <input.md> <output.hpp>")
        sys.exit(1)
    embed_prompt(args[0], args[1], force)
```

**CMakeLists.txt** (pre-build step):
```cmake
# Regenerate prompt header only if md is newer or hpp doesn't exist
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND AND IDASQL_WITH_CLAUDE_AGENT)
    set(PROMPT_MD "${CMAKE_CURRENT_SOURCE_DIR}/prompts/idasql_agent.md")
    set(PROMPT_HPP "${CMAKE_CURRENT_SOURCE_DIR}/src/common/idasql_agent_prompt.hpp")

    add_custom_command(
        OUTPUT ${PROMPT_HPP}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/embed_prompt.py
            ${PROMPT_MD} ${PROMPT_HPP}
        DEPENDS ${PROMPT_MD}
        COMMENT "Checking/regenerating idasql_agent_prompt.hpp"
    )

    add_custom_target(generate_prompt DEPENDS ${PROMPT_HPP})
endif()
```

### Git Workflow

The generated `.hpp` file is **checked into git** so:
1. Builds work without Python (header already exists)
2. Changes to the prompt are visible in diffs
3. CI can verify the header matches the source:

```yaml
# .github/workflows/check-prompt.yml
- name: Verify prompt header is up-to-date
  run: |
    python scripts/embed_prompt.py --force prompts/idasql_agent.md /tmp/check.hpp
    diff -q src/common/idasql_agent_prompt.hpp /tmp/check.hpp
```

## 3. CMake Configuration

### `idasql/CMakeLists.txt` (top-level)

```cmake
option(IDASQL_WITH_CLAUDE_AGENT "Build with Claude AI agent support" OFF)

if(IDASQL_WITH_CLAUDE_AGENT)
    set(CLAUDE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(CLAUDE_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    add_subdirectory(external/claude-agent-sdk-cpp)

    # Make system prompt available at build time
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/prompts/idasql_agent.md
        ${CMAKE_BINARY_DIR}/prompts/idasql_agent.md
        COPYONLY
    )
endif()
```

### `idasql/src/cli/CMakeLists.txt`

```cmake
if(IDASQL_WITH_CLAUDE_AGENT)
    target_link_libraries(idasql PRIVATE claude_sdk)
    target_compile_definitions(idasql PRIVATE
        IDASQL_HAS_CLAUDE_AGENT
        IDASQL_SYSTEM_PROMPT_PATH="${CMAKE_BINARY_DIR}/prompts/idasql_agent.md"
    )
endif()
```

### `idasql/src/plugin/CMakeLists.txt`

```cmake
if(IDASQL_WITH_CLAUDE_AGENT)
    target_link_libraries(idasql_plugin PRIVATE claude_sdk)
    target_compile_definitions(idasql_plugin PRIVATE IDASQL_HAS_CLAUDE_AGENT)
endif()
```

## 4. SDK Architecture: MCP Tool for SQL Execution

The `claude-agent-sdk-cpp` wraps the Claude Code CLI and supports in-process MCP tools. We'll create an `execute_sql` tool that Claude can call directly.

### Shared ClaudeAgent Class

**`src/common/claude_agent.hpp`**:
```cpp
#pragma once

#ifdef IDASQL_HAS_CLAUDE_AGENT

#include <claude/claude.hpp>
#include <claude/mcp.hpp>
#include <functional>
#include <string>
#include "idasql_agent_prompt.hpp"

namespace idasql {

class ClaudeAgent {
public:
    using SqlExecutor = std::function<std::string(const std::string& sql)>;

    explicit ClaudeAgent(SqlExecutor executor);
    ~ClaudeAgent();

    // One-shot natural language query
    std::string query(const std::string& prompt);

    // Multi-turn conversation
    void start_session();
    std::string send_message(const std::string& message);
    void end_session();

    // Check if input looks like SQL (passthrough)
    static bool looks_like_sql(const std::string& input);

private:
    SqlExecutor executor_;
    std::unique_ptr<claude::ClaudeClient> client_;
    bool in_session_ = false;

    claude::ClaudeOptions create_options();
    std::string process_response(const std::vector<claude::Message>& messages);
};

} // namespace idasql

#endif // IDASQL_HAS_CLAUDE_AGENT
```

### MCP Tool Implementation

**`src/common/claude_agent.cpp`**:
```cpp
#include "claude_agent.hpp"

#ifdef IDASQL_HAS_CLAUDE_AGENT

#include <algorithm>
#include <cctype>

namespace idasql {

ClaudeAgent::ClaudeAgent(SqlExecutor executor)
    : executor_(std::move(executor))
{
}

ClaudeAgent::~ClaudeAgent() {
    end_session();
}

claude::ClaudeOptions ClaudeAgent::create_options() {
    using namespace claude::mcp;

    claude::ClaudeOptions opts;

    // Set system prompt from embedded header
    opts.system_prompt = SYSTEM_PROMPT;

    // Create execute_sql MCP tool
    auto execute_sql_tool = make_tool(
        "execute_sql",
        "Execute a SQL query against the IDA database. Returns results as formatted text.",
        [this](std::string query) -> std::string {
            return executor_(query);
        },
        std::vector<std::string>{"query"}
    );

    // Create MCP server with our tool
    auto idasql_server = create_server("idasql", "1.0.0", execute_sql_tool);

    // Register as SDK MCP handler (runs in-process)
    opts.sdk_mcp_handlers["idasql"] = idasql_server;

    // Allow our tool
    opts.allowed_tools = {"mcp__idasql__execute_sql"};

    // Bypass permission prompts for automation
    opts.permission_mode = "bypassPermissions";

    return opts;
}

std::string ClaudeAgent::query(const std::string& prompt) {
    // Check if it's raw SQL - execute directly
    if (looks_like_sql(prompt)) {
        return executor_(prompt);
    }

    auto opts = create_options();
    auto result = claude::query(prompt, opts);

    return process_response(result.messages());
}

void ClaudeAgent::start_session() {
    if (in_session_) return;

    auto opts = create_options();
    client_ = std::make_unique<claude::ClaudeClient>(opts);
    client_->connect();
    in_session_ = true;
}

std::string ClaudeAgent::send_message(const std::string& message) {
    if (!in_session_ || !client_) {
        start_session();
    }

    // Check if it's raw SQL - execute directly
    if (looks_like_sql(message)) {
        return executor_(message);
    }

    client_->send_query(message);
    auto response = client_->receive_response();
    return process_response(response);
}

void ClaudeAgent::end_session() {
    if (!in_session_ || !client_) return;

    client_->disconnect();
    client_.reset();
    in_session_ = false;
}

std::string ClaudeAgent::process_response(const std::vector<claude::Message>& messages) {
    std::string result;

    for (const auto& msg : messages) {
        if (claude::is_assistant_message(msg)) {
            const auto& assistant = std::get<claude::AssistantMessage>(msg);
            for (const auto& block : assistant.content) {
                if (std::holds_alternative<claude::TextBlock>(block)) {
                    if (!result.empty()) result += "\n";
                    result += std::get<claude::TextBlock>(block).text;
                }
            }
        }
    }

    return result;
}

bool ClaudeAgent::looks_like_sql(const std::string& input) {
    if (input.empty()) return false;

    std::string upper = input;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

    // Skip leading whitespace for comparison
    size_t start = upper.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return false;
    upper = upper.substr(start);

    return upper.rfind("SELECT ", 0) == 0 ||
           upper.rfind("INSERT ", 0) == 0 ||
           upper.rfind("UPDATE ", 0) == 0 ||
           upper.rfind("DELETE ", 0) == 0 ||
           upper.rfind("CREATE ", 0) == 0 ||
           upper.rfind("DROP ", 0) == 0 ||
           upper.rfind("PRAGMA ", 0) == 0 ||
           upper.rfind("WITH ", 0) == 0 ||
           upper.rfind(".tables", 0) == 0 ||
           upper.rfind(".schema", 0) == 0;
}

} // namespace idasql

#endif // IDASQL_HAS_CLAUDE_AGENT
```

### How It Works

1. **User types natural language**: "Find functions that call malloc"
2. **ClaudeAgent sends to Claude** with system prompt explaining IDASQL
3. **Claude generates SQL** and calls `mcp__idasql__execute_sql` tool
4. **Tool executes SQL** via the provided `SqlExecutor` callback
5. **Claude receives results** and formulates a response
6. **Response returned to user** with analysis

The same `ClaudeAgent` class is used by both CLI tool and IDA plugin, ensuring consistent behavior.

## 5. CLI Changes

### New Command-Line Options

```
--prompt <text>         Natural language query (one-shot, requires Claude)
--claude-code           Enable Claude Code mode in interactive REPL
--system-prompt <file>  Custom system prompt file (default: built-in)
```

### Usage Examples

```bash
# One-shot natural language query
idasql -s test.i64 --prompt "Find the 10 largest functions"
idasql -s test.i64 --prompt "Show me functions that call malloc without checking return"

# Interactive mode with Claude Code
idasql -s test.i64 -i --claude-code

# Remote mode with Claude Code
idasql --remote localhost:13337 -i --claude-code
```

## 5. Plugin CLI Integration

### Overview

Register a custom `cli_t` in the IDA plugin, similar to how `climacros` hooks CLIs. This allows users to type natural language queries directly in IDA's command line interface.

### CLI Structure

```cpp
// src/plugin/idasql_cli.hpp

#pragma once
#ifdef IDASQL_HAS_CLAUDE_AGENT

#include <ida.hpp>
#include <kernwin.hpp>
#include <functional>
#include <string>

namespace idasql {

// Forward declaration
class ClaudeAgent;

class IdasqlCLI {
public:
    using SqlExecutor = std::function<std::string(const std::string& sql)>;

    IdasqlCLI(SqlExecutor executor);
    ~IdasqlCLI();

    // Install/uninstall the CLI
    bool install();
    void uninstall();

    // The cli_t callbacks
    static bool idaapi execute_line(const char* line);
    static bool idaapi complete_line(
        qstring* completion,
        const char* prefix,
        int n,
        const char* line,
        int x);
    static bool idaapi keydown(qstring* line, int* p_x, int* p_sellen,
                               int* p_vk_key, int shift);

private:
    static IdasqlCLI* instance_;
    SqlExecutor executor_;
    std::unique_ptr<ClaudeAgent> agent_;  // Shared agent for NL processing
    bool installed_ = false;
};

// The actual cli_t structure
extern cli_t idasql_cli;

} // namespace idasql

#endif // IDASQL_HAS_CLAUDE_AGENT
```

### CLI Implementation

```cpp
// src/plugin/idasql_cli.cpp

#include "idasql_cli.hpp"
#include "../common/claude_agent.hpp"  // Shared agent with MCP tool

namespace idasql {

IdasqlCLI* IdasqlCLI::instance_ = nullptr;

cli_t idasql_cli = {
    sizeof(cli_t),
    0,                              // flags
    "idasql",                       // sname (short name for switching)
    "idasql - SQL queries with natural language support",  // lname
    "Enter SQL or natural language queries. Type 'help' for examples.\n",
    IdasqlCLI::execute_line,
    IdasqlCLI::complete_line,
    IdasqlCLI::keydown
};

IdasqlCLI::IdasqlCLI(SqlExecutor executor)
    : executor_(std::move(executor))
    , agent_(std::make_unique<ClaudeAgent>(executor_))
{
    instance_ = this;
}

IdasqlCLI::~IdasqlCLI() {
    uninstall();
    agent_.reset();
    instance_ = nullptr;
}

bool IdasqlCLI::install() {
    if (installed_) return true;
    installed_ = install_command_interpreter(&idasql_cli);
    if (installed_) {
        msg("IDASQL CLI installed. Switch with Alt+9 or type in Output window.\n");
    }
    return installed_;
}

void IdasqlCLI::uninstall() {
    if (!installed_) return;
    remove_command_interpreter(&idasql_cli);
    installed_ = false;
}

bool idaapi IdasqlCLI::execute_line(const char* line) {
    if (!instance_ || !line || !*line) return false;

    std::string input(line);

    // Handle special commands
    if (input == "help") {
        msg("IDASQL CLI - Examples:\n"
            "  SELECT * FROM funcs LIMIT 5\n"
            "  Find functions that call malloc\n"
            "  Show the 10 largest functions\n"
            "  What imports does this binary use?\n"
            "\n"
            "SQL queries execute directly. Natural language uses Claude.\n");
        return true;
    }

    // Use shared ClaudeAgent (handles both SQL passthrough and NL)
    std::string result = instance_->agent_->query(input);
    msg("%s\n", result.c_str());
    return true;
}

bool idaapi IdasqlCLI::complete_line(qstring*, const char*, int, const char*, int) {
    return false;  // No completion support yet
}

bool idaapi IdasqlCLI::keydown(qstring*, int*, int*, int*, int) {
    return false;  // No special key handling
}

} // namespace idasql
```

### Plugin Integration

Modify `src/plugin/main.cpp` to manage the CLI:

```cpp
struct idasql_plugmod_t : public plugmod_t {
    std::unique_ptr<idasql::QueryEngine> engine_;
    idasql_server_t server_;

#ifdef IDASQL_HAS_CLAUDE_AGENT
    std::unique_ptr<idasql::IdasqlCLI> idasql_cli_;
#endif

    idasql_plugmod_t() {
        engine_ = std::make_unique<idasql::QueryEngine>();
        if (engine_->is_valid()) {
            // ... existing server setup ...

#ifdef IDASQL_HAS_CLAUDE_AGENT
            // Create IDASQL CLI with SQL executor
            auto executor = [this](const std::string& sql) -> std::string {
                auto result = engine_->query(sql);
                return format_result(result);
            };
            idasql_cli_ = std::make_unique<idasql::IdasqlCLI>(executor);
            idasql_cli_->install();
#endif
        }
    }

    ~idasql_plugmod_t() {
#ifdef IDASQL_HAS_CLAUDE_AGENT
        idasql_cli_.reset();  // Uninstalls CLI
#endif
        server_.stop();
        engine_.reset();
    }

    virtual bool idaapi run(size_t arg) override {
        switch (arg) {
            // ... existing cases 0-4 ...

#ifdef IDASQL_HAS_CLAUDE_AGENT
            case 5:  // Toggle IDASQL CLI
                if (idasql_cli_) {
                    // Toggle installation
                }
                return true;

            case 6:  // Execute Claude prompt (for testing)
                // Read prompt from environment, execute, return result
                return true;
#endif

            default:
                return false;
        }
    }
};
```

## 6. Headless Testing

### Test Driver Modifications

Extend `src/test/idalib_driver.cpp` to support Claude integration testing:

```cpp
// New command-line options for test driver
// idalib_driver <database.i64> [--claude-test <prompt>] [--claude-interactive]

int main(int argc, char* argv[]) {
    const char* db_path = nullptr;
    const char* claude_prompt = nullptr;
    bool claude_interactive = false;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--claude-test") == 0 && i + 1 < argc) {
            claude_prompt = argv[++i];
        } else if (strcmp(argv[i], "--claude-interactive") == 0) {
            claude_interactive = true;
        } else if (!db_path) {
            db_path = argv[i];
        }
    }

    // ... existing init code ...

#ifdef IDASQL_HAS_CLAUDE_AGENT
    if (claude_prompt) {
        // One-shot Claude test
        std::cout << "Testing Claude prompt: " << claude_prompt << "\n\n";

        // Load plugin with Claude test mode (arg=6)
        // Plugin reads prompt from environment or shared memory
        setenv("IDASQL_CLAUDE_PROMPT", claude_prompt, 1);
        load_and_run_plugin("idasql_plugin", 6);

        return 0;
    }

    if (claude_interactive) {
        // Interactive Claude mode via stdin
        std::cout << "Claude Code Interactive Mode\n";
        std::cout << "Type natural language queries or 'quit' to exit.\n\n";

        std::string line;
        while (std::getline(std::cin, line)) {
            if (line == "quit" || line == "exit") break;

            setenv("IDASQL_CLAUDE_PROMPT", line.c_str(), 1);
            load_and_run_plugin("idasql_plugin", 6);
        }

        return 0;
    }
#endif

    // ... existing server mode code ...
}
```

### GTest Integration

Add `tests/claude_agent_test.cpp`:

```cpp
#include <gtest/gtest.h>

#ifdef IDASQL_HAS_CLAUDE_AGENT

#include "test_utils.hpp"

class ClaudeAgentTest : public IdasqlTestFixture {
protected:
    void SetUp() override {
        IdasqlTestFixture::SetUp();
        // Additional Claude-specific setup
    }
};

TEST_F(ClaudeAgentTest, SimpleNaturalLanguageQuery) {
    // This test requires Claude API access
    // Skip if ANTHROPIC_API_KEY not set
    if (!std::getenv("ANTHROPIC_API_KEY")) {
        GTEST_SKIP() << "ANTHROPIC_API_KEY not set";
    }

    auto result = execute_claude_prompt("How many functions are in this database?");

    // Should contain a number
    EXPECT_TRUE(result.find_first_of("0123456789") != std::string::npos);
}

TEST_F(ClaudeAgentTest, SqlPassthrough) {
    // SQL should be executed directly without Claude
    auto result = execute_with_agent("SELECT COUNT(*) FROM funcs");

    // Should return a count
    EXPECT_FALSE(result.empty());
}

TEST_F(ClaudeAgentTest, ComplexAnalysisQuery) {
    if (!std::getenv("ANTHROPIC_API_KEY")) {
        GTEST_SKIP() << "ANTHROPIC_API_KEY not set";
    }

    auto result = execute_claude_prompt(
        "Find functions that might have buffer overflow vulnerabilities"
    );

    // Should mention dangerous functions or return SQL results
    EXPECT_FALSE(result.empty());
}

#endif // IDASQL_HAS_CLAUDE_AGENT
```

### CI/CD Considerations

```yaml
# .github/workflows/test-claude.yml
name: Claude Integration Tests

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test-claude:
    runs-on: ubuntu-latest
    if: github.event_name == 'push'  # Only on push, not PRs (needs secrets)

    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Build with Claude support
        run: |
          cmake -B build -DIDASQL_WITH_CLAUDE_AGENT=ON
          cmake --build build --config Release

      - name: Run Claude tests
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          ctest --test-dir build -C Release -R "Claude" --output-on-failure
```

## 7. Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Input                               │
│  (Natural Language or SQL)                                       │
└─────────────────────┬───────────────────────────────────────────┘
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│   CLI Tool      │     │   IDA Plugin    │
│  (idasql.exe)   │     │ (idasql_plugin) │
└────────┬────────┘     └────────┬────────┘
         │                       │
         │  --claude-code        │  cli_t "claude"
         │  --prompt             │
         ▼                       ▼
┌─────────────────────────────────────────┐
│           ClaudeAgent                    │
│  ┌─────────────────────────────────┐    │
│  │  System Prompt (idasql_agent.md)│    │
│  └─────────────────────────────────┘    │
│  ┌─────────────────────────────────┐    │
│  │  execute_sql Tool               │────┼──► SQL Executor
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────┐
│         idasql::QueryEngine             │
│  (SQLite + IDA Virtual Tables)          │
└─────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────┐
│            IDA Database                  │
│  (funcs, xrefs, ctree, etc.)            │
└─────────────────────────────────────────┘
```

## 8. Implementation Order

1. **Phase 1: Submodule & Build**
   - Add claude-agent-sdk-cpp submodule
   - Update CMake files with IDASQL_WITH_CLAUDE_AGENT option
   - Copy system prompt to prompts/

2. **Phase 2: CLI Tool Integration**
   - Create `claude_agent.hpp` wrapper
   - Add --prompt and --claude-code to main.cpp
   - Test with local and remote modes

3. **Phase 3: Plugin CLI**
   - Create `claude_cli.hpp/cpp`
   - Register cli_t in plugin
   - Add run() arg codes 5, 6

4. **Phase 4: Testing**
   - Extend test driver
   - Add GTest cases
   - CI/CD pipeline

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `external/claude-agent-sdk-cpp` | Add | Git submodule |
| `prompts/idasql_agent.md` | Copy | From ../kb-ati/idasql/idasql-agent.md |
| `scripts/embed_prompt.py` | Create | Converts markdown to C++ header |
| `src/common/idasql_agent_prompt.hpp` | Generate | Embedded system prompt (checked in) |
| `src/common/claude_agent.hpp` | Create | Shared agent wrapper class |
| `src/cli/main.cpp` | Modify | Add --prompt, --claude-code flags |
| `src/cli/CMakeLists.txt` | Modify | Conditional claude_sdk linking |
| `src/plugin/idasql_cli.hpp` | Create | IDA CLI integration |
| `src/plugin/idasql_cli.cpp` | Create | IDA CLI implementation |
| `src/plugin/main.cpp` | Modify | Add CLI management, run() args 5,6 |
| `src/plugin/CMakeLists.txt` | Modify | Conditional claude_sdk linking |
| `src/test/idalib_driver.cpp` | Modify | Add --claude-test, --claude-interactive |
| `tests/claude_agent_test.cpp` | Create | GTest cases for Claude integration |
| `CMakeLists.txt` | Modify | IDASQL_WITH_CLAUDE_AGENT option |
| `.github/workflows/test-claude.yml` | Create | CI for Claude tests |
| `.github/workflows/check-prompt.yml` | Create | CI to verify prompt header is current |
