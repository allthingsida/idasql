// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

namespace idasql {
namespace ui_actions {

struct CatalogEntry {
    const char* name;
    const char* kind;
    const char* ida_action;
    const char* description;
    const char* arg_spec;
    const char* where;
    int min_ida;
};

inline constexpr CatalogEntry kCatalog[] = {
    {"quit", "idasql", nullptr,
     "Quit IDA (or end this idasql server session), saving the database or leaving it on disk exactly as it was. Runs after the current request, so its reply still arrives.",
     "{\"save\":{\"default\":true,\"doc\":\"true: save first; false: quit without saving\",\"type\":\"bool\"}}", "gui+server", 920},
    {"jump_to", "idasql", nullptr,
     "Move IDA's cursor (the current disassembly or pseudocode view) to an address.",
     "{\"addr\":{\"doc\":\"the address to go to\",\"required\":true,\"type\":\"int\"}}", "gui", 920},
    {"open_pseudocode", "idasql", nullptr,
     "Open (or reuse) the pseudocode window on a function. Needs the Hex-Rays decompiler.",
     "{\"func_addr\":{\"doc\":\"an address inside the function\",\"required\":true,\"type\":\"int\"}}", "gui", 920},
    {"open_link", "idasql", nullptr,
     "Open an ida:// deep link in this IDA (what ida_open_link() does).",
     "{\"uri\":{\"doc\":\"an ida:// link, as the deep_links table builds them\",\"required\":true,\"type\":\"text\"}}", "gui", 940},
    {"batch_mode", "idasql", nullptr,
     "IDA's batch mode: while on, dialogs do not appear and take their default answer, so nothing waits for a person. checked shows the current state.",
     "{\"on\":{\"doc\":\"true: on; false: off; omitted: flip it\",\"type\":\"bool\"}}", "gui+server", 920},
    {"toggle_breakpoint", "idasql", nullptr,
     "Add a breakpoint at an address, or remove the one that is there. last_result says which.",
     "{\"addr\":{\"doc\":\"the breakpoint address\",\"required\":true,\"type\":\"int\"}}", "gui+server", 920},
    {"run_to", "idasql", nullptr,
     "Debugger: run until an address is reached (starts the process if it is not running).",
     "{\"addr\":{\"doc\":\"where to stop\",\"required\":true,\"type\":\"int\"}}", "gui", 920},
    {"step_over", "ida", "ThreadStepOver",
     "Debugger: step over the current instruction (F8).",
     "{}", "gui", 920},
    {"step_into", "ida", "ThreadStepInto",
     "Debugger: single step, into calls (F7).",
     "{}", "gui", 920},
    {"add_breakpoint", "ida", "BreakpointAdd",
     "Debugger: add a breakpoint at the cursor. (toggle_breakpoint takes an address.)",
     "{}", "gui", 920},
    {"attach_process", "ida", "ProcessAttach",
     "Debugger: attach to a running process. Opens IDA's process list and waits for a person (in batch mode it takes the default).",
     "{}", "gui", 920},
    {"detach_process", "ida", "ProcessDetach",
     "Debugger: detach from the debugged process, leaving it running.",
     "{}", "gui", 920},
    {"terminate_process", "ida", "ProcessExit",
     "Debugger: terminate the debugged process (Ctrl-F2).",
     "{}", "gui", 920},
    {"pause_process", "ida", "ProcessPause",
     "Debugger: pause the debugged process, or continue it when it is paused.",
     "{}", "gui", 920},
    {"start_process", "ida", "ProcessStart",
     "Debugger: start the process in the debugger, or continue it when it is paused (F9).",
     "{}", "gui", 920},
    {"save_desktop", "ida", "SaveDesktop",
     "Save the window layout as a named desktop. Asks for the name (in batch mode it takes the default).",
     "{}", "gui", 920},
    {"run_to_cursor", "ida", "ThreadRunToCursor",
     "Debugger: run until the instruction under the cursor (F4). (run_to takes an address.)",
     "{}", "gui", 920},
    {"run_to_cursor_backwards", "ida", "ThreadRunToCursorBackwards",
     "Debugger, replay/time-travel debuggers only: run backwards to the instruction under the cursor.",
     "{}", "gui", 920},
    {"run_until_return", "ida", "ThreadRunUntilReturn",
     "Debugger: run until the current function returns (Ctrl-F7).",
     "{}", "gui", 920},
    {"set_ip", "ida", "ThreadSetCurrentIp",
     "Debugger: set the instruction pointer to the cursor (Ctrl-N).",
     "{}", "gui", 920},
    {"step_into_backwards", "ida", "ThreadStepIntoBackwards",
     "Debugger, replay/time-travel debuggers only: step one instruction backwards, into calls.",
     "{}", "gui", 920},
    {"step_over_backwards", "ida", "ThreadStepOverBackwards",
     "Debugger, replay/time-travel debuggers only: step backwards over calls.",
     "{}", "gui", 920},
};

}
}
