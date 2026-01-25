#pragma once
// IDASQL Plugin Control Codes
// See tests/idasql/harness/run_tests.py for documentation

namespace idasql {

constexpr size_t PLUGIN_ARG_GUI_TOGGLE       = 0;   // Toggle server (GUI mode)
constexpr size_t PLUGIN_ARG_START_POLL_MODE  = 21;  // Start server in poll mode
constexpr size_t PLUGIN_ARG_STOP_SERVER      = 22;  // Stop server
constexpr size_t PLUGIN_ARG_TOGGLE_CLI       = 23;  // Toggle CLI
constexpr size_t PLUGIN_ARG_POLL_ONE         = 24;  // Execute one pending query

// Port encoding: arg = (port << 16) | command
constexpr size_t PLUGIN_ARG_PORT_SHIFT = 16;
constexpr size_t PLUGIN_ARG_CMD_MASK   = 0xFFFF;
constexpr int    PLUGIN_DEFAULT_PORT   = 13337;

} // namespace idasql
