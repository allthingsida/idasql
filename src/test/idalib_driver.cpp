/**
 * idalib_driver - Test driver for IDASQL plugin in headless mode
 *
 * Usage:
 *   idalib_driver <database.i64>
 *
 * Opens database via idalib, starts plugin server in poll mode, pumps queries.
 * The plugin handles all server logic; this driver just pumps the queue.
 *
 * Exit: Ctrl-C
 *
 * Connect with: idasql --remote localhost:13337 -q "SELECT * FROM funcs"
 */

#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>
#include <atomic>

#include <ida.hpp>
#include <idalib.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <segment.hpp>

//=============================================================================
// Global state
//=============================================================================

static std::atomic<bool> g_running{true};

static void signal_handler(int sig)
{
    (void)sig;
    g_running = false;
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "idalib_driver - Test driver for IDASQL plugin\n\n"
                  << "Usage: " << argv[0] << " <database.i64>\n\n"
                  << "Starts IDASQL server in poll mode.\n"
                  << "Connect with: idasql --remote localhost:13337 -i\n"
                  << "Exit: Ctrl-C\n";
        return 1;
    }

    const char* db_path = argv[1];

    // Setup signal handlers
    std::signal(SIGINT, signal_handler);
#ifndef _WIN32
    std::signal(SIGTERM, signal_handler);
#endif

    //-------------------------------------------------------------------------
    // Initialize IDA library
    //-------------------------------------------------------------------------
    std::cout << "Initializing IDA library...\n";
    if (init_library() != 0) {
        std::cerr << "Error: init_library() failed\n";
        return 1;
    }
    enable_console_messages(true);

    //-------------------------------------------------------------------------
    // Open database
    // Note: PLUGIN_MULTI plugins auto-load when database opens
    //-------------------------------------------------------------------------
    std::cout << "Opening: " << db_path << "\n";
    if (open_database(db_path, true, nullptr) != 0) {
        std::cerr << "Error: open_database() failed\n";
        return 1;
    }

    // Wait for auto-analysis
    auto_wait();

    std::cout << "Database opened.\n";
    std::cout << "  Functions: " << get_func_qty() << "\n";
    std::cout << "  Segments:  " << get_segm_qty() << "\n";

    //-------------------------------------------------------------------------
    // Start server in poll mode (arg=1)
    //-------------------------------------------------------------------------
    std::cout << "\nStarting IDASQL server...\n";
    if (!load_and_run_plugin("idasql_plugin", 1)) {
        std::cerr << "Warning: load_and_run_plugin returned false\n";
        // Continue anyway - plugin might have logged its own error
    }

    std::cout << "\n";
    std::cout << "===========================================\n";
    std::cout << " IDASQL Server running on 127.0.0.1:13337\n";
    std::cout << "===========================================\n";
    std::cout << "\n";
    std::cout << "Connect with:\n";
    std::cout << "  idasql --remote localhost:13337 -q \"SELECT * FROM funcs LIMIT 5\"\n";
    std::cout << "  idasql --remote localhost:13337 -i\n";
    std::cout << "\n";
    std::cout << "Press Ctrl-C to exit.\n";
    std::cout << "\n";

    //-------------------------------------------------------------------------
    // Poll loop - pump pending queries
    //-------------------------------------------------------------------------
    while (g_running) {
        // Execute pending queries (arg=4)
        // This processes one query per call, returns true if something was processed
        load_and_run_plugin("idasql_plugin", 4);

        // Small sleep to avoid busy-waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cout << "\nShutting down...\n";

    //-------------------------------------------------------------------------
    // Stop server (arg=2)
    //-------------------------------------------------------------------------
    load_and_run_plugin("idasql_plugin", 2);

    //-------------------------------------------------------------------------
    // Cleanup
    //-------------------------------------------------------------------------
    close_database(false);

    std::cout << "Done.\n";
    return 0;
}
