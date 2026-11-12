// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "rescue.hpp"

#include "../../common/cli_args.hpp"
#include "control_channel.hpp"

#include <chrono>
#include <cstdio>
#include <iostream>

namespace idasql {
namespace rescue {

const char* const kUsage =
    "usage: idasql rescue <database> [--kill] [--timeout <seconds>]\n"
    "\n"
    "  Saves a copy of the database a stuck IDA has open, as\n"
    "  <database>.rescued-<YYYYMMDD-HHMMSS>.<ext> next to it, without opening\n"
    "  the database here. Works for the IDA GUI and for idasql sessions on this\n"
    "  machine. --kill then ends that IDA (after the save, or after the timeout\n"
    "  when the save cannot finish). --timeout: seconds to wait (default 120).\n"
    "\n"
    "  For a stuck IDA only: one that is busy (a script still calling IDA,\n"
    "  analysis running) may crash. Wait, or use --kill.\n"
    "\n"
    "  Exit codes: 0 saved, 1 no armed IDA has it open / the save failed / IDA\n"
    "  exited during the save, 2 usage, 3 timed out.\n";

std::optional<std::string> derive_rescued_path(const std::string& db_path, const std::tm& when) {
    const size_t sep = db_path.find_last_of("/\\");
    const size_t name_begin = sep == std::string::npos ? 0 : sep + 1;
    const size_t dot = db_path.rfind('.');
    if (dot == std::string::npos || dot <= name_begin) return std::nullopt;
    char stamp[32];
    std::snprintf(stamp, sizeof(stamp), "%04d%02d%02d-%02d%02d%02d", when.tm_year + 1900, when.tm_mon + 1,
                  when.tm_mday, when.tm_hour, when.tm_min, when.tm_sec);
    return db_path.substr(0, dot) + ".rescued-" + stamp + db_path.substr(dot);
}

std::optional<std::string> derive_rescued_path(const std::string& db_path) {
    const std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm local{};
#ifdef _WIN32
    localtime_s(&local, &now);
#else
    localtime_r(&now, &local);
#endif
    return derive_rescued_path(db_path, local);
}

std::optional<std::string> unique_rescued_path(const std::string& db_path, const std::tm& when) {
    const auto base = derive_rescued_path(db_path, when);
    if (!base) return base;
    const size_t dot = base->rfind('.');
    std::string candidate = *base;
    for (int n = 2; control::file_exists(candidate) && n < 1000; ++n)
        candidate = base->substr(0, dot) + "-" + std::to_string(n) + base->substr(dot);
    return candidate;
}

std::optional<std::string> unique_rescued_path(const std::string& db_path) {
    const std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm local{};
#ifdef _WIN32
    localtime_s(&local, &now);
#else
    localtime_r(&now, &local);
#endif
    return unique_rescued_path(db_path, local);
}

int run_cli(const std::vector<std::string>& in) {
    const cli::Args args = cli::parse_args(in, {{"--kill"}, {"--timeout"}});
    if (!args.ok() || args.positionals.size() != 1) {
        std::cerr << "error: "
                  << (!args.ok() ? args.error : args.positionals.empty() ? "a database path is needed"
                                                                         : "one database at a time")
                  << "\n"
                  << kUsage;
        return cli::kUsage;
    }
    int timeout_s = kDefaultTimeoutS;
    if (!args.value("--timeout").empty()) {
        try {
            size_t used = 0;
            timeout_s = std::stoi(args.value("--timeout"), &used);
            if (used != args.value("--timeout").size()) throw std::invalid_argument("trailing");
        } catch (...) {
            timeout_s = -1;
        }
        if (timeout_s < 1 || timeout_s > 3600) {
            std::cerr << "error: --timeout must be 1..3600 seconds\n";
            return cli::kUsage;
        }
    }
    const std::string db = args.positionals[0];
    const std::string shown = control::normalise_db_path(db);
    const bool kill = args.has("--kill");

    if (!control::is_armed(db)) {
        std::cerr << "no idasql-armed IDA has " << shown << " open\n";
        return cli::kFailed;
    }
    std::cout << "waiting for the IDA holding " << shown << " to save ...\n" << std::flush;
    const auto r = control::send(db, "rescue", xsql::json{{"kill", kill}, {"timeout_s", timeout_s}},
                                 (timeout_s + 5) * 1000);
    switch (r.status) {
        case control::SendStatus::no_server:
            std::cerr << "no idasql-armed IDA has " << shown << " open\n";
            return cli::kFailed;
        case control::SendStatus::error:
            std::cerr << "error: " << r.error << "\n";
            return cli::kFailed;
        case control::SendStatus::timeout:
            if (!control::is_armed(db)) {
                std::cerr << "IDA exited during the save; no rescue file was written\n";
                return cli::kFailed;
            }
            std::cerr << "timed out after " << timeout_s
                      << " s: IDA may be busy rather than stuck, or a Python save hook is waiting for the hung "
                         "thread; the save may still finish\n";
            return cli::kTimeout;
        case control::SendStatus::ok:
            break;
    }
    if (r.reply.outcome == "saved") {
        std::cout << "saved: " << r.reply.data.value("path", std::string()) << "\n";
        if (kill) std::cout << "IDA was ended (--kill)\n";
        return cli::kOk;
    }
    if (r.reply.outcome == "timed_out") {
        std::cerr << "timed out after " << timeout_s
                  << " s: IDA may be busy rather than stuck, or a Python save hook is waiting for the hung thread"
                  << (kill ? "; IDA was ended (--kill), no rescue file was written" : "") << "\n";
        return cli::kTimeout;
    }
    std::cerr << "the save failed: " << r.reply.data.value("message", r.reply.outcome) << "\n";
    return cli::kFailed;
}

}
}
