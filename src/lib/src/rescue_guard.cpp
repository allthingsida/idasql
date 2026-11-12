// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include <idasql/platform.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "control_channel.hpp"
#include "rescue.hpp"
#include "rescue_guard.hpp"
#include "os.hpp"
#include "ui_actions.hpp"

#include <idasql/platform_undef.hpp>

#include "ida_headers.hpp"

namespace idasql {
namespace rescue {

namespace {

using json = xsql::json;

struct MboxMute : public event_listener_t {
    std::atomic<int> active{0};
    ssize_t idaapi on_event(ssize_t code, va_list) override {
        return (active.load() > 0 && code == ui_mbox) ? 1 : 0;
    }
};

[[noreturn]] void end_process() {
#ifdef _WIN32
    ExitProcess(0);
#else
    _exit(0);
#endif
}

struct SaveJob {
    std::mutex m;
    std::condition_variable cv;
    bool done = false;
    bool ok = false;
};

}

struct HostActions {
    std::mutex m;
    control::Handler handler;
};

struct Guard::Impl {
    control::Server server;
    std::shared_ptr<HostActions> host = std::make_shared<HostActions>();
    std::shared_ptr<MboxMute> mute = std::make_shared<MboxMute>();
    bool hooked = false;
    std::string idb_path;
};

Guard::Guard() : impl_(std::make_unique<Impl>()) {}

Guard::~Guard() { (void)disarm(); }

bool Guard::armed() const { return impl_->server.running(); }

bool Guard::arm(const std::string& idb_path, std::string* error) {
    (void)disarm();
    if (idb_path.empty()) {
        if (error) *error = "no database is open";
        return false;
    }
    impl_->idb_path = idb_path;
    if (!impl_->hooked) impl_->hooked = hook_event_listener(HT_UI, impl_->mute.get(), nullptr);
    std::shared_ptr<MboxMute> mute = impl_->mute;
    std::shared_ptr<HostActions> host = impl_->host;
    const std::string db = idb_path;
    return impl_->server.start(
        db,
        [mute, host, db](const control::Request& req) -> control::Reply {
            if (req.action == "close") {
                std::string why;
                if (!ui_actions::request_quit(req.args.value("save", true), why))
                    return {"refused", json{{"message", why}}};
                return {"closing", json{{"pid", os::current_pid()}}};
            }
            if (req.action != "rescue") {
                control::Handler h;
                {
                    std::lock_guard<std::mutex> lock(host->m);
                    h = host->handler;
                }
                return h ? h(req) : control::Reply{"unknown_action", json::object()};
            }
            const bool kill = req.args.value("kill", false);
            const int timeout_s = req.args.value("timeout_s", kDefaultTimeoutS);
            const auto target = unique_rescued_path(db);
            if (!target) return {"failed", json{{"message", "the database path has no extension: " + db}}};

            auto job = std::make_shared<SaveJob>();
            const std::string path = *target;
            std::thread([job, mute, path] {
                ++mute->active;
                flush_buffers();
                const bool ok = save_database(path.c_str(), DBFL_BAK);
                --mute->active;
                std::lock_guard<std::mutex> lock(job->m);
                job->ok = ok;
                job->done = true;
                job->cv.notify_all();
            }).detach();

            control::Reply reply;
            {
                std::unique_lock<std::mutex> lock(job->m);
                if (!job->cv.wait_for(lock, std::chrono::seconds(timeout_s), [&job] { return job->done; })) {
                    reply = {"timed_out", json{{"path", path}}};
                } else if (job->ok) {
                    reply = {"saved", json{{"path", path}}};
                } else {
                    reply = {"failed", json{{"message", "save_database returned false for " + path}}};
                }
            }
            qeprintf("idasql rescue: %s %s\n", reply.outcome.c_str(), path.c_str());
            if (kill) reply.after_reply = [] { end_process(); };
            return reply;
        },
        error);
}

void Guard::set_host_actions(control::Handler actions) {
    std::lock_guard<std::mutex> lock(impl_->host->m);
    impl_->host->handler = std::move(actions);
}

bool Guard::disarm() {
    const bool finished = impl_->server.stop();
    if (impl_->hooked && finished) {
        unhook_event_listener(HT_UI, impl_->mute.get());
        impl_->hooked = false;
    }
    if (impl_->hooked && !finished) {
        static std::mutex keep_m;
        static std::vector<std::shared_ptr<MboxMute>>* keep = new std::vector<std::shared_ptr<MboxMute>>();
        std::lock_guard<std::mutex> lock(keep_m);
        keep->push_back(impl_->mute);
        impl_->mute = std::make_shared<MboxMute>();
        impl_->hooked = false;
    }
    return finished;
}

}
}
