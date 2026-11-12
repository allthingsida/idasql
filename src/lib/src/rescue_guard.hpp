// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <memory>
#include <string>

#include "control_channel.hpp"

namespace idasql {
namespace rescue {

class Guard {
public:
    Guard();
    ~Guard();
    Guard(const Guard&) = delete;
    Guard& operator=(const Guard&) = delete;

    bool arm(const std::string& idb_path, std::string* error = nullptr);
    bool disarm();
    bool armed() const;
    void set_host_actions(control::Handler actions);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
}
