// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace idasql {
namespace deep_link {

const std::vector<std::string>& resources();

std::string default_view(std::string_view resource);

const std::vector<std::string>& allowed_views(std::string_view resource);

bool is_resource(std::string_view resource);
bool is_view(std::string_view view);
bool view_allowed(std::string_view resource, std::string_view view);

std::string percent_encode(std::string_view text);

std::optional<std::string> percent_decode(std::string_view text);

bool encode_type_name(std::string_view name, std::string& out, std::string& error);

std::string format_hex(uint64_t value);

struct LinkTarget {
    std::string source;
    std::string idb_name;
    std::string resource;
    std::optional<uint64_t> rva;
    std::optional<uint64_t> ea;
    std::string name;
    std::string view;
    std::string idb_path;
};

struct BuildResult {
    bool valid = false;
    std::string uri;
    std::string view;
    std::string diagnostic;
};

BuildResult build(const LinkTarget& target);

struct ParsedLink {
    bool valid = false;
    std::string diagnostic;
    bool is_ke = false;
    LinkTarget target;
};

ParsedLink parse(std::string_view uri);

std::string to_ida_uri(const ParsedLink& link);

std::string screen_untrusted_uri(std::string_view uri);

struct IpcOptions {
    int connect_timeout_ms = 2000;
    int io_timeout_ms = 10000;
    std::string socket_dir = "/tmp";
    std::vector<uint64_t> only_pids;
};

struct Endpoint {
    uint64_t pid = 0;
    std::string path;
};

struct Instance {
    uint64_t pid = 0;
    std::string endpoint;
    bool responsive = false;
    std::string idb_path;
    std::string version;
    std::string idb_name() const;
};

std::string endpoint_path(uint64_t pid, const IpcOptions& options = {});

std::vector<Endpoint> discover(const IpcOptions& options = {});

std::optional<std::string> request(const Endpoint& endpoint, const std::string& json_request,
                                   std::string& error, const IpcOptions& options = {});

std::vector<Instance> list_instances(const IpcOptions& options = {});

bool open_in(const Endpoint& endpoint, const std::string& ida_uri, std::string& message,
             const IpcOptions& options = {});

std::optional<bool> analysis_complete(const Endpoint& endpoint, std::string& error,
                                      const IpcOptions& options = {});

struct Selection {
    std::optional<Instance> chosen;
    std::string error;
    std::vector<Instance> candidates;
    bool by_name = false;
};

Selection select_instance(const std::vector<Instance>& instances, const LinkTarget& target,
                          std::optional<uint64_t> pid = std::nullopt, bool allow_name_fallback = true);

struct SessionChoice {
    bool here = false;
    Selection other;
};

SessionChoice choose_from_session(const std::vector<Instance>& others, const LinkTarget& target,
                                  std::string_view current_idb_path, bool allow_name_fallback);

bool same_path(std::string_view a, std::string_view b);

bool same_database(std::string_view a, std::string_view b);

struct Config {
    std::map<std::string, std::string> sources;
    std::string ida;
    std::vector<std::string> ida_args;
    int launch_timeout_s = 120;
    bool wait_analysis = true;
};

std::filesystem::path default_config_path();
Config load_config(const std::filesystem::path& path, std::string* error = nullptr);
bool save_config(const std::filesystem::path& path, const Config& config, std::string& error);

bool valid_source_name(std::string_view name);

std::filesystem::path self_executable();

std::optional<std::filesystem::path> resolve_ida(const Config& config,
                                                 const std::filesystem::path& self,
                                                 std::string& error);

struct IdbResolution {
    std::optional<std::filesystem::path> path;
    bool under_source = false;
    std::string error;
};

IdbResolution resolve_idb(const LinkTarget& target, const Config& config);

std::optional<uint64_t> spawn_ida(const std::filesystem::path& ida,
                                  const std::vector<std::string>& extra_args,
                                  const std::filesystem::path& idb, std::string& error);

struct RegistrationEnv {
    std::string windows_classes_key = "Software\\Classes";
    std::filesystem::path home;
    std::function<int(const std::vector<std::string>&)> run;
};

enum class HandlerOwner { none, idasql, hcli, other };
const char* owner_name(HandlerOwner owner);

struct HandlerStatus {
    HandlerOwner owner = HandlerOwner::none;
    std::string command;
    std::string previous;
};

bool register_handler(const std::filesystem::path& handler_exe, const RegistrationEnv& env, std::string& error);
bool unregister_handler(const RegistrationEnv& env, std::string& error);
HandlerStatus handler_status(const RegistrationEnv& env);

int run_cli(const std::vector<std::string>& args);

void set_ipc_options_override(std::optional<IpcOptions> options);
IpcOptions effective_ipc_options();

}
}
