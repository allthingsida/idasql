// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * deep_link.hpp - IDA 9.4 ida:// deep links, natively, on every platform.
 *
 * Everything idasql needs to work with deep links without any external tool:
 *
 *   - the link model: build ida:// URIs byte-identical to IDA's own Copy Link, and
 *     parse them with IDA's own rules;
 *   - a client for the IPC endpoint every IDA 9.4 GUI runs (ida_ipc_<pid>): list
 *     running instances, open a link in one, wait for its auto-analysis;
 *   - instance selection, launching IDA on a database, a small config file;
 *   - registering idasql as the OS handler for ida:// (restoring the previous handler,
 *     such as hcli's, on unregister);
 *   - the `idasql link ...` command-line verbs.
 *
 * idasql's links carry one extra parameter, idb_path= (the database's full path), after
 * everything IDA's Copy Link emits. IDA reads only rva, ea, name and view, so the link
 * still opens in IDA; idasql's handler uses the path to find or launch the right
 * database. It is dropped before a link is handed to IDA.
 *
 * This file and deep_link.cpp use no IDA SDK API, so the link verbs run before
 * idalib is initialised and the module compiles and tests on its own.
 */

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

// ---------------------------------------------------------------------------
// Link model
// ---------------------------------------------------------------------------

/// Resource names, in IDA's order.
const std::vector<std::string>& resources();

/// Default view for a resource, or "" for an unknown resource.
std::string default_view(std::string_view resource);

/// Views IDA accepts for a resource (empty for an unknown resource).
const std::vector<std::string>& allowed_views(std::string_view resource);

bool is_resource(std::string_view resource);
bool is_view(std::string_view view);
bool view_allowed(std::string_view resource, std::string_view view);

/// Percent-encode like Qt's QUrl::toPercentEncoding with empty sets, which is what
/// IDA uses for the database name: A-Z a-z 0-9 - . _ ~ stay literal, every other
/// byte becomes %XX (upper case). The result never contains ( ) [ ] | < > or a
/// space, so a database name is always safe inside a markdown link destination.
/// (A type name is encoded with encode_type_name() instead.)
std::string percent_encode(std::string_view text);

/// Decode %XX escapes. Returns nullopt on a malformed escape.
std::optional<std::string> percent_decode(std::string_view text);

/// Encode a type name for name= the way IDA 9.4 can read it back: URL delimiters
/// (: / ? [ ] @ ! $ ' ( ) * + , ; =) stay raw because IDA does not decode their
/// escapes there; other bytes outside the unreserved set become %XX. Fails for a
/// name containing '&', '#' or '%', which no link can carry to IDA.
bool encode_type_name(std::string_view name, std::string& out, std::string& error);

/// IDA's address format for links: "0x" + upper-case hex, no padding.
std::string format_hex(uint64_t value);

/// What a link points at.
struct LinkTarget {
    std::string source;     ///< optional host segment; IDA ignores it
    std::string idb_name;   ///< database basename; empty = the running instance's database
    std::string resource;   ///< functions, addresses, ..., types
    std::optional<uint64_t> rva;
    std::optional<uint64_t> ea;
    std::string name;       ///< type name, for resource "types"
    std::string view;       ///< empty = the resource's default view
    std::string idb_path;   ///< the database's full path (idasql's extra parameter)
};

struct BuildResult {
    bool valid = false;
    std::string uri;
    std::string view;        ///< the view actually used (default filled in)
    std::string diagnostic;  ///< why the link is invalid, empty when valid
};

/// Build a link. Validates like IDA (resource, view compatibility, coordinate).
/// A non-empty idb_path is appended last as &idb_path=.
BuildResult build(const LinkTarget& target);

struct ParsedLink {
    bool valid = false;
    std::string diagnostic;
    bool is_ke = false;      ///< a Knowledge Exchange link (hcli territory, never opened)
    LinkTarget target;
};

/// Parse an ida:// URI with IDA 9.4's rules: percent-decoded path and
/// name, base-0 numbers (0x hex, leading-0 octal, decimal), unknown parameters
/// ignored, ea/rva mutually exclusive, exactly two path segments when a source is
/// present.
ParsedLink parse(std::string_view uri);

/// The canonical form of a parsed link without idb_path: exactly what IDA's Copy
/// Link would produce. This is the only string ever handed to IDA. Empty for an
/// invalid link.
std::string to_ida_uri(const ParsedLink& link);

/// Reject URIs a handler must never act on: over-long, control characters, a
/// scheme other than ida. Returns an error message, or "" when acceptable. This
/// screens the raw text only; parse() rejects control bytes that percent-decoding
/// produces (%00, %0A, ...).
std::string screen_untrusted_uri(std::string_view uri);

// ---------------------------------------------------------------------------
// IPC client for IDA 9.4's ida_ipc_<pid> endpoint
// ---------------------------------------------------------------------------

struct IpcOptions {
    int connect_timeout_ms = 2000;
    /// The reply is written only after IDA's UI thread has run the command (a
    /// navigation included), so this must be seconds, not milliseconds.
    int io_timeout_ms = 10000;
    /// Unix-domain socket directory on Linux/macOS (IDA and hcli use /tmp).
    std::string socket_dir = "/tmp";
    /// When set, only these pids are considered (tests, `--pid`).
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
    std::string idb_path;   ///< empty when no database is open
    std::string version;
    std::string idb_name() const;
};

/// The endpoint path for a pid.
std::string endpoint_path(uint64_t pid, const IpcOptions& options = {});

/// Live IDA IPC endpoints (no connection is made to find them).
std::vector<Endpoint> discover(const IpcOptions& options = {});

/// Send one JSON request and return the parsed JSON reply as a string, or nullopt
/// with `error` set. Verifies that the endpoint is served by the pid in its name.
std::optional<std::string> request(const Endpoint& endpoint, const std::string& json_request,
                                   std::string& error, const IpcOptions& options = {});

/// Every endpoint, with its get_info answer. The endpoints are asked concurrently,
/// so one that does not answer costs one timeout, not one per instance.
std::vector<Instance> list_instances(const IpcOptions& options = {});

/// Ask one instance to open an ida:// URI. `message` carries IDA's error text.
bool open_in(const Endpoint& endpoint, const std::string& ida_uri, std::string& message,
             const IpcOptions& options = {});

/// is_analysis_complete; nullopt when the instance did not answer it.
std::optional<bool> analysis_complete(const Endpoint& endpoint, std::string& error,
                                      const IpcOptions& options = {});

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

struct Selection {
    std::optional<Instance> chosen;
    std::string error;
    std::vector<Instance> candidates;  ///< the ambiguous set, when error says so
    bool by_name = false;              ///< matched by basename, not by the link's exact path
};

/// Pick the instance a link targets:
///   - an explicit pid wins;
///   - a link with idb_path matches the full path exactly (normalised);
///   - failing that (or without idb_path), the IDB basename, case-insensitively,
///     ignoring .i64/.idb, so a copy of the database opened elsewhere still counts --
///     unless allow_name_fallback is false, which a caller passes when the exact file
///     the link names exists on this machine (a same-named database elsewhere is then
///     a different database);
///   - an IDB-less link needs exactly one instance with a database open.
/// More than one match is an error listing the candidates, never a silent pick.
Selection select_instance(const std::vector<Instance>& instances, const LinkTarget& target,
                          std::optional<uint64_t> pid = std::nullopt, bool allow_name_fallback = true);

/// Where a link opened from inside an IDA session goes.
struct SessionChoice {
    bool here = false;  ///< open it in this session
    Selection other;    ///< otherwise: the instance to steer (or why there is none)
};

/// The rule for a link opened from inside an IDA session (current_idb_path is the
/// session's database; `others` excludes the session itself):
///   1. a link naming no database opens here;
///   2. a link whose idb_path is this session's database opens here;
///   3. an instance with the link's exact idb_path is chosen;
///   4. else a database of the same name here (a copy) opens here;
///   5. else select_instance among the others.
SessionChoice choose_from_session(const std::vector<Instance>& others, const LinkTarget& target,
                                  std::string_view current_idb_path, bool allow_name_fallback);

bool same_path(std::string_view a, std::string_view b);

/// The same database: the same text path (same_path), the same file once both are
/// made canonical (symlinks, 8.3 names, case on case-insensitive systems), or the
/// .idb and the .i64 IDA upgrades it to, side by side.
bool same_database(std::string_view a, std::string_view b);

// ---------------------------------------------------------------------------
// Config (links.json in the user config directory)
// ---------------------------------------------------------------------------

struct Config {
    std::map<std::string, std::string> sources;  ///< name -> directory
    std::string ida;                             ///< ida executable; empty = auto
    std::vector<std::string> ida_args;           ///< extra arguments for launches
    int launch_timeout_s = 120;
    bool wait_analysis = true;
};

std::filesystem::path default_config_path();
Config load_config(const std::filesystem::path& path, std::string* error = nullptr);
bool save_config(const std::filesystem::path& path, const Config& config, std::string& error);

/// Source names follow hcli's rule: ^[a-z0-9][a-z0-9-]*$, and "localhost" is reserved.
bool valid_source_name(std::string_view name);

// ---------------------------------------------------------------------------
// Launch
// ---------------------------------------------------------------------------

/// The running executable's path.
std::filesystem::path self_executable();

/// This process's id.
uint64_t current_pid();

/// The IDA GUI executable to launch: config.ida, else $IDADIR, else next to `self`.
std::optional<std::filesystem::path> resolve_ida(const Config& config,
                                                 const std::filesystem::path& self,
                                                 std::string& error);

struct IdbResolution {
    std::optional<std::filesystem::path> path;
    bool under_source = false;  ///< found in (or inside) a configured source
    std::string error;
};

/// The database file a link names: its local idb_path if it exists, else a
/// literal-filename search of the configured sources (the link's source only, when
/// it names one). Remote and UNC paths are refused, and so is anything that is not
/// a .i64/.idb. A name found more than once is an error that lists every match.
IdbResolution resolve_idb(const LinkTarget& target, const Config& config);

/// Start IDA on a database; returns the new process id, or nullopt with `error`.
/// On macOS a bundle is started through `open`, which does not report a pid (0).
std::optional<uint64_t> spawn_ida(const std::filesystem::path& ida,
                                  const std::vector<std::string>& extra_args,
                                  const std::filesystem::path& idb, std::string& error);

// ---------------------------------------------------------------------------
// OS handler registration
// ---------------------------------------------------------------------------

/// Where registration writes, and how it runs helper programs. The defaults touch
/// the real per-user OS state; tests substitute a scratch root and a recorder.
struct RegistrationEnv {
    /// Windows: HKCU subkey that holds URL classes.
    std::string windows_classes_key = "Software\\Classes";
    /// Linux/macOS: the home directory to write under; empty = $HOME.
    std::filesystem::path home;
    /// Runs a helper (xdg-mime, lsregister, osacompile...); returns its exit code.
    std::function<int(const std::vector<std::string>&)> run;
};

enum class HandlerOwner { none, idasql, hcli, other };
const char* owner_name(HandlerOwner owner);

struct HandlerStatus {
    HandlerOwner owner = HandlerOwner::none;
    std::string command;   ///< the registered command line, when readable
    std::string previous;  ///< the handler idasql replaced and restores on unregister
};

/// Make idasql the ida:// handler. A handler that was there before (hcli's, say) is
/// remembered, and unregister_handler puts it back.
bool register_handler(const std::filesystem::path& handler_exe, const RegistrationEnv& env, std::string& error);
bool unregister_handler(const RegistrationEnv& env, std::string& error);
HandlerStatus handler_status(const RegistrationEnv& env);

// ---------------------------------------------------------------------------
// `idasql link ...`
// ---------------------------------------------------------------------------

/// Run the link verbs; args exclude the program name and the word "link".
/// Returns the process exit code.
int run_cli(const std::vector<std::string>& args);

/// Test seam: every IPC call made by run_cli and by the SQL surface uses these
/// options when set (restricts discovery to a mock endpoint).
void set_ipc_options_override(std::optional<IpcOptions> options);
IpcOptions effective_ipc_options();

}  // namespace deep_link
}  // namespace idasql
