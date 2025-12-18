/**
 * remote.hpp - Remote session client for IDASQL plugin server
 *
 * This header is self-contained and does NOT depend on IDA SDK.
 * It can be used in thin client mode without loading IDA libraries.
 *
 * Usage:
 *   idasql::RemoteSession remote;
 *   if (remote.connect("127.0.0.1", 13337)) {
 *       auto result = remote.query("SELECT * FROM funcs");
 *   }
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET socket_t;
    #define SOCKET_INVALID INVALID_SOCKET
    #define CLOSE_SOCKET closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    typedef int socket_t;
    #define SOCKET_INVALID -1
    #define CLOSE_SOCKET close
#endif

namespace idasql {

//=============================================================================
// Result types (self-contained, no IDA dependency)
//=============================================================================

struct RemoteRow {
    std::vector<std::string> values;

    const std::string& operator[](size_t i) const { return values[i]; }
    size_t size() const { return values.size(); }
};

struct RemoteResult {
    std::vector<std::string> columns;
    std::vector<RemoteRow> rows;
    std::string error;
    bool success = false;

    size_t row_count() const { return rows.size(); }
    size_t column_count() const { return columns.size(); }
    bool empty() const { return rows.empty(); }
};

//=============================================================================
// Remote session client
//=============================================================================

class RemoteSession
{
    socket_t sock_ = SOCKET_INVALID;
    std::string error_;
    bool wsa_init_ = false;

public:
    RemoteSession()
    {
#ifdef _WIN32
        WSADATA wsa;
        wsa_init_ = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
#endif
    }

    ~RemoteSession()
    {
        disconnect();
#ifdef _WIN32
        if (wsa_init_) WSACleanup();
#endif
    }

    // Non-copyable
    RemoteSession(const RemoteSession&) = delete;
    RemoteSession& operator=(const RemoteSession&) = delete;

    bool connect(const std::string& host, int port)
    {
        // Use getaddrinfo for hostname resolution (supports both hostnames and IPs)
        struct addrinfo hints{}, *result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        std::string port_str = std::to_string(port);
        int ret = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
        if (ret != 0 || result == nullptr) {
            error_ = "failed to resolve host: " + host;
            return false;
        }

        sock_ = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (sock_ == SOCKET_INVALID) {
            freeaddrinfo(result);
            error_ = "socket() failed";
            return false;
        }

        if (::connect(sock_, result->ai_addr, static_cast<int>(result->ai_addrlen)) < 0) {
            CLOSE_SOCKET(sock_);
            sock_ = SOCKET_INVALID;
            freeaddrinfo(result);
            error_ = "connect() failed";
            return false;
        }

        freeaddrinfo(result);
        return true;
    }

    void disconnect()
    {
        if (sock_ != SOCKET_INVALID) {
            CLOSE_SOCKET(sock_);
            sock_ = SOCKET_INVALID;
        }
    }

    bool is_connected() const { return sock_ != SOCKET_INVALID; }
    const std::string& error() const { return error_; }

    RemoteResult query(const std::string& sql)
    {
        RemoteResult result;

        if (!is_connected()) {
            result.error = "not connected";
            return result;
        }

        // Build JSON request
        std::string request = "{\"sql\":\"";
        request += json_escape(sql);
        request += "\"}";

        if (!send_message(request)) {
            result.error = "send failed";
            return result;
        }

        std::string response;
        if (!recv_message(response)) {
            result.error = "recv failed";
            return result;
        }

        return parse_response(response);
    }

private:
    static std::string json_escape(const std::string& s)
    {
        std::string out;
        out.reserve(s.size() + 10);
        for (char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:   out += c; break;
            }
        }
        return out;
    }

    bool send_message(const std::string& payload)
    {
        uint32_t len = static_cast<uint32_t>(payload.size());
        if (send(sock_, reinterpret_cast<char*>(&len), 4, 0) != 4) return false;
        if (send(sock_, payload.c_str(), static_cast<int>(len), 0) != static_cast<int>(len)) return false;
        return true;
    }

    bool recv_message(std::string& payload)
    {
        uint32_t len = 0;
        int received = recv(sock_, reinterpret_cast<char*>(&len), 4, 0);
        if (received != 4) return false;
        if (len > 100 * 1024 * 1024) return false;

        payload.resize(len);
        size_t total = 0;
        while (total < len) {
            int n = recv(sock_, payload.data() + total, static_cast<int>(len - total), 0);
            if (n <= 0) return false;
            total += n;
        }
        return true;
    }

    RemoteResult parse_response(const std::string& json)
    {
        RemoteResult result;

        result.success = json.find("\"success\":true") != std::string::npos;

        if (!result.success) {
            auto pos = json.find("\"error\":\"");
            if (pos != std::string::npos) {
                pos += 9;
                result.error = extract_string(json, pos);
            }
            return result;
        }

        // Parse columns
        auto cols_start = json.find("\"columns\":[");
        if (cols_start != std::string::npos) {
            cols_start += 11;
            while (cols_start < json.size() && json[cols_start] != ']') {
                if (json[cols_start] == '"') {
                    cols_start++;
                    result.columns.push_back(extract_string(json, cols_start));
                }
                cols_start++;
            }
        }

        // Parse rows
        auto rows_start = json.find("\"rows\":[");
        if (rows_start != std::string::npos) {
            rows_start += 8;
            while (rows_start < json.size()) {
                if (json[rows_start] == ']' && (rows_start + 1 >= json.size() || json[rows_start + 1] != '[')) {
                    break;
                }
                if (json[rows_start] == '[') {
                    rows_start++;
                    RemoteRow row;
                    while (rows_start < json.size() && json[rows_start] != ']') {
                        if (json[rows_start] == '"') {
                            rows_start++;
                            row.values.push_back(extract_string(json, rows_start));
                        }
                        rows_start++;
                    }
                    result.rows.push_back(std::move(row));
                }
                rows_start++;
            }
        }

        return result;
    }

    // Extract string starting at pos, updating pos to after closing quote
    std::string extract_string(const std::string& json, size_t& pos)
    {
        std::string s;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                pos++;
                switch (json[pos]) {
                    case 'n': s += '\n'; break;
                    case 'r': s += '\r'; break;
                    case 't': s += '\t'; break;
                    case '"': s += '"'; break;
                    case '\\': s += '\\'; break;
                    default: s += json[pos]; break;
                }
            } else {
                s += json[pos];
            }
            pos++;
        }
        return s;
    }
};

} // namespace idasql
