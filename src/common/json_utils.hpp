#pragma once

#include <iomanip>
#include <sstream>
#include <string>

namespace idasql {

inline std::string escape_json(const std::string& input) {
    std::ostringstream oss;
    for (unsigned char c : input) {
        switch (c) {
            case '\"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (c < 0x20) {
                    oss << "\\u"
                        << std::hex << std::uppercase << std::setfill('0')
                        << std::setw(4) << static_cast<int>(c);
                    // reset flags for subsequent writes
                    oss << std::dec;
                } else {
                    oss << static_cast<char>(c);
                }
                break;
        }
    }
    return oss.str();
}

} // namespace idasql
