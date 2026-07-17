#include "true_believers.h"

#include <cstddef>
#include <cstdint>

namespace true_believers {
namespace {

// Reconstruct the original NUL-separated byte stream from the packed
// bitstream. Returns an empty vector on a malformed/truncated blob.
std::vector<uint8_t> decode_blob() {
    std::vector<uint8_t> out;
    const size_t num_symbols = detail::NUM_SYMBOLS;
    if (num_symbols == 0) return out;
    out.reserve(detail::DECODED_SIZE);

    uint8_t max_len = 0;
    for (size_t i = 0; i < num_symbols; ++i)
        if (detail::code_lengths[i] > max_len)
            max_len = detail::code_lengths[i];
    if (max_len == 0) return out;

    // Decode tables, indexed by code length 1..max_len.
    std::vector<uint32_t> num_codes(max_len + 1u, 0);
    std::vector<uint32_t> first_code(max_len + 1u, 0);
    std::vector<uint32_t> first_symbol(max_len + 1u, 0);

    for (size_t i = 0; i < num_symbols; ++i) {
        uint8_t len = detail::code_lengths[i];
        if (len == 0 || len > max_len) return out;  // malformed
        num_codes[len]++;
    }
    uint32_t sum = 0;
    for (uint8_t l = 1; l <= max_len; ++l) { first_symbol[l] = sum; sum += num_codes[l]; }
    for (uint8_t l = 1; l <= max_len; ++l)
        first_code[l] = (l == 1) ? 0u : ((first_code[l - 1] + num_codes[l - 1]) << 1);

    const uint32_t blob_bits = detail::BLOB_BITS;
    uint32_t bit_index = 0;
    uint8_t cur_len = 0;
    uint32_t cur_code = 0;
    while (out.size() < static_cast<size_t>(detail::DECODED_SIZE)) {
        if (bit_index >= blob_bits) { out.clear(); return out; }  // truncated
        uint32_t byte_off = bit_index >> 3;
        uint8_t bit_off = static_cast<uint8_t>(7 - (bit_index & 7u));
        uint8_t bit = (detail::blob[byte_off] >> bit_off) & 1u;
        ++bit_index;
        cur_code = (cur_code << 1) | bit;
        ++cur_len;
        if (cur_len > max_len) { out.clear(); return out; }
        if (num_codes[cur_len] == 0) continue;  // no codes of this length yet
        uint32_t first = first_code[cur_len];
        uint32_t count = num_codes[cur_len];
        if (cur_code >= first && cur_code < first + count) {
            uint32_t idx = first_symbol[cur_len] + (cur_code - first);
            if (idx >= num_symbols) { out.clear(); return out; }
            out.push_back(detail::symbols[idx]);
            cur_code = 0;
            cur_len = 0;
        }
    }
    return out;
}

}  // namespace

std::vector<std::pair<std::string, std::string>> rows() {
    const std::vector<uint8_t> bytes = decode_blob();
    // The stream is NUL-separated fields [handle0, name0, handle1, name1, ...]
    // with a trailing NUL, so splitting on NUL yields exactly 2*N fields.
    std::vector<std::string> fields;
    std::string cur;
    for (uint8_t b : bytes) {
        if (b == 0) { fields.push_back(cur); cur.clear(); }
        else        { cur.push_back(static_cast<char>(b)); }
    }
    std::vector<std::pair<std::string, std::string>> result;
    result.reserve(fields.size() / 2);
    for (size_t i = 0; i + 1 < fields.size(); i += 2)
        result.emplace_back(fields[i], fields[i + 1]);
    return result;
}

}  // namespace true_believers
