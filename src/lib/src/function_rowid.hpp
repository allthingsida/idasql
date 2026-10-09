// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "ida_headers.hpp"

#include <xsql/vtable.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace idasql::detail {

// Stable, non-negative rowids for rows identified by a function plus a local
// ordinal. The high 31 bits hold IDA's function ordinal; the low 32 bits hold
// the row's index within that function. Both a full scan and a func_addr
// pushdown can compute this identity without enumerating earlier functions.
inline int64_t pack_function_rowid(ea_t func_addr, std::size_t local_index) {
    const int function_index = get_func_num(func_addr);
    if (function_index < 0 || local_index > std::numeric_limits<uint32_t>::max()) {
        xsql::set_vtab_error("rowid coordinate exceeds the function/local packing range");
        return -1;
    }
    const uint64_t packed = (static_cast<uint64_t>(static_cast<uint32_t>(function_index)) << 32) |
                            static_cast<uint32_t>(local_index);
    return static_cast<int64_t>(packed);
}

// Microcode has an additional 8-value maturity coordinate. Reserve three bits
// below the function ordinal and 29 bits for the per-function row index, so
// different lifting rungs never alias while default and pushed scans agree.
inline int64_t pack_function_maturity_rowid(ea_t func_addr, uint8_t maturity_ordinal,
                                            std::size_t local_index) {
    constexpr std::size_t kLocalLimit = (std::size_t{1} << 29) - 1;
    const int function_index = get_func_num(func_addr);
    if (function_index < 0 || maturity_ordinal > 7 || local_index > kLocalLimit) {
        xsql::set_vtab_error("rowid coordinate exceeds the function/maturity/local packing range");
        return -1;
    }
    const uint64_t packed = (static_cast<uint64_t>(static_cast<uint32_t>(function_index)) << 32) |
                            (static_cast<uint64_t>(maturity_ordinal) << 29) |
                            static_cast<uint64_t>(local_index);
    return static_cast<int64_t>(packed);
}

// ----------------------------------------------------------------------------
// Rows keyed by (owning function, address)
// ----------------------------------------------------------------------------
// A function is not necessarily contiguous, and one tail chunk may belong to
// several functions. Tables that report a func_addr for an address (blocks,
// instructions, xrefs, ...) therefore carry one row per OWNER for an address in
// a shared tail, and the rowid must tell those rows apart: SQLite de-duplicates
// a MULTI-INDEX OR plan by rowid, so an address-only rowid silently drops the
// second owner's rows from `func_addr = A OR (func_addr = C AND ...)`.

// The chunks of one function in iteration order -- the entry chunk first, then
// each tail in address order -- laid end to end. A position is the byte offset
// of an address in that concatenation, so (function, position) names an
// address inside the function independently of where its chunks live.
class FunctionLayout {
public:
    explicit FunctionLayout(ea_t owner) {
        if (!idasql_is_func_start(owner))
            return;
        uint64_t base = 0;
        idasql_for_each_func_chunk(owner, [&](const range_t& chunk, bool) {
            chunks_.push_back({chunk.start_ea, chunk.end_ea, base});
            base += static_cast<uint64_t>(chunk.end_ea - chunk.start_ea);
        });
    }

    bool valid() const { return !chunks_.empty(); }

    bool position_of(ea_t ea, uint64_t& pos) const {
        for (const Chunk& chunk : chunks_) {
            if (ea >= chunk.start && ea < chunk.end) {
                pos = chunk.base + static_cast<uint64_t>(ea - chunk.start);
                return true;
            }
        }
        return false;
    }

    bool address_at(uint64_t pos, ea_t& ea) const {
        for (const Chunk& chunk : chunks_) {
            const uint64_t size = static_cast<uint64_t>(chunk.end - chunk.start);
            if (pos >= chunk.base && pos - chunk.base < size) {
                ea = chunk.start + static_cast<ea_t>(pos - chunk.base);
                return true;
            }
        }
        return false;
    }

private:
    struct Chunk {
        ea_t start;
        ea_t end;
        uint64_t base;
    };
    std::vector<Chunk> chunks_;
};

// Position of `ea` inside function `owner` (an entry address). The common case,
// an address in the entry chunk, needs no chunk walk.
inline bool function_position(ea_t owner, ea_t ea, uint64_t& pos) {
    idasql_func_info_t fi;
    if (!idasql_func_info(owner, &fi) || fi.start_ea != owner)
        return false;
    if (ea >= fi.start_ea && ea < fi.end_ea) {
        pos = static_cast<uint64_t>(ea - fi.start_ea);
        return true;
    }
    return FunctionLayout(owner).position_of(ea, pos);
}

// The bit-63 (outside every function) rowid form: segment index above a 44-bit
// local part.
constexpr unsigned kSegmentRowidLocalBits = 44;
constexpr uint64_t kSegmentRowidSegments = uint64_t{1} << (63 - kSegmentRowidLocalBits);

// Rowid for a row identified by its owning function and an address, plus an
// optional sub-index below the address (an operand number). Function-owned rows
// use pack_function_rowid(owner, position << sub_bits | sub), so two owners of a
// shared tail never collide. A row outside every function (owner == BADADDR)
// sets bit 63 and packs the segment ordinal over the segment offset instead;
// the two forms never meet. Both are decoded by unpack_owned_address_rowid.
inline int64_t pack_owned_address_rowid(ea_t owner, ea_t ea, uint32_t sub = 0,
                                        unsigned sub_bits = 0) {
    uint64_t offset = 0;
    if (owner != BADADDR) {
        if (!function_position(owner, ea, offset)) {
            xsql::set_vtab_error("rowid: address is not inside its owning function");
            return -1;
        }
    } else {
        const int seg_index = get_segm_num(ea);
        const ea_t seg_start = seg_index >= 0 ? idasql_segment_ea_by_num(seg_index) : BADADDR;
        if (seg_start == BADADDR) {
            xsql::set_vtab_error("rowid: address is outside every segment");
            return -1;
        }
        // Outside functions the address is a segment offset, which can be far
        // larger than any function's layout (a GiB-sized firmware segment): 19 bits
        // of segment index over 44 bits of (offset << sub_bits | sub).
        offset = static_cast<uint64_t>(ea - seg_start);
        if (static_cast<uint64_t>(seg_index) >= kSegmentRowidSegments ||
            offset >= (uint64_t{1} << (kSegmentRowidLocalBits - sub_bits))) {
            xsql::set_vtab_error("rowid coordinate exceeds the segment/offset packing range");
            return -1;
        }
        const uint64_t local = (offset << sub_bits) | sub;
        return static_cast<int64_t>((uint64_t{1} << 63) |
                                    (static_cast<uint64_t>(seg_index) << kSegmentRowidLocalBits) | local);
    }
    if (offset > (std::numeric_limits<uint32_t>::max() >> sub_bits)) {
        xsql::set_vtab_error("rowid coordinate exceeds the function/position packing range");
        return -1;
    }
    return pack_function_rowid(owner, static_cast<std::size_t>((offset << sub_bits) | sub));
}

// Inverse of pack_owned_address_rowid. `owner` is BADADDR for a row outside
// every function. Returns false for a rowid that names no current address.
inline bool unpack_owned_address_rowid(int64_t rowid, unsigned sub_bits, ea_t& owner,
                                       ea_t& ea, uint32_t& sub) {
    const uint64_t raw = static_cast<uint64_t>(rowid);
    if ((raw >> 63) != 0) {
        const uint64_t local = raw & ((uint64_t{1} << kSegmentRowidLocalBits) - 1);
        const uint64_t index = (raw >> kSegmentRowidLocalBits) & (kSegmentRowidSegments - 1);
        const uint64_t offset = local >> sub_bits;
        sub = static_cast<uint32_t>(local & ((uint64_t{1} << sub_bits) - 1));
        idasql_segment_info_t seg;
        if (!idasql_segment_info(idasql_segment_ea_by_num(static_cast<int>(index)), &seg)
            || offset >= static_cast<uint64_t>(seg.end_ea - seg.start_ea))
            return false;
        owner = BADADDR;
        ea = seg.start_ea + static_cast<ea_t>(offset);
        return true;
    }
    const uint64_t local = raw & 0xFFFFFFFFull;
    const uint64_t index = (raw >> 32) & 0x7FFFFFFFull;
    const uint64_t offset = local >> sub_bits;
    sub = static_cast<uint32_t>(local & ((uint64_t{1} << sub_bits) - 1));
    owner = idasql_func_ea_by_num(static_cast<size_t>(index));
    if (owner == BADADDR)
        return false;
    return FunctionLayout(owner).address_at(offset, ea);
}

} // namespace idasql::detail
