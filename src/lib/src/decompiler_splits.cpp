// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// decompiler_splits — Hex-Rays "Split expression" as a table.
//
// Split expression keeps the decompiler from merging narrower operations into
// one wider one at an address: an 8-byte store of two 4-byte fields prints as
// two assignments instead of one `*(_QWORD *)...`. The pseudocode window does it
// for the item under the cursor (hexrays.hpp: vdui_t::split_item); the SDK has
// no call that works without a window. Observed on IDA 9.0, 9.1, 9.2 and 9.4,
// where the window's action and this table store byte-identical data:
//
//   - the state is a blob (tag 'm', start 0) in the node whose index + 1 the
//     function's netnode keeps at altval(2, 'A'), the node Hex-Rays also keeps
//     the function's user comments in;
//   - the blob is the format version (1), pack_dd(count), then per entry in
//     address order pack_dq(addr - func_addr + 1), pack_dd(operand, always 0),
//     pack_dd(flags); a function without entries has no blob;
//   - the low 3 bits of flags give the piece size, 1/2/3/4 = 1/2/4/8 bytes;
//     the other bits are kept as they are.
//
// The decompiler reads the state the next time it decompiles the function; a
// write marks the function's pseudocode dirty. It ignores a blob with another
// version byte, and so does nothing here: such a blob is refused, never
// rewritten. IDA versions other than 9.0-9.4 are refused as a whole.

#include "decompiler.hpp"
#include "function_rowid.hpp"
#include "address_resolution.hpp"

#include <idasql/string_utils.hpp>

#include <algorithm>
#include <cstdlib>
#include <string>
#include <vector>

namespace idasql {
namespace decompiler {
namespace {

constexpr uchar kBlobTag = 'm';
constexpr nodeidx_t kNodeAlt = 2;
constexpr uchar kNodeTag = 'A';
constexpr uchar kFormatVersion = 1;
constexpr uint32 kSizeMask = 7;

struct Entry {
    ea_t ea = BADADDR;
    uint32 opnum = 0;
    uint32 flags = 0;
};

int piece_size_of(uint32 flags) {
    switch (flags & kSizeMask) {
        case 1: return 1;
        case 2: return 2;
        case 3: return 4;
        case 4: return 8;
        default: return 0;
    }
}

uint32 code_of(int64_t piece_size) {
    switch (piece_size) {
        case 1: return 1;
        case 2: return 2;
        case 4: return 3;
        case 8: return 4;
        default: return 0;
    }
}

bool check_version() {
    char buf[32] = {};
    get_kernel_version(buf, sizeof(buf));
    if (splits_version_supported(buf))
        return true;
    xsql::set_vtab_error(std::string("decompiler_splits: the stored split format is verified on IDA "
                                     "9.0-9.4 only; this is IDA ") + buf);
    return false;
}

nodeidx_t state_node(ea_t func_addr, bool create) {
    netnode fn = getnode(func_addr);
    const nodeidx_t stored = fn.altval(kNodeAlt, kNodeTag);
    if (stored != 0)
        return stored - 1;
    if (!create)
        return BADNODE;
    netnode node;
    if (!node.create())
        return BADNODE;
    fn.altset(kNodeAlt, nodeidx_t(node) + 1, kNodeTag);
    return nodeidx_t(node);
}

std::string where(ea_t func_addr) {
    return " (func_addr " + format_ea_hex(func_addr) + ")";
}

// Read a function's entries. false + vtab error when the blob is not one this
// table understands.
bool read_entries(ea_t func_addr, std::vector<Entry>& out) {
    out.clear();
    const nodeidx_t id = state_node(func_addr, false);
    if (id == BADNODE)
        return true;
    bytevec_t blob;
    if (netnode(id).getblob(&blob, 0, kBlobTag) <= 0 || blob.empty())
        return true;
    if (blob[0] != kFormatVersion) {
        xsql::set_vtab_error("decompiler_splits: unrecognised split state version " +
                             std::to_string(blob[0]) + where(func_addr) +
                             "; refusing to read or change it");
        return false;
    }
    const uchar* p = blob.begin() + 1;
    const uchar* end = blob.end();
    const uint32 count = unpack_dd(&p, end);
    for (uint32 i = 0; i < count; ++i) {
        if (p >= end) {
            xsql::set_vtab_error("decompiler_splits: truncated split state" + where(func_addr));
            return false;
        }
        Entry e;
        const uint64 rel = unpack_dq(&p, end);
        e.ea = static_cast<ea_t>(func_addr + rel - 1);
        e.opnum = unpack_dd(&p, end);
        e.flags = unpack_dd(&p, end);
        out.push_back(e);
    }
    if (p != end) {
        xsql::set_vtab_error("decompiler_splits: split state has trailing bytes" + where(func_addr));
        return false;
    }
    return true;
}

bool write_entries(ea_t func_addr, std::vector<Entry> entries) {
    std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
        return a.ea != b.ea ? a.ea < b.ea : a.opnum < b.opnum;
    });
    const nodeidx_t id = state_node(func_addr, !entries.empty());
    if (id == BADNODE)
        return entries.empty();
    netnode node(id);
    if (entries.empty()) {
        node.delblob(0, kBlobTag);
    } else {
        bytevec_t blob;
        blob.push_back(kFormatVersion);
        blob.pack_dd(static_cast<uint32>(entries.size()));
        for (const Entry& e : entries) {
            blob.pack_dq(static_cast<uint64>(e.ea - func_addr + 1));
            blob.pack_dd(e.opnum);
            blob.pack_dd(e.flags);
        }
        if (!node.setblob(blob.begin(), blob.size(), 0, kBlobTag)) {
            xsql::set_vtab_error("decompiler_splits: IDA did not store the split state" +
                                 where(func_addr));
            return false;
        }
    }
    mark_cfunc_dirty(func_addr, false);
    return true;
}

// Rows of one function: the operand-0 entries with a piece size.
bool collect_function(ea_t func_addr, std::vector<SplitRow>& rows) {
    std::vector<Entry> entries;
    if (!read_entries(func_addr, entries))
        return false;
    for (const Entry& e : entries) {
        if (e.opnum != 0 || (e.flags & kSizeMask) == 0)
            continue;
        const int size = piece_size_of(e.flags);
        if (size == 0) {
            xsql::set_vtab_error("decompiler_splits: unrecognised piece size code " +
                                 std::to_string(e.flags & kSizeMask) + " at " +
                                 format_ea_hex(e.ea) + where(func_addr));
            return false;
        }
        rows.push_back(SplitRow{func_addr, e.ea, size});
    }
    return true;
}

// rowid = function index << 32 | the address's position in the function's
// layout (chunks end to end): exact, so two splits never share a key however far
// apart their addresses are, and it does not move when another split of the same
// function is removed. A stored split whose address is no longer in the function
// (stale) sets bit 63 over the low 32 bits of its distance from the entry.
int64_t pack_rowid(ea_t func_addr, ea_t addr) {
    const int fnum = get_func_num(func_addr);
    if (fnum < 0)
        return -1;
    const uint64_t high = static_cast<uint64_t>(static_cast<uint32_t>(fnum)) << 32;
    uint64_t pos = 0;
    if (idasql::detail::function_position(func_addr, addr, pos) && pos <= 0xFFFFFFFFull)
        return static_cast<int64_t>(high | pos);
    return static_cast<int64_t>((uint64_t{1} << 63) | high |
                                (static_cast<uint64_t>(addr - func_addr) & 0xFFFFFFFFull));
}

bool owned_by(ea_t addr, ea_t func_addr) {
    bool found = false;
    idasql_for_each_owner_of(addr, [&](ea_t owner) {
        if (owner == func_addr)
            found = true;
    });
    return found;
}

// Change the piece size at (func_addr, addr): 0 removes the split.
bool apply(ea_t func_addr, ea_t addr, uint32 code) {
    std::vector<Entry> entries;
    if (!read_entries(func_addr, entries))
        return false;
    auto it = std::find_if(entries.begin(), entries.end(),
                           [&](const Entry& e) { return e.ea == addr && e.opnum == 0; });
    if (it == entries.end()) {
        if (code == 0)
            return true;
        entries.push_back(Entry{addr, 0, code});
    } else {
        it->flags = (it->flags & ~kSizeMask) | code;
        if (it->flags == 0)
            entries.erase(it);
    }
    if (!write_entries(func_addr, entries))
        return false;
    // Read back: the next decompile sees exactly this.
    std::vector<Entry> after;
    if (!read_entries(func_addr, after))
        return false;
    auto back = std::find_if(after.begin(), after.end(),
                             [&](const Entry& e) { return e.ea == addr && e.opnum == 0; });
    const uint32 got = back == after.end() ? 0 : (back->flags & kSizeMask);
    if (got != code) {
        xsql::set_vtab_error("decompiler_splits: the split state did not read back as written" +
                             where(func_addr));
        return false;
    }
    return true;
}

bool valid_piece_size(int64_t piece_size) {
    if (code_of(piece_size) != 0)
        return true;
    xsql::set_vtab_error("decompiler_splits: piece_size must be 1, 2, 4 or 8 (bytes), not " +
                         std::to_string(piece_size));
    return false;
}

} // namespace

// The IDA versions whose stored form was verified (see the header comment).
bool splits_version_supported(const char* kernel_version) {
    if (kernel_version == nullptr)
        return false;
    char* end = nullptr;
    const long major = std::strtol(kernel_version, &end, 10);
    if (end == kernel_version || *end != '.')
        return false;
    const char* minor_text = end + 1;
    const long minor = std::strtol(minor_text, &end, 10);
    if (end == minor_text)
        return false;
    return major == 9 && minor >= 0 && minor <= 4;
}

SplitsInFuncIterator::SplitsInFuncIterator(ea_t func_addr) {
    if (!check_version())
        return;
    if (!idasql_is_func_start(func_addr))
        return;
    collect_function(func_addr, rows_);
}

bool SplitsInFuncIterator::next() {
    if (!started_) {
        started_ = true;
        idx_ = 0;
        return !rows_.empty();
    }
    if (idx_ + 1 < rows_.size()) {
        ++idx_;
        return true;
    }
    idx_ = rows_.size();
    return false;
}

bool SplitsInFuncIterator::eof() const {
    return started_ && idx_ >= rows_.size();
}

void SplitsInFuncIterator::column(xsql::FunctionContext& ctx, int col) {
    if (idx_ >= rows_.size()) {
        ctx.result_null();
        return;
    }
    const SplitRow& r = rows_[idx_];
    switch (col) {
        case 0: ctx.result_int64(static_cast<int64_t>(r.func_addr)); break;
        case 1: ctx.result_int64(static_cast<int64_t>(r.addr)); break;
        case 2: ctx.result_int(r.piece_size); break;
        default: ctx.result_null(); break;
    }
}

int64_t SplitsInFuncIterator::rowid() const {
    if (idx_ >= rows_.size())
        return -1;
    return pack_rowid(rows_[idx_].func_addr, rows_[idx_].addr);
}

CachedTableDef<SplitRow> define_decompiler_splits() {
    return cached_table<SplitRow>("decompiler_splits")
        .no_shared_cache()
        .estimate_rows([]() -> size_t { return 16; })
        // Full scan: one netnode lookup per function, no decompilation.
        .cache_builder([](std::vector<SplitRow>& rows) {
            rows.clear();
            if (!check_version())
                return;
            const size_t qty = get_func_qty();
            for (size_t i = 0; i < qty; ++i) {
                const ea_t f = idasql_func_ea_by_num(i);
                if (f == BADADDR)
                    continue;
                if (!collect_function(f, rows))
                    return;
            }
        })
        .rowid([](const SplitRow& row) -> int64_t { return pack_rowid(row.func_addr, row.addr); })
        .row_lookup([](SplitRow& row, int64_t rowid) -> bool {
            if (!check_version())
                return false;
            // Bit 63 marks a stale split (see pack_rowid); the function index
            // sits below it either way.
            const int64_t fnum = static_cast<int64_t>((static_cast<uint64_t>(rowid) >> 32) & 0x7FFFFFFFull);
            const ea_t f = idasql_func_ea_by_num(static_cast<size_t>(fnum));
            if (f == BADADDR)
                return false;
            std::vector<SplitRow> rows;
            if (!collect_function(f, rows))
                return false;
            for (const SplitRow& r : rows) {
                if (pack_rowid(r.func_addr, r.addr) == rowid) {
                    row = r;
                    return true;
                }
            }
            return false;
        })
        .column_int64("func_addr", [](const SplitRow& row) -> int64_t {
            return static_cast<int64_t>(row.func_addr);
        })
        .column_int64("addr", [](const SplitRow& row) -> int64_t {
            return static_cast<int64_t>(row.addr);
        })
        .column_int_rw(
            "piece_size", [](const SplitRow& row) -> int { return row.piece_size; },
            [](SplitRow& row, xsql::FunctionArg value) -> bool {
                if (value.is_nochange())
                    return true;
                if (value.is_null()) {
                    xsql::set_vtab_error(
                        "decompiler_splits: piece_size cannot be NULL; DELETE the row to unsplit");
                    return false;
                }
                const auto exact = idasql::write_int(value, "decompiler_splits", "piece_size", INT64_MIN, INT64_MAX);
                if (!exact)
                    return false;
                const int64_t size = *exact;
                if (!check_version() || !valid_piece_size(size))
                    return false;
                if (!apply(row.func_addr, row.addr, code_of(size)))
                    return false;
                row.piece_size = static_cast<int>(size);
                return true;
            })
        .filter_eq("func_addr", [](int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<SplitsInFuncIterator>(static_cast<ea_t>(func_addr));
        }, 5.0, 4.0)
        .deletable([](SplitRow& row) -> bool {
            if (!check_version())
                return false;
            return apply(row.func_addr, row.addr, 0);
        })
        .insertable([](int argc, xsql::FunctionArg* argv) -> bool {
            // argv[0]=func_addr, argv[1]=addr, argv[2]=piece_size
            if (!check_version())
                return false;
            if (argc < 3 || argv[1].is_null() || argv[2].is_null()) {
                xsql::set_vtab_error(
                    "decompiler_splits: INSERT needs addr and piece_size (func_addr is optional)");
                return false;
            }
            ea_t addr = BADADDR;
            if (!idasql::write_address(argv[1], "decompiler_splits", "addr", addr))
                return false;
            const auto exact = idasql::write_int(argv[2], "decompiler_splits", "piece_size", INT64_MIN, INT64_MAX);
            if (!exact)
                return false;
            const int64_t size = *exact;
            if (!valid_piece_size(size))
                return false;
            if (!is_code(get_flags(addr)) || get_item_head(addr) != addr) {
                xsql::set_vtab_error("decompiler_splits: " + format_ea_hex(addr) +
                                     " is not the start of an instruction");
                return false;
            }
            ea_t func_addr = BADADDR;
            if (argv[0].is_null()) {
                func_addr = idasql_func_start(addr);
                if (func_addr == BADADDR) {
                    xsql::set_vtab_error("decompiler_splits: " + format_ea_hex(addr) +
                                         " is not in a function");
                    return false;
                }
            } else {
                if (!idasql::write_address(argv[0], "decompiler_splits", "func_addr", func_addr))
                    return false;
                if (!idasql_is_func_start(func_addr)) {
                    xsql::set_vtab_error("decompiler_splits: func_addr " + format_ea_hex(func_addr) +
                                         " is not a function entry");
                    return false;
                }
                if (!owned_by(addr, func_addr)) {
                    xsql::set_vtab_error("decompiler_splits: " + format_ea_hex(addr) +
                                         " is not in the function at " + format_ea_hex(func_addr));
                    return false;
                }
            }
            std::vector<SplitRow> existing;
            if (!collect_function(func_addr, existing))
                return false;
            for (const SplitRow& r : existing) {
                if (r.addr == addr) {
                    xsql::set_vtab_error("decompiler_splits: " + format_ea_hex(addr) +
                                         " is already split into " + std::to_string(r.piece_size) +
                                         "-byte pieces; UPDATE piece_size or DELETE the row");
                    return false;
                }
            }
            return apply(func_addr, addr, code_of(size));
        })
        .build();
}

} // namespace decompiler
} // namespace idasql
