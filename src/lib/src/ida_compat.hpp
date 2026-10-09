// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * ida_compat.hpp - IDA SDK cross-version compatibility shims.
 *
 * Centralizes feature detection and the wrappers that paper over
 * API differences between IDA SDK versions. Included via ida_headers.hpp,
 * so every translation unit picks the same definitions. The wrapper bodies
 * live in ida_compat.cpp (built once, with the full SDK); only the macros,
 * the small structs, the declarations and the callback templates are here.
 *
 * Feature macros are named IDASQL_HAS_<FEATURE> and resolve to 0 or 1.
 * Use `#if IDASQL_HAS_FOO` at call sites; never repeat magic SDK numbers
 * outside this file.
 *
 * ea-based wrappers (IDASQL_HAS_EA_API). SDK 9.4 deprecates every API that
 * hands out a func_t*, segment_t* or hidden_range_t*, plus qflow_chart_t and
 * mba_ranges_t. These wrappers take an address and return values; on 9.4 they
 * use only the ea-based replacements, on 9.0-9.3 the pointer calls. Library
 * code calls these, never the deprecated APIs. Semantics were measured on 9.4
 * against the old calls (identical results; see each wrapper's comment).
 *
 *   functions -- "the function containing ea" = get_func(ea),
 *   i.e. the OWNER for an address in a tail chunk:
 *     ea_t    idasql_func_start(ea_t ea)                  BADADDR if none
 *     bool    idasql_is_func_start(ea_t ea)               ea is an entry address
 *     ea_t    idasql_func_ea_by_num(size_t n)             BADADDR if out of range
 *     bool    idasql_func_info(ea_t ea, idasql_func_info_t *out)
 *               {start_ea, end_ea (entry chunk), flags, frsize, frregs, argsize}
 *     uint64  idasql_func_flags(ea_t ea)                  0 if none
 *     bool    idasql_set_func_flags(ea_t ea, uint64 flags)
 *     size_t  idasql_func_tail_qty(ea_t ea)
 *     ssize_t idasql_get_func_cmt(qstring *out, ea_t ea, bool repeatable)
 *     bool    idasql_set_func_cmt(ea_t ea, const char *cmt, bool repeatable)
 *     asize_t idasql_func_frame_size(ea_t ea)             get_frame_size
 *     bool    idasql_fchunk_info(ea_t ea, idasql_fchunk_info_t *out)
 *               {start_ea, end_ea, flags, is_tail()} of the CHUNK at ea
 *     ea_t    idasql_fchunk_ea_by_num(int n)
 *     size_t  idasql_for_each_func_chunk(ea_t ea, cb(const range_t &, bool is_entry))
 *     size_t  idasql_func_chunk_count(ea_t ea)
 *     asize_t idasql_func_total_size(ea_t ea)
 *     size_t  idasql_for_each_tail_owner(ea_t tail_ea, cb(ea_t owner))
 *     size_t  idasql_for_each_owner_of(ea_t ea, cb(ea_t owner))
 *     class   idasql_func_item_iterator   set(ea), current(), next_code(), next_head()
 *     class   idasql_flow_chart           create_func(ea, flags), create_range(ea1, ea2, flags);
 *               blocks[i], size(), nproper, nsucc/succ, npred/pred, calc_block_type
 *   segments -- "the segment containing ea":
 *     bool    idasql_segment_info(ea_t ea, idasql_segment_info_t *out)
 *               {start_ea, end_ea, perm, bitness, type}
 *     ea_t    idasql_segment_ea_by_num(int n)             BADADDR if out of range
 *     ea_t    idasql_next_segment_ea(ea_t ea)             get_next_seg, gaps included
 *     ea_t    idasql_prev_segment_ea(ea_t ea)             get_prev_seg, gaps/BADADDR included
 *     ssize_t idasql_segment_name(qstring *out, ea_t ea)  -1 if no segment
 *     ssize_t idasql_segment_class(qstring *out, ea_t ea) -1 if no segment
 *     bool    idasql_set_segment_name(ea_t ea, const char *name)
 *     bool    idasql_set_segment_class(ea_t ea, const char *sclass)
 *     bool    idasql_set_segment_perm(ea_t ea, uchar perm)
 *     move_segm_code_t idasql_move_segment(ea_t ea, ea_t to, int flags = 0)
 *     bool    idasql_hidden_range_by_num(int n, idasql_hidden_range_t *out)
 *               {start_ea, end_ea, description, header, footer, visible, color}
 *   types -- struct/union member edits (IDASQL_HAS_INPLACE_UDM_EDIT):
 *     tinfo_code_t idasql_udt_add_udm(tinfo_t &tif, const udm_t &udm, uint etf, int times, ssize_t idx)
 *     tinfo_code_t idasql_udt_del_udm(tinfo_t &tif, size_t idx)
 *   decompiler (declared only after <hexrays.hpp>, i.e. in library TUs):
 *     cfuncptr_t idasql_decompile(ea_t ea, hexrays_failure_t *hf = nullptr, int decomp_flags = 0)
 *     mba_t     *idasql_gen_microcode(ea_t ea, hexrays_failure_t *hf, const mlist_t *retlist,
 *                                     int decomp_flags, mba_maturity_t reqmat)
 */

#pragma once

// The plugin target includes this header directly after kernwin.hpp. Pull in
// the complete bookmark/place definitions instead of depending on a
// precompiled header to include them first.
#include <moves.hpp>

// Cutoffs empirically verified against IDA SDK headers 9.0, 9.1, 9.2, 9.3.
//
//  9.0 SP1 renamed tinfo_t::find_edm() to get_edm()/get_edm_by_value() without changing
//              IDA_SDK_VERSION (900): detected by member in code_operand_repr.cpp.
//  9.0 SP1 also added get_undo_action_label()/get_redo_action_label() (undo.hpp), detected
//              from the header by src/lib/CMakeLists.txt (IDASQL_SDK_HAS_UNDO_LABELS),
//              and HTI_SEMICOLON (typeinf.hpp).
//  9.1 added:  open_database()'s third `args` parameter.
//  9.2 added:  ctree_parentee_t::parent_item(),
//              in-place add_udm/del_udm on a fixed struct that another struct
//              embeds by value (9.0/9.1 abort with INTERR 821; see
//              the types section below),
//              is_ida_library() default arguments,
//              callcnv_t typedef, GENDSM_UNHIDE,
//              place_t::equals() (and the idaplace_t__equals runtime export
//              — shimmed locally in ida_compat.cpp).
//  9.3 added:  BWN_TITREE (handled via plain `#ifdef`),
//              bookmarks_t::get_by_inode().
//  9.4 added:  ida:// deep links: open_ida_link()/ui_open_ida_link and the
//              ida_ipc_<pid> navigation endpoint in ida.exe. The whole idasql
//              deep-link surface (tables, views, ida_open_link, the setting and
//              the `idasql link` CLI verbs) exists only in 9.4+ builds.
//              The ea-based function / segment / hidden-range / flow-chart /
//              decompiler API (get_func_start, get_func_entry_info,
//              function_item_iterator_t, qflow_chart_ea_t, get_segment_info,
//              decomp_ranges_t, ...); every func_t*, segment_t* and
//              hidden_range_t* API became DEPRECATED (qflow_chart_t and
//              mba_ranges_t too). IDASQL_HAS_EA_API selects the wrappers' branch.
#define IDASQL_HAS_PARENT_ITEM             (IDA_SDK_VERSION >= 920)
#define IDASQL_HAS_INPLACE_UDM_EDIT        (IDA_SDK_VERSION >= 920)
#define IDASQL_HAS_OPEN_DATABASE_3ARG      (IDA_SDK_VERSION >= 910)
#define IDASQL_HAS_IS_IDA_LIBRARY_NOARG    (IDA_SDK_VERSION >= 920)
#define IDASQL_HAS_BOOKMARKS_GET_BY_INODE  (IDA_SDK_VERSION >= 930)
#define IDASQL_HAS_DEEP_LINKS              (IDA_SDK_VERSION >= 940)
// libfuncs.hpp (get_idasgn_header_by_short_name: a .sig's processor, module count
// and startup flag) is in every SDK from 9.0 SP1 on, not in 9.0 GA.
#if defined(__has_include)
#if __has_include(<libfuncs.hpp>)
#define IDASQL_HAS_IDASGN_HEADER           1
#endif
#endif
#ifndef IDASQL_HAS_IDASGN_HEADER
#define IDASQL_HAS_IDASGN_HEADER           0
#endif
#define IDASQL_HAS_EA_API                  (IDA_SDK_VERSION >= 940)
#ifdef IDASQL_SDK_HAS_UNDO_LABELS
#define IDASQL_HAS_UNDO_LABELS             IDASQL_SDK_HAS_UNDO_LABELS
#else
#define IDASQL_HAS_UNDO_LABELS             (IDA_SDK_VERSION >= 910)
#endif

#if IDA_SDK_VERSION < 920
// callcnv_t was introduced in 9.2 as a distinct type for calling-convention
// values extracted from cm_t. On older SDKs, cm_t is the underlying type.
using callcnv_t = cm_t;

// HTI_SEMICOLON: optional-semicolon mode for parse_decls. Added in 9.0 SP1.
// The #ifndef guard means this no-op fallback only kicks in on 9.0 GA where
// the flag genuinely has no SDK constant — from 9.0 SP1 on the real value
// from typeinf.hpp wins. Falling back to 0 makes the bitmask OR inert: the
// parser will be strict about trailing semicolons on 9.0 GA.
#ifndef HTI_SEMICOLON
#define HTI_SEMICOLON 0
#endif

// GENDSM_UNHIDE: generate_disasm_line flag to render hidden objects.
// Added in 9.2. Falling back to 0 means hidden segments/functions/ranges
// stay hidden in the disasm we produce on older SDKs.
#ifndef GENDSM_UNHIDE
#define GENDSM_UNHIDE 0
#endif
#endif

/**
 * Respect the user's auto-analysis choice when waiting for AA.
 *
 * idasql calls auto_wait() defensively before write operations so that
 * renames/type applies/etc. don't fight in-progress analysis. When the
 * user has explicitly disabled auto-analysis (`idat -a`, the
 * Options→General→Analysis toggle, or a runtime enable_auto(false)),
 * dragging them back into AA defeats their choice. is_auto_enabled()
 * reflects the effective state across all three opt-out paths.
 *
 * See allthingsida/idasql#31.
 */
void idasql_auto_wait();

/**
 * is_ida_library() distinguishes the idalib/CLI runtime from a full IDA (GUI
 * plugin) runtime. It gained default arguments in SDK 9.2; older SDKs require
 * all three. Wrap it so call sites never repeat the version guard.
 */
bool idasql_is_ida_library();

/**
 * Resolve a bookmark dirtree inode to its store slot.
 *
 * bookmarks_t::get_by_inode() was added in IDA 9.3. Older SDKs expose enough
 * stable API to scan the store and match the coordinate used for a dirtree
 * leaf: the address for idaplace bookmarks or the ordinal for tiplace
 * bookmarks.
 */
uint32 idasql_bookmarks_get_by_inode(
    lochist_entry_t *out_entry, qstring *out_desc, inode_t inode, void *ud);

// ea-based wrappers (see the list at the top of this file).

// ============================================================================

/**
 * Functions: ea-based function, chunk, item-iterator and
 * flow-chart wrappers. Included from ida_compat.hpp; see the wrapper list
 * there.
 *
 * SDK 9.4 deprecates every API that hands out a func_t* (the pointer is
 * invalidated by del_func, add_func, set_func_start/end, undo and recursive
 * IDB events). On 9.4 these wrappers use only the ea-based replacements; on
 * 9.0-9.3, where those replacements do not exist, they keep the func_t* calls.
 * Every wrapper takes an address and returns values, so call sites never hold
 * a func_t*.
 *
 * "Function" below always means the function that get_func(ea) returned: for
 * an address in a tail chunk, the tail's OWNER. The 9.4 calls that take an
 * address are not uniform about that (get_func_flags, set_func_flags and
 * set_func_cmt_ea act on the CHUNK containing the address, so a tail address
 * reaches the tail, not the owner), so every wrapper resolves the function
 * start first.
 */

#include <frame.hpp>
#include <funcs.hpp>
#include <gdl.hpp>

/**
 * The function containing `ea` (owner of a tail), or BADADDR.
 */
ea_t idasql_func_start(ea_t ea);

/**
 * True when `ea` is the entry address of a function. Use this instead of
 * `idasql_func_start(ea) == ea`, which is also true for ea == BADADDR.
 */
bool idasql_is_func_start(ea_t ea);

/**
 * Entry address of function number `n` (0..get_func_qty()-1), or BADADDR.
 */
ea_t idasql_func_ea_by_num(size_t n);

/**
 * Snapshot of a function's entry-chunk fields (what func_t carried).
 * end_ea ends the ENTRY CHUNK only; see idasql_func_total_size() and
 * idasql_for_each_func_chunk() for the whole function.
 */
struct idasql_func_info_t
{
    ea_t start_ea = BADADDR;
    ea_t end_ea = BADADDR;
    uint64 flags = 0;     // FUNC_* of the function (never FUNC_TAIL)
    asize_t frsize = 0;   // local variables part of the frame
    ushort frregs = 0;    // saved registers
    asize_t argsize = 0;  // bytes purged on return
};

/**
 * Fill `out` for the function containing `ea`. Returns false (and leaves
 * `out` untouched) when `ea` is in no function.
 */
bool idasql_func_info(ea_t ea, idasql_func_info_t *out);

/**
 * FUNC_* flags of the function containing `ea`; 0 when there is none.
 */
uint64 idasql_func_flags(ea_t ea);

/**
 * Replace the FUNC_* flags of the function containing `ea` (the old
 * `pfn->flags = flags; update_func(pfn)`). False when there is no function.
 */
bool idasql_set_func_flags(ea_t ea, uint64 flags);

/**
 * Number of tail chunks of the function containing `ea`; 0 when there is none.
 */
size_t idasql_func_tail_qty(ea_t ea);

/**
 * Function comment of the function containing `ea` (get_func_cmt semantics:
 * comment length, or -1 when there is none or no function).
 */
ssize_t idasql_get_func_cmt(qstring *out, ea_t ea, bool repeatable);

/**
 * Set (or, with "", delete) the comment of the function containing `ea`.
 */
bool idasql_set_func_cmt(ea_t ea, const char *cmt, bool repeatable);

/**
 * Full stack-frame size (get_frame_size) of the function containing `ea`;
 * 0 when there is none.
 */
asize_t idasql_func_frame_size(ea_t ea);

/**
 * Function chunks.
 *
 * A function is not necessarily contiguous: besides its entry chunk
 * [start_ea, end_ea) it may own any number of tail chunks anywhere in the
 * database, and one tail may be shared by several functions. The entry-chunk
 * end describes the ENTRY CHUNK ONLY; code that means "the whole function"
 * must go through these helpers.
 *
 * Note: on both the legacy and the ea-based tail iterators, first() yields
 * only the tail chunks; main() followed by next() yields the entry chunk
 * first and then every tail in address order.
 */

/**
 * The chunk (entry or tail) containing an address.
 */
struct idasql_fchunk_info_t
{
    ea_t start_ea = BADADDR;
    ea_t end_ea = BADADDR;
    uint64 flags = 0;  // the CHUNK's flags: FUNC_TAIL set for a tail
    bool is_tail() const { return (flags & FUNC_TAIL) != 0; }
};

/**
 * Fill `out` for the chunk containing `ea`. Returns false (and leaves `out`
 * untouched) when `ea` is in no function chunk.
 */
bool idasql_fchunk_info(ea_t ea, idasql_fchunk_info_t *out);

/**
 * Start address of chunk number `n` (0..get_fchunk_qty()-1), or BADADDR.
 */
ea_t idasql_fchunk_ea_by_num(int n);

// Invoke cb(const range_t &chunk, bool is_entry) for every chunk of the
// function containing `ea`: the entry chunk first, then each tail. Returns the
// number of chunks visited (0 when `ea` is not inside a function).
template <typename Callback>
inline size_t idasql_for_each_func_chunk(ea_t ea, Callback &&cb)
{
    size_t count = 0;
#if IDASQL_HAS_EA_API
    const ea_t start = get_func_start(ea);
    if (start == BADADDR)
        return 0;
    function_tail_iterator_t fti;
    if (!fti.set(start))
        return 0;
    for (bool ok = fti.main(); ok; ok = fti.next())
    {
        range_t chunk;
        fti.chunk(&chunk);
        cb(static_cast<const range_t &>(chunk), count == 0);
        ++count;
    }
#else
    func_t *pfn = get_func(ea);
    if (pfn == nullptr)
        return 0;
    func_tail_iterator_t fti;
    if (!fti.set(pfn))
        return 0;
    for (bool ok = fti.main(); ok; ok = fti.next())
    {
        cb(fti.chunk(), count == 0);
        ++count;
    }
#endif
    return count;
}

// Number of chunks (entry + tails) of the function containing `ea`; 0 if none.
size_t idasql_func_chunk_count(ea_t ea);

// Total size in bytes of every chunk of the function containing `ea`.
asize_t idasql_func_total_size(ea_t ea);

// Invoke cb(ea_t owner_start_ea) for every function that owns the tail chunk
// containing `tail_ea`. A tail may be shared by several functions; its primary
// owner is only one of them. Returns the number of owners visited (0 when
// `tail_ea` is not in a tail chunk).
template <typename Callback>
inline size_t idasql_for_each_tail_owner(ea_t tail_ea, Callback &&cb)
{
    size_t count = 0;
#if IDASQL_HAS_EA_API
    if (!is_function_tail(tail_ea))
        return 0;
    function_parent_iterator_t fpi;
    if (!fpi.set(tail_ea))
        return 0;
    for (bool ok = fpi.first(); ok; ok = fpi.next())
    {
        cb(fpi.parent());
        ++count;
    }
#else
    func_t *tail = get_fchunk(tail_ea);
    if (tail == nullptr || (tail->flags & FUNC_TAIL) == 0)
        return 0;
    func_parent_iterator_t fpi;
    if (!fpi.set(tail))
        return 0;
    for (bool ok = fpi.first(); ok; ok = fpi.next())
    {
        cb(fpi.parent());
        ++count;
    }
#endif
    return count;
}

// Invoke cb(ea_t owner_start_ea) for every function whose body contains `ea`:
// the function itself for an address in an entry chunk, every owner of the
// tail for an address in a (possibly shared) tail chunk, nothing outside any
// function. Returns the number of owners visited.
template <typename Callback>
inline size_t idasql_for_each_owner_of(ea_t ea, Callback &&cb)
{
    idasql_fchunk_info_t chunk;
    if (!idasql_fchunk_info(ea, &chunk))
        return 0;
    if (!chunk.is_tail())
    {
        cb(chunk.start_ea);
        return 1;
    }
    return idasql_for_each_tail_owner(ea, cb);
}

/**
 * Item iterator over a function: the entry chunk first, then every tail in
 * address order (func_item_iterator_t order).
 *
 * The underlying SDK iterator locks the function for as long as it exists,
 * and IDA refuses to undefine a locked function's instructions. Collect the
 * addresses, then let the iterator go out of scope before mutating.
 */
class idasql_func_item_iterator
{
#if IDASQL_HAS_EA_API
    function_item_iterator_t it_;
#else
    func_item_iterator_t it_;
#endif

public:
    // Position at the entry of the function containing `ea` (any address in
    // it, including a tail address, which selects the tail's owner). False
    // when `ea` is in no function.
    bool set(ea_t ea)
    {
#if IDASQL_HAS_EA_API
        const ea_t start = get_func_start(ea);
        return start != BADADDR && it_.set(start);
#else
        func_t *pfn = get_func(ea);
        return pfn != nullptr && it_.set(pfn);
#endif
    }
    ea_t current() const { return it_.current(); }
    bool next_code() { return it_.next_code(); }
    bool next_head() { return it_.next_head(); }
};

/**
 * Flow chart (basic blocks) of a function or of an address range.
 *
 * Exposes the members call sites read from qflow_chart_t, unchanged:
 * `blocks[i]` (qbasic_block_t: start_ea, end_ea, succ, pred), size(),
 * nproper, nsucc(i), succ(i, j), npred(i), pred(i, j), calc_block_type(i).
 * Building is the only API change: create_func() / create_range() replace
 * create("", pfn, ea1, ea2, flags).
 */
#if IDASQL_HAS_EA_API
using idasql_flow_chart_base = qflow_chart_ea_t;
#else
using idasql_flow_chart_base = qflow_chart_t;
#endif

class idasql_flow_chart : private idasql_flow_chart_base
{
public:
    using idasql_flow_chart_base::blocks;
    using idasql_flow_chart_base::nproper;
    using idasql_flow_chart_base::size;
    using idasql_flow_chart_base::nsucc;
    using idasql_flow_chart_base::succ;
    using idasql_flow_chart_base::npred;
    using idasql_flow_chart_base::pred;
    using idasql_flow_chart_base::calc_block_type;

    // Chart the whole function containing `ea` (a tail address selects the
    // tail's owner). False, with an empty chart, when `ea` is in no function.
    bool create_func(ea_t ea, int flags)
    {
        blocks.clear();
        nproper = 0;
#if IDASQL_HAS_EA_API
        func_entry_info_t fi;
        if (!get_func_entry_info(&fi, ea))
            return false;
        create("", fi.start_ea, fi.start_ea, fi.end_ea, flags);
#else
        func_t *pfn = get_func(ea);
        if (pfn == nullptr)
            return false;
        create("", pfn, pfn->start_ea, pfn->end_ea, flags);
#endif
        return true;
    }

    // Chart exactly [ea1, ea2), independent of function boundaries.
    void create_range(ea_t ea1, ea_t ea2, int flags)
    {
#if IDASQL_HAS_EA_API
        create("", BADADDR, ea1, ea2, flags);
#else
        create("", nullptr, ea1, ea2, flags);
#endif
    }
};

// ============================================================================

/**
 * Segments: ea-based segment and hidden-range wrappers.
 * Included from ida_compat.hpp; see the wrapper list there.
 *
 * SDK 9.4 deprecates every API that hands out a segment_t* or a
 * hidden_range_t*. On 9.4 these wrappers use only the ea-based / copy-based
 * replacements; on 9.0-9.3 they keep the pointer calls. Call sites pass any
 * address inside the segment and never hold a segment_t*.
 */

#include <bytes.hpp>
#include <segment.hpp>

/**
 * Snapshot of the segment_t fields call sites read.
 */
struct idasql_segment_info_t
{
    ea_t start_ea = BADADDR;
    ea_t end_ea = BADADDR;
    uchar perm = 0;     // SEGPERM_* (0 = no information)
    uchar bitness = 0;  // 0 = 16, 1 = 32, 2 = 64 bit
    uchar type = 0;     // SEG_*
};

/**
 * Fill `out` for the segment containing `ea`. Returns false (and leaves
 * `out` untouched) when `ea` is in no segment.
 */
bool idasql_segment_info(ea_t ea, idasql_segment_info_t *out);

/**
 * Start address of segment number `n` (0..get_segm_qty()-1), or BADADDR.
 */
ea_t idasql_segment_ea_by_num(int n);

/**
 * Start of the first segment after the one containing `ea`; for an address
 * in a gap, the first segment above it. BADADDR when there is none.
 * get_next_seg semantics, gaps and BADADDR included.
 */
ea_t idasql_next_segment_ea(ea_t ea);

/**
 * Start of the last segment before the one containing `ea`; for an address
 * in a gap, the last segment below it; for BADADDR, the last segment.
 * BADADDR when there is none. get_prev_seg semantics.
 */
ea_t idasql_prev_segment_ea(ea_t ea);

/**
 * Name of the segment containing `ea` (get_segm_name semantics: length, or
 * -1 with `out` cleared when there is no segment).
 */
ssize_t idasql_segment_name(qstring *out, ea_t ea);

/**
 * Class of the segment containing `ea` (get_segm_class semantics: length, or
 * -1 with `out` cleared when there is no segment).
 */
ssize_t idasql_segment_class(qstring *out, ea_t ea);

/**
 * Rename the segment containing `ea`. False when there is no segment or IDA
 * refuses the name.
 */
bool idasql_set_segment_name(ea_t ea, const char *name);

/**
 * Set the class of the segment containing `ea`.
 */
bool idasql_set_segment_class(ea_t ea, const char *sclass);

/**
 * Set the SEGPERM_* permissions of the segment containing `ea`.
 */
bool idasql_set_segment_perm(ea_t ea, uchar perm);

/**
 * Bitness code IDA uses (0=16, 1=32, 2=64) for the database's default addressing.
 */
uchar idasql_default_segment_bitness();

/**
 * Create [start, end) the way a loader does: a flat base (paragraph 0) for 32/64-bit
 * code, the real-mode paragraph for 16-bit; never truncates a neighbour. `perm` < 0
 * keeps IDA's default permissions.
 */
bool idasql_add_segment(ea_t start, ea_t end, const char *name, const char *sclass,
                               uchar bitness, int perm);

/**
 * Move (rebase) the segment containing `ea` so that it starts at `to`.
 * MOVE_SEGM_PARAM when `ea` is in no segment.
 */
move_segm_code_t idasql_move_segment(ea_t ea, ea_t to, int flags = 0);

/**
 * Snapshot of a hidden range. Absent texts are empty strings.
 */
struct idasql_hidden_range_t
{
    ea_t start_ea = BADADDR;
    ea_t end_ea = BADADDR;
    qstring description;
    qstring header;
    qstring footer;
    bool visible = false;
    bgcolor_t color = DEFCOLOR;
};

/**
 * Fill `out` for hidden range number `n` (0..get_hidden_range_qty()-1).
 * Returns false (and leaves `out` untouched) for a bad `n`.
 */
bool idasql_hidden_range_by_num(int n, idasql_hidden_range_t *out);

// ============================================================================

/**
 * Types: struct/union member add and delete across IDA SDKs.
 *
 * Included by ida_compat.hpp; selected by IDASQL_HAS_INPLACE_UDM_EDIT.
 *
 *   tinfo_code_t idasql_udt_add_udm(tinfo_t &tif, const udm_t &udm,
 *                                   uint etf_flags, int times, ssize_t idx)
 *   tinfo_code_t idasql_udt_del_udm(tinfo_t &tif, size_t idx)
 *
 * Both have tinfo_t::add_udm / del_udm semantics and leave `tif` bound to the
 * edited type, so callers keep using it (get_size, set_struct_size, ...).
 *
 * Why: on IDA 9.0 and 9.1, add_udm or del_udm on a til-bound FIXED struct that
 * another struct embeds by value aborts the process with INTERR 821 (the kernel
 * shows "internal error 821" and exits). Measured with headless idalib against
 * 9.0, 9.1, 9.2 and 9.4: the same edit done on a detached copy built from the
 * type's details, then committed with one set_numbered_type(NTF_REPLACE), gives
 * the layout 9.2+ produces in place (same members, offsets, size, fixed flag,
 * and the embedding struct re-laid out), with no INTERR. 9.2+ edit in place.
 */

#include <typeinf.hpp>

#if !IDASQL_HAS_INPLACE_UDM_EDIT
template <class Edit>
inline tinfo_code_t idasql_udt_commit_detached(tinfo_t &tif, Edit edit)
{
    const uint32 ordinal = tif.get_ordinal();
    if (ordinal == 0)
        return edit(tif);  // not a til type: nothing embeds it, edit in place

    udt_type_data_t details;
    if (!tif.get_udt_details(&details))
        return TERR_BAD_TYPE;
    tinfo_t detached;
    if (!detached.create_udt(details))
        return TERR_BAD_TYPE;

    const tinfo_code_t code = edit(detached);
    if (code != TERR_OK)
        return code;
    const tinfo_code_t saved =
        detached.set_numbered_type(get_idati(), ordinal, NTF_REPLACE, nullptr);
    if (saved != TERR_OK)
        return saved;
    tinfo_t rebound;
    if (rebound.get_numbered_type(get_idati(), ordinal))
        tif = rebound;
    return TERR_OK;
}
#endif

tinfo_code_t idasql_udt_add_udm(
    tinfo_t &tif, const udm_t &udm, uint etf_flags, int times, ssize_t idx);

tinfo_code_t idasql_udt_del_udm(tinfo_t &tif, size_t idx);

// ============================================================================
// Decompiler wrappers: declared only where <hexrays.hpp> was included first
// (the library; the CLI and plugin TUs do not need them).
#ifdef __HEXRAYS_HPP

/**
 * Decompiler: ea-based wrappers.
 *
 * Declared only when <hexrays.hpp> was included first: the library TUs (via
 * ida_headers.hpp) have it, the CLI and plugin TUs need none of these.
 *
 * SDK 9.4 deprecates decompile(mba_ranges_t) / decompile_func(func_t *) and
 * gen_microcode(mba_ranges_t) in favour of the decomp_ranges_t forms. Measured
 * on 9.4: identical pseudocode, microcode text and hexrays_failure_t (code,
 * errea, description) for every function, tail addresses included; an address
 * in no function fails with MERR_BADRANGES on both paths; both paths share the
 * cfunc cache.
 */

/**
 * Decompile the function containing `ea` (a tail address selects the tail's
 * owner). nullptr on failure, with the reason in `*hf`.
 */
cfuncptr_t idasql_decompile(ea_t ea, hexrays_failure_t *hf = nullptr, int decomp_flags = 0);

/**
 * Microcode of the function containing `ea` at maturity `reqmat`. The caller
 * owns the result (delete it). nullptr on failure, with the reason in `*hf`.
 */
mba_t *idasql_gen_microcode(ea_t ea, hexrays_failure_t *hf, const mlist_t *retlist, int decomp_flags,
                                   mba_maturity_t reqmat);
#endif  // __HEXRAYS_HPP
