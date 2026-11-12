// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <moves.hpp>

#define IDASQL_HAS_PARENT_ITEM             (IDA_SDK_VERSION >= 920)
#define IDASQL_HAS_INPLACE_UDM_EDIT        (IDA_SDK_VERSION >= 920)
#define IDASQL_HAS_OPEN_DATABASE_3ARG      (IDA_SDK_VERSION >= 910)
#define IDASQL_HAS_IS_IDA_LIBRARY_NOARG    (IDA_SDK_VERSION >= 920)
#define IDASQL_HAS_BOOKMARKS_GET_BY_INODE  (IDA_SDK_VERSION >= 930)
#define IDASQL_HAS_DEEP_LINKS              (IDA_SDK_VERSION >= 940)
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
using callcnv_t = cm_t;

#ifndef HTI_SEMICOLON
#define HTI_SEMICOLON 0
#endif

#ifndef GENDSM_UNHIDE
#define GENDSM_UNHIDE 0
#endif
#endif

void idasql_auto_wait();

bool idasql_is_ida_library();

uint32 idasql_bookmarks_get_by_inode(
    lochist_entry_t *out_entry, qstring *out_desc, inode_t inode, void *ud);

#include <frame.hpp>
#include <funcs.hpp>
#include <gdl.hpp>

ea_t idasql_func_start(ea_t ea);

bool idasql_is_func_start(ea_t ea);

ea_t idasql_func_ea_by_num(size_t n);

struct idasql_func_info_t
{
    ea_t start_ea = BADADDR;
    ea_t end_ea = BADADDR;
    uint64 flags = 0;
    asize_t frsize = 0;
    ushort frregs = 0;
    asize_t argsize = 0;
};

bool idasql_func_info(ea_t ea, idasql_func_info_t *out);

uint64 idasql_func_flags(ea_t ea);

bool idasql_set_func_flags(ea_t ea, uint64 flags);

size_t idasql_func_tail_qty(ea_t ea);

ssize_t idasql_get_func_cmt(qstring *out, ea_t ea, bool repeatable);

bool idasql_set_func_cmt(ea_t ea, const char *cmt, bool repeatable);

asize_t idasql_func_frame_size(ea_t ea);

struct idasql_fchunk_info_t
{
    ea_t start_ea = BADADDR;
    ea_t end_ea = BADADDR;
    uint64 flags = 0;
    bool is_tail() const { return (flags & FUNC_TAIL) != 0; }
};

bool idasql_fchunk_info(ea_t ea, idasql_fchunk_info_t *out);

ea_t idasql_fchunk_ea_by_num(int n);

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

size_t idasql_func_chunk_count(ea_t ea);

asize_t idasql_func_total_size(ea_t ea);

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

class idasql_func_item_iterator
{
#if IDASQL_HAS_EA_API
    function_item_iterator_t it_;
#else
    func_item_iterator_t it_;
#endif

public:
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

    void create_range(ea_t ea1, ea_t ea2, int flags)
    {
#if IDASQL_HAS_EA_API
        create("", BADADDR, ea1, ea2, flags);
#else
        create("", nullptr, ea1, ea2, flags);
#endif
    }
};

#include <bytes.hpp>
#include <segment.hpp>

struct idasql_segment_info_t
{
    ea_t start_ea = BADADDR;
    ea_t end_ea = BADADDR;
    uchar perm = 0;
    uchar bitness = 0;
    uchar type = 0;
};

bool idasql_segment_info(ea_t ea, idasql_segment_info_t *out);

ea_t idasql_segment_ea_by_num(int n);

ea_t idasql_next_segment_ea(ea_t ea);

ea_t idasql_prev_segment_ea(ea_t ea);

ssize_t idasql_segment_name(qstring *out, ea_t ea);

ssize_t idasql_segment_class(qstring *out, ea_t ea);

bool idasql_set_segment_name(ea_t ea, const char *name);

bool idasql_set_segment_class(ea_t ea, const char *sclass);

bool idasql_set_segment_perm(ea_t ea, uchar perm);

uchar idasql_default_segment_bitness();

bool idasql_add_segment(ea_t start, ea_t end, const char *name, const char *sclass,
                               uchar bitness, int perm);

move_segm_code_t idasql_move_segment(ea_t ea, ea_t to, int flags = 0);

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

bool idasql_hidden_range_by_num(int n, idasql_hidden_range_t *out);

#include <typeinf.hpp>

#if !IDASQL_HAS_INPLACE_UDM_EDIT
template <class Edit>
inline tinfo_code_t idasql_udt_commit_detached(tinfo_t &tif, Edit edit)
{
    const uint32 ordinal = tif.get_ordinal();
    if (ordinal == 0)
        return edit(tif);

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

#ifdef __HEXRAYS_HPP

cfuncptr_t idasql_decompile(ea_t ea, hexrays_failure_t *hf = nullptr, int decomp_flags = 0);

mba_t *idasql_gen_microcode(ea_t ea, hexrays_failure_t *hf, const mlist_t *retlist, int decomp_flags,
                                   mba_maturity_t reqmat);
#endif
