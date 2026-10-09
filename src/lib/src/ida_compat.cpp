// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * ida_compat.cpp - link-time compatibility shims for older IDA runtimes.
 *
 * IDA SDK 9.2 added place_t::equals() and the matching idaplace_t__equals
 * runtime export. A plugin built against 9.2/9.3 headers ends up importing
 * idaplace_t__equals even when it only uses idaplace_t indirectly. IDA 9.0
 * does not export the symbol, so the plugin DLL fails to load before
 * initialization. Provide the default implementation locally for the
 * pre-9.2 case (forward to the still-exported idaplace_t__compare2).
 *
 * See allthingsida/idasql#30.
 */

#include "ida_headers.hpp"

#if IDA_SDK_VERSION < 920

// place_t / idaplace_t come from <kernwin.hpp> via ida_headers.hpp.

#if defined(_WIN32)
#define IDASQL_IDAAPI __stdcall
#else
#define IDASQL_IDAAPI
#endif

extern "C" int IDASQL_IDAAPI idaplace_t__compare2(
        const idaplace_t *ths,
        const place_t *t2,
        void *ud);

extern "C" bool IDASQL_IDAAPI idaplace_t__equals(
        const idaplace_t *ths,
        const place_t *t2,
        void *ud)
{
    return idaplace_t__compare2(ths, t2, ud) == 0;
}

#undef IDASQL_IDAAPI

#endif  // IDA_SDK_VERSION < 920

// ============================================================================
// Out-of-line bodies of the wrappers declared in ida_compat.hpp.

void idasql_auto_wait()
{
    if (!is_auto_enabled())
        return;
    auto_wait();
}

bool idasql_is_ida_library()
{
#if IDASQL_HAS_IS_IDA_LIBRARY_NOARG
    return is_ida_library();
#else
    return is_ida_library(nullptr, 0, nullptr);
#endif
}

uint32 idasql_bookmarks_get_by_inode(
    lochist_entry_t *out_entry, qstring *out_desc, inode_t inode, void *ud)
{
#if IDASQL_HAS_BOOKMARKS_GET_BY_INODE
    return bookmarks_t::get_by_inode(out_entry, out_desc, inode, ud);
#else
    if (out_entry == nullptr || out_entry->place() == nullptr)
        return BOOKMARKS_BAD_INDEX;

    const bool ea_capable = is_place_class_ea_capable(out_entry->place()->id());
    const uint32 count = bookmarks_t::size(*out_entry, ud);
    for (uint32 slot = 0; slot < count; ++slot)
    {
        uint32 index = slot;
        if (!bookmarks_t::get(out_entry, out_desc, &index, ud)
            || out_entry->place() == nullptr)
            continue;

        const uint64 leaf = ea_capable
            ? uint64(static_cast<idaplace_t *>(out_entry->place())->ea)
            : uint64(static_cast<tiplace_t *>(out_entry->place())->ordinal);
        if (leaf == uint64(inode))
            return index;
    }
    return BOOKMARKS_BAD_INDEX;
#endif
}

ea_t idasql_func_start(ea_t ea)
{
#if IDASQL_HAS_EA_API
    return get_func_start(ea);
#else
    func_t *pfn = get_func(ea);
    return pfn != nullptr ? pfn->start_ea : BADADDR;
#endif
}

bool idasql_is_func_start(ea_t ea)
{
    return ea != BADADDR && idasql_func_start(ea) == ea;
}

ea_t idasql_func_ea_by_num(size_t n)
{
#if IDASQL_HAS_EA_API
    return get_func_ea_by_num(n);
#else
    func_t *pfn = getn_func(n);
    return pfn != nullptr ? pfn->start_ea : BADADDR;
#endif
}

bool idasql_func_info(ea_t ea, idasql_func_info_t *out)
{
#if IDASQL_HAS_EA_API
    func_entry_info_t fi;
    if (!get_func_entry_info(&fi, ea))
        return false;
    out->start_ea = fi.start_ea;
    out->end_ea = fi.end_ea;
    out->flags = fi.get_flags();
    out->frsize = fi.get_frsize();
    out->frregs = fi.get_frregs();
    out->argsize = fi.get_argsize();
#else
    func_t *pfn = get_func(ea);
    if (pfn == nullptr)
        return false;
    out->start_ea = pfn->start_ea;
    out->end_ea = pfn->end_ea;
    out->flags = pfn->flags;
    out->frsize = pfn->frsize;
    out->frregs = pfn->frregs;
    out->argsize = pfn->argsize;
#endif
    return true;
}

uint64 idasql_func_flags(ea_t ea)
{
#if IDASQL_HAS_EA_API
    const ea_t start = get_func_start(ea);
    return start != BADADDR ? get_func_flags(start) : 0;
#else
    func_t *pfn = get_func(ea);
    return pfn != nullptr ? uint64(pfn->flags) : 0;
#endif
}

bool idasql_set_func_flags(ea_t ea, uint64 flags)
{
#if IDASQL_HAS_EA_API
    const ea_t start = get_func_start(ea);
    return start != BADADDR && set_func_flags(start, flags);
#else
    func_t *pfn = get_func(ea);
    if (pfn == nullptr)
        return false;
    pfn->flags = flags;
    return update_func(pfn);
#endif
}

size_t idasql_func_tail_qty(ea_t ea)
{
#if IDASQL_HAS_EA_API
    const ea_t start = get_func_start(ea);
    return start != BADADDR ? get_func_tail_qty(start) : 0;
#else
    func_t *pfn = get_func(ea);
    return pfn != nullptr ? size_t(pfn->tailqty) : 0;
#endif
}

ssize_t idasql_get_func_cmt(qstring *out, ea_t ea, bool repeatable)
{
#if IDASQL_HAS_EA_API
    const ea_t start = get_func_start(ea);
    if (start == BADADDR)
    {
        out->clear();
        return -1;
    }
    return get_func_cmt_ea(out, start, repeatable);
#else
    func_t *pfn = get_func(ea);
    if (pfn == nullptr)
    {
        out->clear();
        return -1;
    }
    return get_func_cmt(out, pfn, repeatable);
#endif
}

bool idasql_set_func_cmt(ea_t ea, const char *cmt, bool repeatable)
{
#if IDASQL_HAS_EA_API
    const ea_t start = get_func_start(ea);
    return start != BADADDR && set_func_cmt_ea(start, cmt, repeatable);
#else
    func_t *pfn = get_func(ea);
    return pfn != nullptr && set_func_cmt(pfn, cmt, repeatable);
#endif
}

asize_t idasql_func_frame_size(ea_t ea)
{
#if IDASQL_HAS_EA_API
    const ea_t start = get_func_start(ea);
    return start != BADADDR ? get_frame_size_ea(start) : 0;
#else
    func_t *pfn = get_func(ea);
    return pfn != nullptr ? get_frame_size(pfn) : 0;
#endif
}

bool idasql_fchunk_info(ea_t ea, idasql_fchunk_info_t *out)
{
#if IDASQL_HAS_EA_API
    fchunk_info_t ci;
    if (!get_fchunk_info(&ci, ea))
        return false;
    out->start_ea = ci.start_ea;
    out->end_ea = ci.end_ea;
    out->flags = ci.get_flags();
#else
    func_t *chunk = get_fchunk(ea);
    if (chunk == nullptr)
        return false;
    out->start_ea = chunk->start_ea;
    out->end_ea = chunk->end_ea;
    out->flags = chunk->flags;
#endif
    return true;
}

ea_t idasql_fchunk_ea_by_num(int n)
{
#if IDASQL_HAS_EA_API
    return get_fchunk_ea_by_num(n);
#else
    func_t *chunk = getn_fchunk(n);
    return chunk != nullptr ? chunk->start_ea : BADADDR;
#endif
}

size_t idasql_func_chunk_count(ea_t ea)
{
#if IDASQL_HAS_EA_API
    const ea_t start = get_func_start(ea);
    return start != BADADDR ? size_t(1) + get_func_tail_qty(start) : 0;
#else
    func_t *pfn = get_func(ea);
    return pfn != nullptr ? size_t(1) + size_t(pfn->tailqty) : 0;
#endif
}

asize_t idasql_func_total_size(ea_t ea)
{
#if IDASQL_HAS_EA_API
    return calc_func_size_ea(ea);
#else
    func_t *pfn = get_func(ea);
    return pfn != nullptr ? calc_func_size(pfn) : 0;
#endif
}

bool idasql_segment_info(ea_t ea, idasql_segment_info_t *out)
{
#if IDASQL_HAS_EA_API
    segment_info_t si;
    if (!get_segment_info(&si, ea))
        return false;
    out->start_ea = si.start_ea;
    out->end_ea = si.end_ea;
    out->perm = si.get_perm();
    out->bitness = si.get_bitness();
    out->type = si.get_type();
#else
    segment_t *s = getseg(ea);
    if (s == nullptr)
        return false;
    out->start_ea = s->start_ea;
    out->end_ea = s->end_ea;
    out->perm = s->perm;
    out->bitness = s->bitness;
    out->type = s->type;
#endif
    return true;
}

ea_t idasql_segment_ea_by_num(int n)
{
#if IDASQL_HAS_EA_API
    return get_segment_ea_by_num(n);
#else
    segment_t *s = getnseg(n);
    return s != nullptr ? s->start_ea : BADADDR;
#endif
}

ea_t idasql_next_segment_ea(ea_t ea)
{
#if IDASQL_HAS_EA_API
    return get_next_segment_ea(ea);
#else
    segment_t *s = get_next_seg(ea);
    return s != nullptr ? s->start_ea : BADADDR;
#endif
}

ea_t idasql_prev_segment_ea(ea_t ea)
{
#if IDASQL_HAS_EA_API
    return get_prev_segment_ea(ea);
#else
    segment_t *s = get_prev_seg(ea);
    return s != nullptr ? s->start_ea : BADADDR;
#endif
}

ssize_t idasql_segment_name(qstring *out, ea_t ea)
{
    out->clear();
#if IDASQL_HAS_EA_API
    return get_segment_name(out, ea);
#else
    segment_t *s = getseg(ea);
    return s != nullptr ? get_segm_name(out, s) : -1;
#endif
}

ssize_t idasql_segment_class(qstring *out, ea_t ea)
{
    out->clear();
#if IDASQL_HAS_EA_API
    return get_segment_class(out, ea);
#else
    segment_t *s = getseg(ea);
    return s != nullptr ? get_segm_class(out, s) : -1;
#endif
}

bool idasql_set_segment_name(ea_t ea, const char *name)
{
#if IDASQL_HAS_EA_API
    return set_segment_name(ea, name) != 0;
#else
    segment_t *s = getseg(ea);
    return s != nullptr && set_segm_name(s, name) != 0;
#endif
}

bool idasql_set_segment_class(ea_t ea, const char *sclass)
{
#if IDASQL_HAS_EA_API
    return set_segment_class(ea, sclass) != 0;
#else
    segment_t *s = getseg(ea);
    return s != nullptr && set_segm_class(s, sclass) != 0;
#endif
}

bool idasql_set_segment_perm(ea_t ea, uchar perm)
{
#if IDASQL_HAS_EA_API
    segment_info_t si;
    if (!get_segment_info(&si, ea))
        return false;
    si.set_perm(perm);
    return set_segment_info(&si);
#else
    segment_t *s = getseg(ea);
    if (s == nullptr)
        return false;
    s->perm = perm;
    return s->update();
#endif
}

uchar idasql_default_segment_bitness()
{
    return inf_is_64bit() ? 2 : (inf_is_32bit_or_higher() ? 1 : 0);
}

bool idasql_add_segment(ea_t start, ea_t end, const char *name, const char *sclass,
                               uchar bitness, int perm)
{
    const sel_t sel = bitness == 0 ? setup_selector(start >> 4) : find_selector(0);
    const int flags = ADDSEG_QUIET | ADDSEG_NOAA | ADDSEG_NOTRUNC;
#if IDASQL_HAS_EA_API
    segment_info_t si;
    si.start_ea = start;
    si.end_ea = end;
    si.set_sel(sel);
    si.set_bitness(bitness);
    si.set_align(saRelByte);
    si.set_comb(scPub);
    if (name != nullptr)
        si.set_name(name);
    if (sclass != nullptr)
        si.set_sclass(sclass);
    if (perm >= 0)
        si.set_perm(static_cast<uchar>(perm));
    return add_segment_ex(&si, flags);
#else
    segment_t s;
    s.start_ea = start;
    s.end_ea = end;
    s.sel = sel;
    s.bitness = bitness;
    s.align = saRelByte;
    s.comb = scPub;
    if (perm >= 0)
        s.perm = static_cast<uchar>(perm);
    return add_segm_ex(&s, name, sclass, flags);
#endif
}

move_segm_code_t idasql_move_segment(ea_t ea, ea_t to, int flags)
{
#if IDASQL_HAS_EA_API
    if (get_segment_ea(ea) == BADADDR)
        return MOVE_SEGM_PARAM;
    return move_segment(ea, to, flags);
#else
    segment_t *s = getseg(ea);
    if (s == nullptr)
        return MOVE_SEGM_PARAM;
    return move_segm(s, to, flags);
#endif
}

bool idasql_hidden_range_by_num(int n, idasql_hidden_range_t *out)
{
#if IDASQL_HAS_EA_API
    hidden_range_info_t hi;
    if (!get_hidden_range_info_by_num(&hi, n))
        return false;
    out->start_ea = hi.start_ea;
    out->end_ea = hi.end_ea;
    out->description = hi.get_description() != nullptr ? hi.get_description() : "";
    out->header = hi.get_header() != nullptr ? hi.get_header() : "";
    out->footer = hi.get_footer() != nullptr ? hi.get_footer() : "";
    out->visible = hi.get_visible();
    out->color = hi.get_color();
#else
    hidden_range_t *hr = getn_hidden_range(n);
    if (hr == nullptr)
        return false;
    out->start_ea = hr->start_ea;
    out->end_ea = hr->end_ea;
    out->description = hr->description != nullptr ? hr->description : "";
    out->header = hr->header != nullptr ? hr->header : "";
    out->footer = hr->footer != nullptr ? hr->footer : "";
    out->visible = hr->visible;
    out->color = hr->color;
#endif
    return true;
}

tinfo_code_t idasql_udt_add_udm(
    tinfo_t &tif, const udm_t &udm, uint etf_flags, int times, ssize_t idx)
{
#if IDASQL_HAS_INPLACE_UDM_EDIT
    return tif.add_udm(udm, etf_flags, times, idx);
#else
    return idasql_udt_commit_detached(tif, [&](tinfo_t &t) {
        return t.add_udm(udm, etf_flags, times, idx);
    });
#endif
}

tinfo_code_t idasql_udt_del_udm(tinfo_t &tif, size_t idx)
{
#if IDASQL_HAS_INPLACE_UDM_EDIT
    return tif.del_udm(idx);
#else
    return idasql_udt_commit_detached(tif, [&](tinfo_t &t) {
        return t.del_udm(idx);
    });
#endif
}

cfuncptr_t idasql_decompile(ea_t ea, hexrays_failure_t *hf, int decomp_flags)
{
#if IDASQL_HAS_EA_API
    return decompile_function(ea, hf, decomp_flags);
#else
    return decompile(mba_ranges_t(get_func(ea)), hf, decomp_flags);
#endif
}

mba_t *idasql_gen_microcode(ea_t ea, hexrays_failure_t *hf, const mlist_t *retlist, int decomp_flags,
                                   mba_maturity_t reqmat)
{
#if IDASQL_HAS_EA_API
    return gen_microcode(decomp_ranges_t(ea), hf, retlist, decomp_flags, reqmat);
#else
    return gen_microcode(mba_ranges_t(get_func(ea)), hf, retlist, decomp_flags, reqmat);
#endif
}
