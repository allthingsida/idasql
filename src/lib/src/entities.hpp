// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * entities.hpp - IDA entity tables (funcs, segments, names, entries, comments,
 * imports, strings, xrefs, blocks, etc.)
 */

#pragma once

#include <idasql/platform.hpp>

#include <idasql/string_utils.hpp>
#include <idasql/vtable.hpp>
#include <xsql/database.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "ida_headers.hpp"

namespace idasql {
namespace entities {

// ============================================================================
// Struct declarations
// ============================================================================

struct FuncRow {
  ea_t start_ea = BADADDR;
  std::string original_name;
  std::string original_prototype;
  std::string original_comment;
  std::string original_rpt_comment;

  // Lazy-computed type details
  mutable func_type_data_t fi;
  mutable bool fi_valid = false;
  mutable bool fi_computed = false;

  // Defined after get_func_type_details declaration below
  inline bool ensure_fi() const;
};

struct CommentRow {
  ea_t ea = BADADDR;
  std::string comment;
  std::string rpt_comment;
};

struct ImportInfo {
  int module_idx;
  ea_t ea;
  std::string name;
  uval_t ord;
};

struct XrefInfo {
  ea_t from_ea;
  ea_t to_ea;
  ea_t from_func = BADADDR; // Pre-computed: function containing from_ea
  uint8_t type;
  bool is_code;
};

struct DataRefInfo {
  ea_t from_ea = BADADDR;
  ea_t to_ea = BADADDR;
  ea_t from_func = BADADDR;
  uint8_t type = 0;
};

struct BlockInfo {
  ea_t func_ea;
  ea_t start_ea;
  ea_t end_ea;
};

struct FunctionChunkInfo {
  ea_t func_ea = BADADDR;
  ea_t chunk_start = BADADDR;
  ea_t chunk_end = BADADDR;
  int block_count = 0;
  asize_t total_size = 0;
};

struct BookmarkRow {
  uint32_t index = 0;
  ea_t ea = BADADDR;
  std::string desc;
};

struct NetnodeKvRow {
  std::string key;
  std::string value;
};

struct HeadRow {
  ea_t ea = BADADDR;
};

struct PatchedByteInfo {
  ea_t ea;
  qoff64_t fpos;
  uint64 original_value;
  uint64 patched_value;
};

struct InstructionRow {
  ea_t ea = BADADDR;
};

struct ImportEnumContext {
  std::vector<ImportInfo> *cache;
  int module_idx;
};

enum class OperandApplyKind {
  None,
  Clear,
  Enum,
  Stroff,
};

struct OperandApplyRequest {
  OperandApplyKind kind = OperandApplyKind::None;
  std::string enum_name;
  std::string enum_member_name;
  uchar enum_serial = 0;
  std::vector<std::string> stroff_path_names;
  adiff_t stroff_delta = 0;
};

// ============================================================================
// Helper function declarations
// ============================================================================

std::string safe_func_name(ea_t ea);
std::string safe_segm_name(segment_t *seg);
std::string safe_segm_class(segment_t *seg);
std::string safe_name(ea_t ea);
std::string safe_entry_name(size_t idx);

bool get_func_tinfo(ea_t ea, tinfo_t &tif);
bool get_func_type_details(ea_t ea, func_type_data_t &fi);
const char *get_cc_name(callcnv_t cc);

inline bool FuncRow::ensure_fi() const {
  if (!fi_computed) {
    fi_computed = true;
    fi_valid = get_func_type_details(start_ea, fi);
  }
  return fi_valid;
}

void collect_comment_rows(std::vector<CommentRow> &rows);

std::string get_import_module_name_safe(int idx);

// String helpers
int get_string_width(int strtype);
const char *get_string_width_name(int strtype);
const char *get_string_type_name(int strtype);
int get_string_layout(int strtype);
const char *get_string_layout_name(int strtype);
int get_string_encoding(int strtype);
std::string get_string_content(const string_info_t &si);

void collect_bookmark_rows(std::vector<BookmarkRow> &rows);

void collect_head_rows(std::vector<HeadRow> &rows);
const char *get_item_type_str(ea_t ea);

void collect_instruction_rows(std::vector<InstructionRow> &rows);

// Operand helpers
std::string operand_kind_text(ea_t ea, int opnum);
std::string operand_type_text(ea_t ea, int opnum);
int operand_enum_serial(ea_t ea, int opnum);
int64_t operand_stroff_delta(ea_t ea, int opnum);
std::string operand_class_text(ea_t ea, int opnum);
std::string operand_repr_kind_text(ea_t ea, int opnum);
std::string operand_repr_type_name_text(ea_t ea, int opnum);
std::string operand_repr_member_name_text(ea_t ea, int opnum);
int operand_repr_serial(ea_t ea, int opnum);
int64_t operand_repr_delta(ea_t ea, int opnum);
std::string operand_format_spec_text(ea_t ea, int opnum);

void instruction_column_common(xsql::FunctionContext &ctx, ea_t ea,
                               ea_t func_addr, int col);

// Constants
inline constexpr int kInstructionOperandCount = 8;
inline constexpr int kInstructionOperandBaseCol = 4;
inline constexpr int kInstructionDisasmCol =
    kInstructionOperandBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionFuncAddrCol = kInstructionDisasmCol + 1;
inline constexpr int kInstructionClassBaseCol = kInstructionFuncAddrCol + 1;
inline constexpr int kInstructionReprKindBaseCol =
    kInstructionClassBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionReprTypeBaseCol =
    kInstructionReprKindBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionReprMemberBaseCol =
    kInstructionReprTypeBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionReprSerialBaseCol =
    kInstructionReprMemberBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionReprDeltaBaseCol =
    kInstructionReprSerialBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionFormatSpecBaseCol =
    kInstructionReprDeltaBaseCol + kInstructionOperandCount;
inline constexpr int kInstructionColumnCount =
    kInstructionFormatSpecBaseCol + kInstructionOperandCount;

// Parsing helpers (trim_copy is in <idasql/string_utils.hpp>)
using idasql::trim_copy;
bool starts_with_ci(const std::string &text, const char *prefix);
bool equals_ci(const std::string &text, const char *token);
bool parse_int64(const std::string &text, int64_t &out_value);
bool resolve_named_type_tid(const std::string &name, tid_t &out_tid,
                            tinfo_t *out_tif = nullptr);
std::string tid_name_or_fallback(tid_t tid);
void split_path_names(const std::string &path_spec,
                      std::vector<std::string> &out_names);
bool parse_operand_format_spec(const char *spec, OperandApplyRequest &out,
                               std::string *out_error = nullptr);
bool parse_operand_apply_spec(const char *spec, OperandApplyRequest &out);
bool decode_operand(ea_t ea, int opnum, insn_t &out_insn, op_t &out_op,
                    std::string *out_error = nullptr);
bool operand_numeric_value(ea_t ea, int opnum, uint64 &out_value,
                           std::string *out_error = nullptr);
bool resolve_enum_member_serial(const tinfo_t &enum_tif,
                                const std::string &member_name,
                                uchar &out_serial,
                                std::string *out_error = nullptr);
bool apply_operand_representation(ea_t ea, int opnum,
                                  const OperandApplyRequest &req,
                                  std::string *out_error = nullptr);
const char *operand_class_name(optype_t type);

int idaapi patched_bytes_visitor(ea_t ea, qoff64_t fpos, uint64 o, uint64 v,
                                 void *ud);

// ============================================================================
// Table definition declarations
// ============================================================================

CachedTableDef<FuncRow> define_funcs();
VTableDef define_segments();
VTableDef define_names();
VTableDef define_entries();
CachedTableDef<CommentRow> define_comments();
CachedTableDef<BookmarkRow> define_bookmarks();
CachedTableDef<HeadRow> define_heads();
CachedTableDef<HeadRow> define_bytes();
CachedTableDef<PatchedByteInfo> define_patched_bytes();
CachedTableDef<InstructionRow> define_instructions();
CachedTableDef<XrefInfo> define_xrefs();
CachedTableDef<DataRefInfo> define_data_refs();
CachedTableDef<BlockInfo> define_blocks();
CachedTableDef<FunctionChunkInfo> define_function_chunks();
CachedTableDef<ImportInfo> define_imports();
CachedTableDef<string_info_t> define_strings();
CachedTableDef<NetnodeKvRow> define_netnode_kv();

// ============================================================================
// Iterator class declarations
// ============================================================================

/**
 * Iterator for xrefs TO a specific address.
 * Used when query has: WHERE to_ea = X
 * Uses xrefblk_t::first_to/next_to for O(refs_to_X) instead of O(all_xrefs)
 */
class XrefsToIterator : public xsql::RowIterator {
  ea_t target_;
  xrefblk_t xb_;
  bool started_ = false;
  bool valid_ = false;

public:
  explicit XrefsToIterator(ea_t target);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

/**
 * Iterator for xrefs FROM a specific address.
 * Used when query has: WHERE from_ea = X
 * Uses xrefblk_t::first_from/next_from for O(refs_from_X) instead of
 * O(all_xrefs)
 */
class XrefsFromIterator : public xsql::RowIterator {
  ea_t source_;
  xrefblk_t xb_;
  bool started_ = false;
  bool valid_ = false;

public:
  explicit XrefsFromIterator(ea_t source);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

/**
 * Iterator for xrefs originating from within a specific function.
 * Used when query has: WHERE from_func = X
 * Iterates all code items in the function and enumerates their outgoing xrefs.
 */
class XrefsFromFuncIterator : public xsql::RowIterator {
  ea_t func_ea_;
  func_item_iterator_t fii_;
  xrefblk_t xb_;
  bool fii_valid_ = false;
  bool xb_valid_ = false;
  bool started_ = false;
  bool eof_ = false;

  bool advance_to_next_xref();

public:
  explicit XrefsFromFuncIterator(ea_t func_ea);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

/**
 * Iterator for blocks in a specific function.
 * Used when query has: WHERE func_ea = X
 * Uses qflow_chart_t on single function for O(func_blocks) instead of
 * O(all_blocks)
 */
class BlocksInFuncIterator : public xsql::RowIterator {
  ea_t func_ea_;
  qflow_chart_t fc_;
  int idx_ = -1;
  bool valid_ = false;

public:
  explicit BlocksInFuncIterator(ea_t func_ea);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

// Iterator for single-address point query (constraint pushdown on ea)
class BytesAtIterator : public xsql::RowIterator {
  ea_t ea_;
  bool yielded_ = false;
  bool exhausted_ = false;

public:
  explicit BytesAtIterator(ea_t ea);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

// Iterator for instructions within a single function (constraint pushdown)
class InstructionsInFuncIterator : public xsql::RowIterator {
  ea_t func_addr_;
  func_t *pfn_ = nullptr;
  func_item_iterator_t fii_;
  bool started_ = false;
  bool valid_ = false;
  ea_t current_ea_ = BADADDR;

public:
  explicit InstructionsInFuncIterator(ea_t func_addr);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

// Iterator for a single instruction by exact address.
class InstructionAtAddressIterator : public xsql::RowIterator {
  ea_t ea_;
  bool started_ = false;
  bool valid_ = false;

public:
  explicit InstructionAtAddressIterator(ea_t ea);
  bool next() override;
  bool eof() const override;
  void column(xsql::FunctionContext &ctx, int col) override;
  int64_t rowid() const override;
};

// ============================================================================
// TableRegistry
// ============================================================================

struct TableRegistry {
  // Cached tables with write support
  CachedTableDef<FuncRow> funcs;
  VTableDef segments;
  VTableDef names;
  VTableDef entries;
  CachedTableDef<CommentRow> comments;
  CachedTableDef<BookmarkRow> bookmarks;
  CachedTableDef<HeadRow> heads;
  CachedTableDef<HeadRow> bytes;
  CachedTableDef<PatchedByteInfo> patched_bytes;
  CachedTableDef<InstructionRow> instructions;

  // Cached tables (query-scoped cache - memory freed after query)
  CachedTableDef<XrefInfo> xrefs;
  CachedTableDef<DataRefInfo> data_refs;
  CachedTableDef<BlockInfo> blocks;
  CachedTableDef<FunctionChunkInfo> function_chunks;
  CachedTableDef<ImportInfo> imports;
  CachedTableDef<string_info_t> strings;
  CachedTableDef<NetnodeKvRow> netnode_kv;

  // Global pointer for cache invalidation from SQL functions
  static inline TableRegistry *g_instance = nullptr;

  TableRegistry();
  ~TableRegistry();

  // Invalidate the strings cache (call after rebuild_strings)
  void invalidate_strings_cache();

  // Static method for SQL functions to invalidate strings cache
  static void invalidate_strings_cache_global();

  void register_all(xsql::Database &db);

  void create_helper_views(xsql::Database &db);

private:
  void register_index_table(xsql::Database &db, const char *name,
                            const VTableDef *def);

  template <typename RowData>
  void register_cached_table(xsql::Database &db, const char *name,
                             const CachedTableDef<RowData> *def) {
    std::string module_name = std::string("ida_") + name;
    db.register_cached_table(module_name.c_str(), def);
    db.create_table(name, module_name.c_str());
  }
};

} // namespace entities
} // namespace idasql
