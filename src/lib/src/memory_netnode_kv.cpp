// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "memory_netnode_kv.hpp"

using namespace idasql::core;

namespace idasql {
namespace memory {

// ============================================================================
// USERDATA Table - netnode-backed key-value store
// ============================================================================

static constexpr const char *NETNODE_KV_MASTER_NAME = "$ idasql netnode_kv";

static netnode get_netnode_kv_master(bool create) {
  netnode master(NETNODE_KV_MASTER_NAME, 0, create);
  return master;
}

// Iterator for single-key lookup via filter_eq_text("key").
// Uses entry_id as rowid for O(1) DELETE/UPDATE via row_lookup.
class NetnodeKvKeyIterator : public xsql::RowIterator {
  std::string key_;
  std::string value_;
  nodeidx_t entry_id_ = 0;
  bool started_ = false;
  bool valid_ = false;

public:
  explicit NetnodeKvKeyIterator(const char *key) : key_(key ? key : "") {}

  bool next() override {
    if (started_) {
      valid_ = false;
      return false;
    }
    started_ = true;

    if (key_.empty()) {
      valid_ = false;
      return false;
    }
    netnode master = get_netnode_kv_master(false);
    if (master == BADNODE) {
      valid_ = false;
      return false;
    }

    entry_id_ = master.hashval_long(key_.c_str());
    if (entry_id_ == 0) {
      valid_ = false;
      return false;
    }

    netnode entry(entry_id_);
    qstring blob;
    if (entry.getblob(&blob, 0, stag) < 0) {
      value_.clear();
    } else {
      value_ = blob.c_str();
    }

    valid_ = true;
    return true;
  }

  bool eof() const override { return started_ && !valid_; }

  void column(xsql::FunctionContext &ctx, int col) override {
    if (!valid_) {
      ctx.result_null();
      return;
    }
    switch (col) {
    case 0:
      ctx.result_text(key_.c_str());
      break;
    case 1:
      ctx.result_text(value_.c_str());
      break;
    default:
      ctx.result_null();
      break;
    }
  }

  int64_t rowid() const override { return static_cast<int64_t>(entry_id_); }
};

CachedTableDef<NetnodeKvRow> define_netnode_kv() {
  return cached_table<NetnodeKvRow>("netnode_kv")
      .no_shared_cache()
      .estimate_rows([]() -> size_t { return 64; })
      .cache_builder([](std::vector<NetnodeKvRow> &rows) {
        rows.clear();
        netnode master = get_netnode_kv_master(false);
        if (master == BADNODE)
          return;

        qstring key_buf;
        for (ssize_t r = master.hashfirst(&key_buf); r >= 0;
             r = master.hashnext(&key_buf, key_buf.c_str())) {
          nodeidx_t entry_id = master.hashval_long(key_buf.c_str());
          if (entry_id == 0)
            continue;

          NetnodeKvRow row;
          row.key = key_buf.c_str();
          row.entry_id = entry_id;

          netnode entry(entry_id);
          qstring blob;
          if (entry.getblob(&blob, 0, stag) >= 0) {
            row.value = blob.c_str();
          }
          rows.push_back(std::move(row));
        }
      })
      .row_populator([](NetnodeKvRow &row, int argc, xsql::FunctionArg *argv) {
        // argv[2]=key, argv[3]=value
        if (argc > 2 && !argv[2].is_null()) {
          const char *k = argv[2].as_c_str();
          row.key = k ? k : "";
        }
        if (argc > 3 && !argv[3].is_null()) {
          const char *v = argv[3].as_c_str();
          row.value = v ? v : "";
        }
      })
      .column_text(
          "key", [](const NetnodeKvRow &row) -> std::string { return row.key; })
      .column_text_rw(
          "value",
          [](const NetnodeKvRow &row) -> std::string { return row.value; },
          [](NetnodeKvRow &row, const char *new_value) -> bool {
            netnode master = get_netnode_kv_master(false);
            if (master == BADNODE) {
              xsql::set_vtab_error("netnode_kv: storage master node not found");
              return false;
            }

            nodeidx_t entry_id = master.hashval_long(row.key.c_str());
            if (entry_id == 0) {
              xsql::set_vtab_error("netnode_kv: key '" + row.key + "' not found");
              return false;
            }

            netnode entry(entry_id);
            const char *val = new_value ? new_value : "";
            size_t len = strlen(val);
            bool ok = entry.setblob(val, len, 0, stag);
            if (ok)
              row.value = val;
            else
              xsql::set_vtab_error("netnode_kv: failed to update key '" + row.key + "'");
            return ok;
          })
      // Stable rowid = the entry netnode index. This is the SAME id the keyed
      // filter iterator (NetnodeKvKeyIterator::rowid) and row_lookup use, so the
      // full-scan rowid round-trips through the entry_id-keyed row_lookup below.
      // A full-scan multi-row DELETE (e.g. WHERE key LIKE 'tag:%') therefore
      // resolves each row by its own entry_id instead of a cache position that
      // shifts as earlier rows are removed.
      .rowid([](const NetnodeKvRow &row) -> int64_t {
        return static_cast<int64_t>(row.entry_id);
      })
      .row_lookup([](NetnodeKvRow &row, int64_t raw_rowid) -> bool {
        netnode master = get_netnode_kv_master(false);
        if (master == BADNODE)
          return false;
        nodeidx_t entry_id = static_cast<nodeidx_t>(raw_rowid);
        qstring key_buf;
        if (master.supstr(&key_buf, entry_id) <= 0)
          return false;
        row.key = key_buf.c_str();
        row.entry_id = entry_id;
        netnode entry(entry_id);
        qstring blob;
        if (entry.getblob(&blob, 0, stag) >= 0)
          row.value = blob.c_str();
        return true;
      })
      .deletable([](NetnodeKvRow &row) -> bool {
        netnode master = get_netnode_kv_master(false);
        if (master == BADNODE)
          return false;

        nodeidx_t entry_id = master.hashval_long(row.key.c_str());
        if (entry_id == 0)
          return false;

        netnode entry(entry_id);
        entry.kill();
        master.hashdel(row.key.c_str());
        master.supdel(entry_id); // clean reverse index
        return true;
      })
      .insertable([](int argc, xsql::FunctionArg *argv) -> bool {
        // argv[0]=key, argv[1]=value
        if (argc < 1 || argv[0].is_null())
          return false;

        const char *key = argv[0].as_c_str();
        if (!key || !key[0])
          return false;

        // The key is stored both as a hash index and (verbatim) as a supval
        // value in the reverse index; supval objects are capped at MAXSPECSIZE.
        // An oversized key would make the store silently fail, so reject it.
        if (strlen(key) >= static_cast<size_t>(MAXSPECSIZE)) {
          xsql::set_vtab_error(
              "netnode_kv: key too long (max " + std::to_string(MAXSPECSIZE - 1) +
              " bytes)");
          return false;
        }

        const char *val = "";
        if (argc > 1 && !argv[1].is_null()) {
          val = argv[1].as_c_str();
          if (!val)
            val = "";
        }
        size_t len = strlen(val);

        netnode master = get_netnode_kv_master(true);
        if (master == BADNODE)
          return false;

        // Upsert: if key already exists, update its value
        nodeidx_t existing = master.hashval_long(key);
        if (existing != 0) {
          netnode entry(existing);
          if (!entry.setblob(val, len, 0, stag)) {
            xsql::set_vtab_error(
                "netnode_kv: failed to store value for key '" +
                std::string(key) + "'");
            return false;
          }
          return true;
        }

        // Create new entry netnode
        netnode entry;
        if (!entry.create())
          return false;

        nodeidx_t entry_id = static_cast<nodeidx_t>(entry);
        // Roll back the freshly-created entry netnode on any storage-write
        // failure so we never leak a dangling entry or a half-wired index.
        if (!entry.setblob(val, len, 0, stag) || !master.hashset(key, entry_id) ||
            !master.supset(entry_id, key)) {
          entry.kill();
          master.hashdel(key);
          master.supdel(entry_id);
          xsql::set_vtab_error(
              "netnode_kv: failed to store entry for key '" + std::string(key) +
              "'");
          return false;
        }
        return true;
      })
      .filter_eq_text(
          "key",
          [](const char *key) -> std::unique_ptr<xsql::RowIterator> {
            return std::make_unique<NetnodeKvKeyIterator>(key);
          },
          1.0, 1.0)
      .build();
}

} // namespace memory
} // namespace idasql
