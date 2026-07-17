// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0

#pragma once

#include <idasql/vtable.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "ida_headers.hpp"

namespace idasql {
namespace dirtrees {

struct StandardTreeInfo {
  const char *name;
  dirtree_id_t id;
  int index;
  bool writable;
};

struct DirtreePathInfo {
  std::string full_path;
  std::string folder_path;
};

struct DirtreeEntryRow {
  std::string tree;
  std::string path;
  std::string parent_path;
  std::string name;
  int is_dir = 0;
  int is_file = 0;
  int64_t inode = 0;
  int64_t rank = -1;
  std::string attrs;
  int depth = 0;
  int orderable = 0;
};

struct DirtreeFolderRow {
  std::string tree;
  std::string path;
  std::string full_path;
  int64_t diridx = 0;
  int tree_index = -1;
};

const std::vector<StandardTreeInfo> &standard_trees();
const StandardTreeInfo *find_tree(std::string_view name);
const StandardTreeInfo *find_tree_by_index(int index);
dirtree_t *get_tree_checked(const StandardTreeInfo &info, std::string *error);

std::string normalize_relative_path(std::string_view path);
std::string normalize_absolute_path(std::string_view path);
std::string absolute_path(std::string_view relative_path);
std::string parent_path_of_absolute(std::string_view full_path);
std::string basename_of_path(std::string_view path);
std::string join_path(std::string_view folder, std::string_view name);
std::optional<std::string> folder_path_from_full(std::string_view full_path);
int path_depth(std::string_view full_path);
bool sqlite_like(std::string_view value, std::string_view pattern);

std::unordered_map<uint64_t, DirtreePathInfo>
collect_inode_paths(dirtree_id_t id);
std::optional<DirtreePathInfo> find_inode_path(dirtree_id_t id, uint64_t inode);

bool ensure_folder(dirtree_t &tree, std::string_view folder,
                   std::string *error);
bool move_inode_to_folder(dirtree_id_t id, uint64_t inode,
                          std::string_view display_name,
                          std::string_view folder,
                          const char *surface_name);
bool move_inode_to_folder(dirtree_id_t id, uint64_t inode,
                          std::string_view display_name,
                          xsql::FunctionArg folder_arg,
                          const char *surface_name);
bool mkdir_folder(const StandardTreeInfo &info, std::string_view folder,
                  std::string *error);
bool rename_folder(const StandardTreeInfo &info, std::string_view from,
                   std::string_view to, std::string *error);
bool remove_empty_folder(const StandardTreeInfo &info, std::string_view folder,
                         std::string *error);

GeneratorTableDef<DirtreeEntryRow> define_dirtree_entries();
GeneratorTableDef<DirtreeFolderRow> define_dirtree_folders();

} // namespace dirtrees
} // namespace idasql
