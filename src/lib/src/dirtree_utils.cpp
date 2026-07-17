// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0

#include "dirtree_utils.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <memory>

namespace idasql {
namespace dirtrees {

namespace {

class VectorEntryGenerator : public xsql::Generator<DirtreeEntryRow> {
  std::vector<DirtreeEntryRow> rows_;
  size_t pos_ = 0;

public:
  explicit VectorEntryGenerator(std::vector<DirtreeEntryRow> rows)
      : rows_(std::move(rows)) {}

  bool next() override {
    if (pos_ < rows_.size()) {
      ++pos_;
      return true;
    }
    return false;
  }

  const DirtreeEntryRow &current() const override { return rows_[pos_ - 1]; }

  int64_t rowid() const override { return static_cast<int64_t>(pos_); }
};

class VectorFolderGenerator : public xsql::Generator<DirtreeFolderRow> {
  std::vector<DirtreeFolderRow> rows_;
  size_t pos_ = 0;

public:
  explicit VectorFolderGenerator(std::vector<DirtreeFolderRow> rows)
      : rows_(std::move(rows)) {}

  bool next() override {
    if (pos_ < rows_.size()) {
      ++pos_;
      return true;
    }
    return false;
  }

  const DirtreeFolderRow &current() const override { return rows_[pos_ - 1]; }

  int64_t rowid() const override {
    if (pos_ == 0)
      return 0;
    const auto &row = rows_[pos_ - 1];
    return (static_cast<int64_t>(row.tree_index + 1) << 32) |
           (row.diridx & 0xffffffffLL);
  }
};

std::string trim_copy(std::string_view value) {
  size_t begin = 0;
  while (begin < value.size() &&
         std::isspace(static_cast<unsigned char>(value[begin]))) {
    ++begin;
  }

  size_t end = value.size();
  while (end > begin &&
         std::isspace(static_cast<unsigned char>(value[end - 1]))) {
    --end;
  }

  return std::string(value.substr(begin, end - begin));
}

std::string dirtree_error(dterr_t err) {
  const char *text = dirtree_t::errstr(err);
  return text ? text : std::to_string(static_cast<int>(err));
}

bool ok_or_exists(dterr_t err) {
  return err == DTE_OK || err == DTE_ALREADY_EXISTS;
}

struct CollectVisitor : public dirtree_visitor_t {
  const StandardTreeInfo &info;
  const dirtree_t &tree;
  std::vector<DirtreeEntryRow> rows;
  std::unordered_map<uint64_t, DirtreePathInfo> inode_paths;
  bool folders_only = false;

  CollectVisitor(const StandardTreeInfo &tree_info, const dirtree_t &dt)
      : info(tree_info), tree(dt) {}

  ssize_t visit(const dirtree_cursor_t &cursor, const direntry_t &entry) override {
    if (folders_only && !entry.isdir)
      return 0;

    qstring qpath = tree.get_abspath(cursor, DTN_FULL_NAME);
    std::string full_path = qpath.empty() ? "/" : std::string(qpath.c_str());
    if (full_path.empty())
      full_path = "/";

    qstring qname = tree.get_entry_name(entry, DTN_DISPLAY_NAME);
    qstring qattrs = tree.get_entry_attrs(entry);

    DirtreeEntryRow row;
    row.tree = info.name;
    row.path = full_path;
    row.parent_path = parent_path_of_absolute(full_path);
    row.name = qname.c_str();
    row.is_dir = entry.isdir ? 1 : 0;
    row.is_file = entry.isdir ? 0 : 1;
    row.inode = static_cast<int64_t>(entry.idx);
    row.rank = cursor.valid() && !cursor.is_root_cursor()
                   ? static_cast<int64_t>(tree.get_rank(cursor.parent, entry))
                   : -1;
    row.attrs = qattrs.c_str();
    row.depth = path_depth(full_path);
    row.orderable = tree.is_orderable() ? 1 : 0;

    if (!entry.isdir) {
      DirtreePathInfo path_info;
      path_info.full_path = full_path;
      auto folder = folder_path_from_full(full_path);
      path_info.folder_path = folder.value_or(std::string());
      inode_paths[static_cast<uint64_t>(entry.idx)] = std::move(path_info);
    }

    rows.push_back(std::move(row));
    return 0;
  }
};

bool row_matches(const DirtreeEntryRow &row,
                 const std::string &path_eq,
                 const std::string &path_like,
                 const std::string &parent_eq,
                 bool has_inode,
                 int64_t inode,
                 bool has_is_dir,
                 int is_dir,
                 bool has_is_file,
                 int is_file) {
  if (!path_eq.empty() && row.path != path_eq)
    return false;
  if (!path_like.empty() && !sqlite_like(row.path, path_like))
    return false;
  if (!parent_eq.empty() && row.parent_path != parent_eq)
    return false;
  if (has_inode && row.inode != inode)
    return false;
  if (has_is_dir && row.is_dir != is_dir)
    return false;
  if (has_is_file && row.is_file != is_file)
    return false;
  return true;
}

std::vector<DirtreeEntryRow> collect_entries_for_tree(const StandardTreeInfo &info,
                                                      std::string *error) {
  dirtree_t *tree = get_tree_checked(info, error);
  if (!tree)
    return {};

  CollectVisitor visitor(info, *tree);
  if (tree->traverse(visitor) != 0) {
    if (error)
      *error = std::string("dirtree_entries: failed to traverse tree '") +
               info.name + "'";
    return {};
  }
  return std::move(visitor.rows);
}

std::vector<DirtreeFolderRow> collect_folders_for_tree(const StandardTreeInfo &info,
                                                       std::string *error) {
  dirtree_t *tree = get_tree_checked(info, error);
  if (!tree)
    return {};

  CollectVisitor visitor(info, *tree);
  visitor.folders_only = true;
  if (tree->traverse(visitor) != 0) {
    if (error)
      *error = std::string("dirtree_folders: failed to traverse tree '") +
               info.name + "'";
    return {};
  }

  std::vector<DirtreeFolderRow> rows;
  rows.reserve(visitor.rows.size());
  for (const auto &entry : visitor.rows) {
    DirtreeFolderRow row;
    row.tree = entry.tree;
    row.full_path = entry.path;
    row.path = normalize_relative_path(entry.path);
    row.diridx = entry.inode;
    row.tree_index = info.index;
    rows.push_back(std::move(row));
  }
  return rows;
}

std::string folder_arg_to_string(xsql::FunctionArg folder_arg) {
  if (folder_arg.is_null())
    return {};
  const char *text = folder_arg.as_c_str();
  return text ? text : "";
}

bool validate_mutation_path(std::string_view raw_path, bool allow_root,
                            const char *surface, std::string *error) {
  std::string trimmed = trim_copy(raw_path);
  if (trimmed.empty() || trimmed == "/" || trimmed == "<root>" ||
      trimmed == "root") {
    if (allow_root)
      return true;
    if (error)
      *error = std::string(surface) + ": root folder is not valid here";
    return false;
  }

  if (trimmed == "." || trimmed == ".." ||
      trimmed.find('\\') != std::string::npos) {
    if (error)
      *error = std::string(surface) + ": invalid folder path: " + trimmed;
    return false;
  }

  std::string normalized = normalize_relative_path(trimmed);
  size_t begin = 0;
  while (begin <= normalized.size()) {
    size_t slash = normalized.find('/', begin);
    std::string component =
        normalized.substr(begin, slash == std::string::npos
                                     ? std::string::npos
                                     : slash - begin);
    if (component.empty() || component == "." || component == "..") {
      if (error)
        *error = std::string(surface) + ": invalid folder path: " + trimmed;
      return false;
    }
    if (slash == std::string::npos)
      break;
    begin = slash + 1;
  }

  return true;
}

bool validate_writable_tree(const StandardTreeInfo &info,
                            const char *surface,
                            std::string *error) {
  if (info.writable)
    return true;
  if (error) {
    *error = std::string(surface) + ": tree '" + info.name +
             "' is read-only";
  }
  return false;
}

} // namespace

const std::vector<StandardTreeInfo> &standard_trees() {
  static const std::vector<StandardTreeInfo> trees = {
      {"local_types", DIRTREE_LOCAL_TYPES, 0, true},
      {"funcs", DIRTREE_FUNCS, 1, true},
      {"names", DIRTREE_NAMES, 2, true},
      {"imports", DIRTREE_IMPORTS, 3, true},
      {"idaplace_bookmarks", DIRTREE_IDAPLACE_BOOKMARKS, 4, true},
      {"bpts", DIRTREE_BPTS, 5, true},
      {"ltypes_bookmarks", DIRTREE_LTYPES_BOOKMARKS, 6, true},
  };
  return trees;
}

const StandardTreeInfo *find_tree(std::string_view name) {
  std::string normalized = trim_copy(name);
  if (normalized == "bookmarks")
    normalized = "idaplace_bookmarks";
  for (const auto &tree : standard_trees()) {
    if (normalized == tree.name)
      return &tree;
  }
  return nullptr;
}

const StandardTreeInfo *find_tree_by_index(int index) {
  for (const auto &tree : standard_trees()) {
    if (tree.index == index)
      return &tree;
  }
  return nullptr;
}

dirtree_t *get_tree_checked(const StandardTreeInfo &info, std::string *error) {
  dirtree_t *tree = get_std_dirtree(info.id);
  if (!tree) {
    if (error)
      *error = std::string("failed to open IDA dirtree '") + info.name + "'";
    return nullptr;
  }
  if (!tree->load()) {
    if (error)
      *error = std::string("failed to load IDA dirtree '") + info.name + "'";
    return nullptr;
  }
  return tree;
}

std::string normalize_relative_path(std::string_view path) {
  std::string value = trim_copy(path);
  if (value == "/" || value == "." || value == "<root>" || value == "root")
    return {};

  size_t begin = 0;
  while (begin < value.size() && value[begin] == '/')
    ++begin;

  size_t end = value.size();
  while (end > begin && value[end - 1] == '/')
    --end;

  return value.substr(begin, end - begin);
}

std::string normalize_absolute_path(std::string_view path) {
  return absolute_path(normalize_relative_path(path));
}

std::string absolute_path(std::string_view relative_path) {
  std::string normalized = normalize_relative_path(relative_path);
  return normalized.empty() ? "/" : "/" + normalized;
}

std::string parent_path_of_absolute(std::string_view full_path) {
  std::string path = normalize_absolute_path(full_path);
  if (path == "/")
    return "/";

  size_t slash = path.find_last_of('/');
  if (slash == std::string::npos || slash == 0)
    return "/";
  return path.substr(0, slash);
}

std::string basename_of_path(std::string_view path) {
  std::string normalized = normalize_relative_path(path);
  size_t slash = normalized.find_last_of('/');
  return slash == std::string::npos ? normalized : normalized.substr(slash + 1);
}

std::string join_path(std::string_view folder, std::string_view name) {
  std::string normalized_folder = normalize_relative_path(folder);
  std::string normalized_name = normalize_relative_path(name);
  if (normalized_folder.empty())
    return normalized_name;
  if (normalized_name.empty())
    return normalized_folder;
  return normalized_folder + "/" + normalized_name;
}

std::optional<std::string> folder_path_from_full(std::string_view full_path) {
  std::string path = normalize_absolute_path(full_path);
  if (path == "/")
    return std::nullopt;
  size_t slash = path.find_last_of('/');
  if (slash == std::string::npos || slash == 0)
    return std::nullopt;
  return normalize_relative_path(path.substr(0, slash));
}

int path_depth(std::string_view full_path) {
  std::string path = normalize_absolute_path(full_path);
  if (path == "/")
    return 0;
  return static_cast<int>(std::count(path.begin(), path.end(), '/'));
}

bool sqlite_like(std::string_view value, std::string_view pattern) {
  std::string v(value);
  std::string p(pattern);
  return sqlite3_strlike(p.c_str(), v.c_str(), '\\') == 0;
}

std::unordered_map<uint64_t, DirtreePathInfo>
collect_inode_paths(dirtree_id_t id) {
  std::unordered_map<uint64_t, DirtreePathInfo> paths;
  const StandardTreeInfo *info = nullptr;
  for (const auto &candidate : standard_trees()) {
    if (candidate.id == id) {
      info = &candidate;
      break;
    }
  }
  if (!info)
    return paths;

  std::string error;
  dirtree_t *tree = get_tree_checked(*info, &error);
  if (!tree)
    return paths;

  CollectVisitor visitor(*info, *tree);
  if (tree->traverse(visitor) != 0)
    return paths;
  return std::move(visitor.inode_paths);
}

std::optional<DirtreePathInfo> find_inode_path(dirtree_id_t id, uint64_t inode) {
  const StandardTreeInfo *info = nullptr;
  for (const auto &candidate : standard_trees()) {
    if (candidate.id == id) {
      info = &candidate;
      break;
    }
  }
  if (!info)
    return std::nullopt;

  std::string error;
  dirtree_t *tree = get_tree_checked(*info, &error);
  if (!tree)
    return std::nullopt;

  dirtree_cursor_t cursor = tree->find_entry(direntry_t(inode, false));
  if (!cursor.valid())
    return std::nullopt;

  qstring qpath = tree->get_abspath(cursor, DTN_FULL_NAME);
  if (qpath.empty())
    return std::nullopt;

  DirtreePathInfo result;
  result.full_path = qpath.c_str();
  auto folder = folder_path_from_full(result.full_path);
  result.folder_path = folder.value_or(std::string());
  return result;
}

bool ensure_folder(dirtree_t &tree, std::string_view folder,
                   std::string *error) {
  std::string normalized = normalize_relative_path(folder);
  if (normalized.empty())
    return true;

  dterr_t err = tree.mkdir(normalized.c_str());
  if (ok_or_exists(err))
    return true;

  if (error)
    *error = "mkdir '" + normalized + "' failed: " + dirtree_error(err);
  return false;
}

bool move_inode_to_folder(dirtree_id_t id, uint64_t inode,
                          std::string_view display_name,
                          std::string_view raw_folder,
                          const char *surface_name) {
  const StandardTreeInfo *info = nullptr;
  for (const auto &candidate : standard_trees()) {
    if (candidate.id == id) {
      info = &candidate;
      break;
    }
  }
  if (!info) {
    xsql::set_vtab_error(std::string(surface_name) + ": unsupported dirtree");
    return false;
  }

  std::string error;
  dirtree_t *tree = get_tree_checked(*info, &error);
  if (!tree) {
    xsql::set_vtab_error(std::string(surface_name) + ": " + error);
    return false;
  }

  if (!validate_mutation_path(raw_folder, true, surface_name, &error)) {
    xsql::set_vtab_error(error);
    return false;
  }
  std::string folder = normalize_relative_path(raw_folder);
  std::optional<DirtreePathInfo> current = find_inode_path(id, inode);
  std::string name =
      current ? basename_of_path(current->full_path) : basename_of_path(display_name);
  if (name.empty()) {
    xsql::set_vtab_error(std::string(surface_name) + ": object name is empty");
    return false;
  }

  std::string source = current ? normalize_relative_path(current->full_path) : name;
  if (!tree->isfile(source.c_str()) && !tree->isfile(name.c_str())) {
    xsql::set_vtab_error(std::string(surface_name) +
                         ": current dirtree entry not found for inode " +
                         std::to_string(inode));
    return false;
  }
  if (!tree->isfile(source.c_str()))
    source = name;

  if (!ensure_folder(*tree, folder, &error)) {
    xsql::set_vtab_error(std::string(surface_name) + ": " + error);
    return false;
  }

  const std::string target = join_path(folder, name);
  auto unlink_alias = [&](const std::string &alias) -> bool {
    if (alias.empty() || alias == target || !tree->isfile(alias.c_str()))
      return true;
    direntry_t alias_entry = tree->resolve_path(alias.c_str());
    if (!alias_entry.valid() || alias_entry.isdir ||
        static_cast<uint64_t>(alias_entry.idx) != inode) {
      return true;
    }
    dterr_t unlink_err = tree->unlink(alias.c_str());
    if (unlink_err != DTE_OK) {
      xsql::set_vtab_error(std::string(surface_name) +
                           ": unlink '" + alias + "' failed: " +
                           dirtree_error(unlink_err));
      return false;
    }
    if (!tree->save()) {
      xsql::set_vtab_error(std::string(surface_name) +
                           ": failed to save after unlink '" + alias + "'");
      return false;
    }
    return true;
  };

  if (source == target)
    return unlink_alias(name);

  if (tree->isfile(target.c_str())) {
    direntry_t target_entry = tree->resolve_path(target.c_str());
    if (target_entry.valid() && !target_entry.isdir &&
        static_cast<uint64_t>(target_entry.idx) == inode) {
      if (source != target) {
        dterr_t unlink_err = tree->unlink(source.c_str());
        if (unlink_err != DTE_OK && !ok_or_exists(unlink_err)) {
          xsql::set_vtab_error(std::string(surface_name) +
                               ": unlink '" + source + "' failed: " +
                               dirtree_error(unlink_err));
          return false;
        }
        if (!tree->save()) {
          xsql::set_vtab_error(std::string(surface_name) +
                               ": failed to save after unlink '" + source + "'");
          return false;
        }
      }
      return true;
    }
  }

  if (tree->isdir(target.c_str()) || tree->isfile(target.c_str())) {
    xsql::set_vtab_error(std::string(surface_name) +
                         ": destination already exists: " + target);
    return false;
  }

  idasql_auto_wait();
  dterr_t err = tree->rename(source.c_str(), target.c_str());
  bool ok = err == DTE_OK && tree->save();
  idasql_auto_wait();
  if (!ok) {
    xsql::set_vtab_error(std::string(surface_name) + ": move '" + source +
                         "' to '" + target + "' failed: " + dirtree_error(err));
    return false;
  }
  return true;
}

bool move_inode_to_folder(dirtree_id_t id, uint64_t inode,
                          std::string_view display_name,
                          xsql::FunctionArg folder_arg,
                          const char *surface_name) {
  return move_inode_to_folder(id, inode, display_name,
                              folder_arg_to_string(folder_arg), surface_name);
}

bool mkdir_folder(const StandardTreeInfo &info, std::string_view folder,
                  std::string *error) {
  if (!validate_writable_tree(info, "dirtree_folders", error))
    return false;

  dirtree_t *tree = get_tree_checked(info, error);
  if (!tree)
    return false;

  if (!validate_mutation_path(folder, true, "dirtree_folders", error))
    return false;

  std::string normalized = normalize_relative_path(folder);
  if (normalized.empty())
    return true;

  idasql_auto_wait();
  dterr_t err = tree->mkdir(normalized.c_str());
  bool ok = ok_or_exists(err) && tree->save();
  idasql_auto_wait();
  if (!ok && error)
    *error = "dirtree_folders: mkdir '" + normalized +
             "' failed: " + dirtree_error(err);
  return ok;
}

bool rename_folder(const StandardTreeInfo &info, std::string_view from,
                   std::string_view to, std::string *error) {
  if (!validate_writable_tree(info, "dirtree_folders", error))
    return false;

  dirtree_t *tree = get_tree_checked(info, error);
  if (!tree)
    return false;

  if (!validate_mutation_path(from, false, "dirtree_folders", error) ||
      !validate_mutation_path(to, false, "dirtree_folders", error)) {
    return false;
  }

  std::string src = normalize_relative_path(from);
  std::string dst = normalize_relative_path(to);
  if (src.empty() || dst.empty()) {
    if (error)
      *error = "dirtree_folders: cannot rename the root folder";
    return false;
  }
  if (src == dst)
    return true;
  if (!tree->isdir(src.c_str())) {
    if (error)
      *error = "dirtree_folders: source folder not found: " + src;
    return false;
  }
  if (tree->isdir(dst.c_str()) || tree->isfile(dst.c_str())) {
    if (error)
      *error = "dirtree_folders: destination already exists: " + dst;
    return false;
  }

  // Reject renaming a folder into its own descendant (e.g. a -> a/b/c). The
  // rename would fail, and doing this check before ensure_folder() avoids
  // leaving a freshly-created destination parent chain behind.
  if (dst == src || dst.compare(0, src.size() + 1, src + "/") == 0) {
    if (error)
      *error = "dirtree_folders: cannot rename '" + src +
               "' into its own descendant: " + dst;
    return false;
  }

  std::string parent = normalize_relative_path(parent_path_of_absolute(dst));
  if (!ensure_folder(*tree, parent, error))
    return false;

  idasql_auto_wait();
  dterr_t err = tree->rename(src.c_str(), dst.c_str());
  bool ok = err == DTE_OK && tree->save();
  idasql_auto_wait();
  if (!ok && error)
    *error = "dirtree_folders: rename '" + src + "' to '" + dst +
             "' failed: " + dirtree_error(err);
  return ok;
}

bool remove_empty_folder(const StandardTreeInfo &info, std::string_view folder,
                         std::string *error) {
  if (!validate_writable_tree(info, "dirtree_folders", error))
    return false;

  dirtree_t *tree = get_tree_checked(info, error);
  if (!tree)
    return false;

  if (!validate_mutation_path(folder, false, "dirtree_folders", error))
    return false;

  std::string normalized = normalize_relative_path(folder);
  if (normalized.empty()) {
    if (error)
      *error = "dirtree_folders: cannot delete the root folder";
    return false;
  }

  idasql_auto_wait();
  dterr_t err = tree->rmdir(normalized.c_str());
  bool ok = err == DTE_OK && tree->save();
  idasql_auto_wait();
  if (!ok && error)
    *error = "dirtree_folders: rmdir '" + normalized +
             "' failed: " + dirtree_error(err);
  return ok;
}

GeneratorTableDef<DirtreeEntryRow> define_dirtree_entries() {
  auto factory = [](const std::vector<xsql::GeneratorConstraintArg> &args)
      -> std::unique_ptr<xsql::Generator<DirtreeEntryRow>> {
    const StandardTreeInfo *selected_tree = nullptr;
    std::string path_eq;
    std::string path_like;
    std::string parent_eq;
    bool has_inode = false;
    int64_t inode = 0;
    bool has_is_dir = false;
    int is_dir = 0;
    bool has_is_file = false;
    int is_file = 0;

    for (const auto &arg : args) {
      if (arg.column_index == 0 && arg.op == xsql::ConstraintOp::Eq) {
        selected_tree = find_tree(arg.value.as_c_str() ? arg.value.as_c_str() : "");
      } else if (arg.column_index == 1 && arg.op == xsql::ConstraintOp::Eq) {
        path_eq = normalize_absolute_path(arg.value.as_c_str() ? arg.value.as_c_str() : "");
      } else if (arg.column_index == 1 && arg.op == xsql::ConstraintOp::Like) {
        path_like = arg.value.as_c_str() ? arg.value.as_c_str() : "";
        if (!path_like.empty() && path_like[0] != '/')
          path_like = "/" + path_like;
      } else if (arg.column_index == 2 && arg.op == xsql::ConstraintOp::Eq) {
        parent_eq = normalize_absolute_path(arg.value.as_c_str() ? arg.value.as_c_str() : "");
      } else if (arg.column_index == 6 && arg.op == xsql::ConstraintOp::Eq) {
        has_inode = true;
        inode = arg.value.as_int64();
      } else if (arg.column_index == 4 && arg.op == xsql::ConstraintOp::Eq) {
        has_is_dir = true;
        is_dir = arg.value.as_int();
      } else if (arg.column_index == 5 && arg.op == xsql::ConstraintOp::Eq) {
        has_is_file = true;
        is_file = arg.value.as_int();
      }
    }

    std::vector<DirtreeEntryRow> rows;
    std::string error;
    auto collect_one = [&](const StandardTreeInfo &info) {
      auto tree_rows = collect_entries_for_tree(info, &error);
      for (auto &row : tree_rows) {
        if (row_matches(row, path_eq, path_like, parent_eq, has_inode, inode,
                        has_is_dir, is_dir, has_is_file, is_file)) {
          rows.push_back(std::move(row));
        }
      }
    };

    if (selected_tree) {
      collect_one(*selected_tree);
    } else {
      for (const auto &info : standard_trees())
        collect_one(info);
    }

    // Surface a tree load()/traverse() failure as a query error instead of
    // silently returning zero rows.
    if (!error.empty())
      xsql::set_vtab_error(error);

    return std::make_unique<VectorEntryGenerator>(std::move(rows));
  };

  return generator_table<DirtreeEntryRow>("dirtree_entries")
      .generator([factory]() { return factory({}); })
      .column_text("tree", [](const DirtreeEntryRow &row) { return row.tree; })
      .column_text("path", [](const DirtreeEntryRow &row) { return row.path; })
      .column_text("parent_path", [](const DirtreeEntryRow &row) { return row.parent_path; })
      .column_text("name", [](const DirtreeEntryRow &row) { return row.name; })
      .column_int("is_dir", [](const DirtreeEntryRow &row) { return row.is_dir; })
      .column_int("is_file", [](const DirtreeEntryRow &row) { return row.is_file; })
      .column_int64("inode", [](const DirtreeEntryRow &row) { return row.inode; })
      .column_int64("rank", [](const DirtreeEntryRow &row) { return row.rank; })
      .column_text("attrs", [](const DirtreeEntryRow &row) { return row.attrs; })
      .column_int("depth", [](const DirtreeEntryRow &row) { return row.depth; })
      .column_int("orderable", [](const DirtreeEntryRow &row) { return row.orderable; })
      .constraint_filter(
          {xsql::optional_eq("tree"), xsql::optional_eq("path"),
           xsql::optional_like("path"), xsql::optional_eq("parent_path"),
           xsql::optional_eq("is_dir"), xsql::optional_eq("is_file"),
           xsql::optional_eq("inode")},
          factory, 10.0, 100.0)
      .build();
}

GeneratorTableDef<DirtreeFolderRow> define_dirtree_folders() {
  auto factory = [](const std::vector<xsql::GeneratorConstraintArg> &args)
      -> std::unique_ptr<xsql::Generator<DirtreeFolderRow>> {
    const StandardTreeInfo *selected_tree = nullptr;
    std::string path_eq;
    std::string path_like;
    for (const auto &arg : args) {
      if (arg.column_index == 0 && arg.op == xsql::ConstraintOp::Eq) {
        selected_tree = find_tree(arg.value.as_c_str() ? arg.value.as_c_str() : "");
      } else if (arg.column_index == 1 && arg.op == xsql::ConstraintOp::Eq) {
        path_eq = normalize_relative_path(arg.value.as_c_str() ? arg.value.as_c_str() : "");
      } else if (arg.column_index == 1 && arg.op == xsql::ConstraintOp::Like) {
        path_like = arg.value.as_c_str() ? arg.value.as_c_str() : "";
      }
    }

    std::vector<DirtreeFolderRow> rows;
    std::string error;
    auto collect_one = [&](const StandardTreeInfo &info) {
      auto tree_rows = collect_folders_for_tree(info, &error);
      for (auto &row : tree_rows) {
        if (!path_eq.empty() && row.path != path_eq)
          continue;
        if (!path_like.empty() && !sqlite_like(row.path, path_like))
          continue;
        rows.push_back(std::move(row));
      }
    };

    if (selected_tree) {
      collect_one(*selected_tree);
    } else {
      for (const auto &info : standard_trees())
        collect_one(info);
    }

    // Surface a tree load()/traverse() failure as a query error instead of
    // silently returning zero rows.
    if (!error.empty())
      xsql::set_vtab_error(error);

    return std::make_unique<VectorFolderGenerator>(std::move(rows));
  };

  return generator_table<DirtreeFolderRow>("dirtree_folders")
      .generator([factory]() { return factory({}); })
      .column_text_rw(
          "tree",
          [](const DirtreeFolderRow &row) { return row.tree; },
          [](DirtreeFolderRow &row, xsql::FunctionArg value) -> bool {
            const char *text = value.as_c_str();
            const StandardTreeInfo *info = find_tree(text ? text : "");
            if (!info || info->name != row.tree) {
              xsql::set_vtab_error("dirtree_folders: tree cannot be changed");
              return false;
            }
            return true;
          })
      .column_text_rw(
          "path",
          [](const DirtreeFolderRow &row) { return row.path; },
          [](DirtreeFolderRow &row, xsql::FunctionArg value) -> bool {
            const StandardTreeInfo *info = find_tree(row.tree);
            if (!info) {
              xsql::set_vtab_error("dirtree_folders: unknown tree '" + row.tree + "'");
              return false;
            }
            std::string error;
            if (!rename_folder(*info, row.path,
                               value.is_null() ? std::string() :
                                   std::string(value.as_c_str() ? value.as_c_str() : ""),
                               &error)) {
              xsql::set_vtab_error(error);
              return false;
            }
            return true;
          })
      .column_text("full_path", [](const DirtreeFolderRow &row) { return row.full_path; })
      .row_lookup([](DirtreeFolderRow &row, int64_t rowid) -> bool {
        int tree_index = static_cast<int>((rowid >> 32) - 1);
        int64_t diridx = rowid & 0xffffffffLL;
        const StandardTreeInfo *info = find_tree_by_index(tree_index);
        if (!info)
          return false;
        std::string error;
        auto rows = collect_folders_for_tree(*info, &error);
        for (auto &candidate : rows) {
          if (candidate.diridx == diridx) {
            row = std::move(candidate);
            return true;
          }
        }
        return false;
      })
      .deletable([](DirtreeFolderRow &row) -> bool {
        const StandardTreeInfo *info = find_tree(row.tree);
        if (!info) {
          xsql::set_vtab_error("dirtree_folders: unknown tree '" + row.tree + "'");
          return false;
        }
        std::string error;
        if (!remove_empty_folder(*info, row.path, &error)) {
          xsql::set_vtab_error(error);
          return false;
        }
        return true;
      })
      .insertable([](int argc, xsql::FunctionArg *argv) -> bool {
        if (argc < 2 || argv[0].is_null() || argv[1].is_null()) {
          xsql::set_vtab_error("dirtree_folders: INSERT requires tree and path");
          return false;
        }
        const char *tree_name = argv[0].as_c_str();
        const StandardTreeInfo *info = find_tree(tree_name ? tree_name : "");
        if (!info) {
          xsql::set_vtab_error("dirtree_folders: unknown tree");
          return false;
        }
        std::string error;
        if (!mkdir_folder(*info, argv[1].as_c_str() ? argv[1].as_c_str() : "",
                          &error)) {
          xsql::set_vtab_error(error);
          return false;
        }
        return true;
      })
      .constraint_filter({xsql::optional_eq("tree"), xsql::optional_eq("path"),
                          xsql::optional_like("path")},
                         factory, 5.0, 20.0)
      .build();
}

} // namespace dirtrees
} // namespace idasql
