// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * entities_comments.hpp - `comments` table (regular + repeatable comments).
 */

#pragma once

#include "core_common.hpp"

namespace idasql {
namespace symbols {

struct CommentRow {
  ea_t ea = BADADDR;
  std::string comment;
  std::string rpt_comment;
};

void collect_comment_rows(std::vector<CommentRow> &rows);

CachedTableDef<CommentRow> define_comments();

} // namespace symbols
} // namespace idasql
