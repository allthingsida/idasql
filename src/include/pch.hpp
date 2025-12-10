/**
 * pch.hpp - Precompiled header for IDASQL
 *
 * Include frequently used headers here for faster compilation.
 */

#pragma once

// Standard library
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <sstream>
#include <iostream>
#include <cstring>
#include <cstdint>

// SQLite
#include <sqlite3.h>

// IDA SDK (most common headers)
#ifdef USE_IDA_SDK
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <xref.hpp>
#include <bytes.hpp>
#include <lines.hpp>
#include <kernwin.hpp>
#endif
