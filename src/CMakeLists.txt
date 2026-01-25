# src/CMakeLists.txt - idasql source directory
# SQLite is now provided by xsql::xsql from libxsql

add_subdirectory(lib)

# CLI tool (standalone, uses idalib)
option(IDASQL_BUILD_CLI "Build idasql CLI tool" ON)
if(IDASQL_BUILD_CLI)
    add_subdirectory(cli)
endif()

# IDA Plugin (requires IDASDK)
option(IDASQL_BUILD_PLUGIN "Build idasql IDA plugin" ON)
if(IDASQL_BUILD_PLUGIN)
    add_subdirectory(plugin)
endif()
