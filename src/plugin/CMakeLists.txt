cmake_minimum_required(VERSION 3.27)
project(idasql_plugin)
set(CMAKE_CXX_STANDARD 20)

# IDA SDK
include($ENV{IDASDK}/src/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# Find libxsql (sibling directory)
if(NOT TARGET xsql::xsql)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../libxsql libxsql)
endif()

# Plugin sources
ida_add_plugin(idasql_plugin
    SOURCES main.cpp
)

# Include directories and link dependencies
target_include_directories(idasql_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../libxsql/include
)
target_link_libraries(idasql_plugin PRIVATE xsql::xsql)

# Windows socket library
if(WIN32)
    target_link_libraries(idasql_plugin PRIVATE ws2_32)
endif()

# Hex-Rays support
target_compile_definitions(idasql_plugin PRIVATE USE_HEXRAYS)
