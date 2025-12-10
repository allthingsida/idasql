# libidasql - SQL interface to IDA databases
#
# This is a header-only library that extends xsql with IDA-specific tables.
# Users link against this target to get the include paths.

add_library(idasql INTERFACE)

target_include_directories(idasql INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Link against xsql::xsql for SQLite virtual table framework
target_link_libraries(idasql INTERFACE xsql::xsql)

# Export the library target
# install(TARGETS idasql EXPORT idasqlTargets)
# install(DIRECTORY include/idasql DESTINATION include)
