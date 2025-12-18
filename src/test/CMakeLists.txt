# idalib_driver - Test driver for IDASQL plugin in headless mode
#
# Build:
#   cmake -B build
#   cmake --build build --config RelWithDebInfo
#
# Run driver manually:
#   Windows: set PATH=%IDASDK%\bin;%PATH% && build\RelWithDebInfo\idalib_driver.exe database.i64
#   Linux:   LD_LIBRARY_PATH=$IDASDK/bin ./build/idalib_driver database.i64
#
# Run full test harness:
#   python run_tests.py
#   python run_tests.py --test-db /path/to/test.i64
#   python run_tests.py --skip-build

cmake_minimum_required(VERSION 3.20)
project(idalib_driver)
set(CMAKE_CXX_STANDARD 20)

include($ENV{IDASDK}/ida-cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

ida_add_idalib(idalib_driver
    TYPE EXECUTABLE
    SOURCES idalib_driver.cpp
)

# Platform-specific settings
if(MSVC)
    file(TO_NATIVE_PATH "${IDABIN}" IDABIN_NATIVE)
    set_target_properties(idalib_driver PROPERTIES
        VS_DEBUGGER_ENVIRONMENT "PATH=${IDABIN_NATIVE};%PATH%"
    )
elseif(APPLE)
    set_target_properties(idalib_driver PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "@executable_path;$ENV{IDASDK}/bin"
    )
elseif(UNIX)
    set_target_properties(idalib_driver PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "$ORIGIN;$ENV{IDASDK}/bin"
    )
endif()

# Add test target that runs the Python harness
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_custom_target(run_tests
        COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py" --skip-build
        DEPENDS idalib_driver
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Running IDASQL plugin tests"
    )
endif()
