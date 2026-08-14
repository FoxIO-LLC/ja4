cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ZeekPluginJA4)

# Zeek's Broker cmake exports may reference CAF targets when built with
# external CAF.  Create stub INTERFACE targets as a safety net.
# Note: Zeek 8.0+ with internal CAF no longer needs these, but the guards
# make them harmless.  The broker/broker-prometheus-cpp targets are created
# by BrokerTargets.cmake — do NOT pre-define them here or the partial-
# definition check in that file will fail.
foreach(_caf_target CAF::core CAF::io CAF::net)
    if(NOT TARGET ${_caf_target})
        add_library(${_caf_target} INTERFACE IMPORTED)
    endif()
endforeach()

include(ZeekPlugin)

# Zeek 7.x Broker headers require C++20 (concepts, requires).
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

zeek_plugin_begin(FINGERPRINT JA4 ${ZEEK_PLUGIN_BEGIN_OPTS})
zeek_plugin_cc(src/Plugin.cc src/ja4.cc src/ja4h.cc src/ja4s.cc src/ja4ssh.cc src/ja4t.cc src/common.cc)
zeek_plugin_bif(src/ja4.bif)
zeek_plugin_dist_files(README COPYING VERSION)
zeek_plugin_scripts(scripts/__load__.zeek)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
