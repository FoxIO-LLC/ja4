# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

cmake_minimum_required(VERSION 3.12)
cmake_policy(SET CMP0048 NEW)

project(Ja4 VERSION 0.18.2 DESCRIPTION "Wireshark Ja Plugin" LANGUAGES C)

find_package(Wireshark CONFIG REQUIRED)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}"
		CACHE PATH "Installation prefix" FORCE
	)
endif()

if(NOT Wireshark_PLUGINS_ENABLED)
	message(WARNING "Wireshark was compiled without support for plugins")
endif()

# External plugins must define HAVE_SSIZE_T for the plugin toolchain.
include(CheckTypeSize)
check_type_size("ssize_t" SSIZE_T)

set(CMAKE_C_VISIBILITY_PRESET hidden)
if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

add_compile_definitions(
	VERSION=\"${PROJECT_VERSION}\"
	$<$<BOOL:${HAVE_SSIZE_T}>:HAVE_SSIZE_T>
)

option(USER_INSTALL "Install plugin to the user's home path instead of system-wide " OFF)

add_library(ja4 MODULE plugin.c packet-ja4.c)
set_target_properties(ja4 PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(ja4 epan)
target_compile_definitions(ja4 PRIVATE OOT_BUILD)

if(${USER_INSTALL})
  set(JA4_INSTALL_DIR "~/.local/lib/wireshark/plugins/${Wireshark_MAJOR_VERSION}.${Wireshark_MINOR_VERSION}")
else()
  set(JA4_INSTALL_DIR ${Wireshark_PLUGIN_LIBDIR})
endif()

# This is the normal installation target to CMAKE_INSTALL_PREFIX. It is relocatable
# using DESTDIR or cmake --install. By default CMAKE_INSTALL_PREFIX should be configured
# correctly for Wireshark's system installation prefix.
install(TARGETS ja4
	LIBRARY DESTINATION "${JA4_INSTALL_DIR}/epan" NAMELINK_SKIP
)

# This custom target installs the plugin to the plugin dir in WiresharkConfig.cmake.
# It does not use CMAKE_INSTALL_PREFIX.
add_custom_target(copy_plugin
	COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ja4> ${JA4_INSTALL_DIR}
	COMMENT "Installing plugin to: ${JA4_INSTALL_DIR}"
)

