# CMakeLists.txt
#
# Wireshark - JA4 Fingerprint
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(ja4 0 0 1 0)

set(DISSECTOR_SRC
	packet-ja4.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(
	plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_wireshark_plugin_library(ja4 epan)

target_link_libraries(ja4 epan)

install_plugin(ja4 epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  ja4
	SWITCHES
	  --group dissectors-prohibited
	  --group dissectors-restricted
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)

