/*
 * Do not modify this file. Changes will be overwritten.
 *
 * Generated automatically from make-plugin-reg.py.
 */

#ifndef OOT_BUILD
#include "config.h"
#endif

#include <gmodule.h>

/* plugins are DLLs on Windows */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

#include "epan/proto.h"

void proto_register_ja4(void);
void proto_reg_handoff_ja4(void);

#ifndef OOT_BUILD
WS_DLL_PUBLIC_DEF const gchar plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;
#else
WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;
#endif

WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void) {
    static proto_plugin plug_ja4;

    plug_ja4.register_protoinfo = proto_register_ja4;
    plug_ja4.register_handoff = proto_reg_handoff_ja4;
    proto_register_plugin(&plug_ja4);
}
