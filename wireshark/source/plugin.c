/*
 * Do not modify this file. Changes will be overwritten.
 *
 * Generated automatically from make-plugin-reg.py.
 */

#include "config.h"

#include <gmodule.h>

/* plugins are DLLs on Windows */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

#include "epan/proto.h"

void proto_register_ja4(void);
void proto_reg_handoff_ja4(void);

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void)
{
    static proto_plugin plug_ja4;

    plug_ja4.register_protoinfo = proto_register_ja4;
    plug_ja4.register_handoff = proto_reg_handoff_ja4;
    proto_register_plugin(&plug_ja4);
}
