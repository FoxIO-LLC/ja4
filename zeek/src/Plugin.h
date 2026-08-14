
#pragma once

#include <zeek/plugin/Plugin.h>

namespace zeek::plugin::FINGERPRINT_JA4 {

class Plugin : public zeek::plugin::Plugin
{
public:
	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
} plugin;

}
