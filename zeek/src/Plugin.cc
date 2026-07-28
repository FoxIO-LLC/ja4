
#include "Plugin.h"
#include <string>
#include <cctype>
#include <sstream>
#include <vector>
#include "zeek/util.h"
#include "zeek/net_util.h"
#include "zeek/ZeekString.h"
#include "zeek/Val.h"
#include "zeek/ZVal.h"
#include "zeek/Conn.h"
#include "zeek/DebugLogger.h"


using namespace zeek::plugin::FINGERPRINT_JA4;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "FINGERPRINT::JA4";
	config.description = "JA4+ network fingerprinting (JA4/JA4S/JA4H/JA4SSH/JA4T/JA4L/JA4D)";
	config.version.major = 1;

	config.version.minor = 0;
	config.version.patch = 0;

	return config;
	}