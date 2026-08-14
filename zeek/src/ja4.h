#pragma once

#include <cstring>
#include <cctype>
#include <vector>
#include "zeek/util.h"
#include "zeek/net_util.h"
#include "zeek/ZeekString.h"
#include "zeek/Val.h"
#include "zeek/Conn.h"

std::string b_hash(std::vector<uint32_t> input);
std::string c_hash(std::string input);
std::string make_a(TransportProto transport_proto, std::string conn_service, std::vector<std::string> sni, std::vector<std::string> alpns, std::vector<uint32_t> cipher_suites,
                   std::vector<uint32_t> extension_codes, int version);
zeek::ValPtr do_ja4(zeek::RecordVal* conn_record, zeek::StringVal* delimiter);
