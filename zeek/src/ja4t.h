#pragma once

#include <string>
#include <vector>
#include "zeek/Val.h"

zeek::ValPtr parse_tcp_options(zeek::StringVal* pkt_data, uint32_t caplen,
                               uint32_t ip_hl, uint32_t tcp_hl);
