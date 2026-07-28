#include <cstdint>
#include <vector>
#include "zeek/Val.h"
#include "zeek/ZeekString.h"

#include "ja4t.h"

// Ethernet/VLAN constants
constexpr uint16_t ETHERTYPE_VLAN     = 0x8100;
constexpr uint16_t ETHERTYPE_QINQ     = 0x8A88;
constexpr uint16_t ETHERTYPE_IPV4     = 0x0800;
constexpr uint16_t ETHERTYPE_IPV6     = 0x86DD;
constexpr uint32_t ETH_MAC_HEADER_LEN = 12;     // 6 dst + 6 src
constexpr uint32_t ETHERTYPE_FIELD_LEN = 2;
constexpr uint32_t VLAN_TAG_LEN       = 4;       // 2 tag protocol id + 2 tag control
constexpr uint32_t IPV6_BASE_HEADER_LEN = 40;
constexpr uint32_t TCP_BASE_HEADER_LEN  = 20;

// TCP option kinds
constexpr uint8_t TCP_OPT_EOL          = 0;
constexpr uint8_t TCP_OPT_NOP          = 1;
constexpr uint8_t TCP_OPT_MSS          = 2;
constexpr uint8_t TCP_OPT_WINDOW_SCALE = 3;

zeek::ValPtr parse_tcp_options(zeek::StringVal* pkt_data, uint32_t caplen,
                               uint32_t ip_hl, uint32_t tcp_hl) {

    auto opts_type = zeek::id::find_type<zeek::RecordType>("FINGERPRINT::JA4T::TCP_Options");
    auto opts = zeek::make_intrusive<zeek::RecordVal>(opts_type);

    const unsigned char* data = pkt_data->AsString()->Bytes();

    // Phase 1: Walk past Ethernet MACs + VLAN tags to find IP header.
    // Ethernet frame: 6 bytes dst MAC + 6 bytes src MAC, then 2-byte EtherType.
    uint32_t eth_offset = ETH_MAC_HEADER_LEN;

    while (eth_offset + ETHERTYPE_FIELD_LEN < caplen) {
        uint16_t ethertype = (data[eth_offset] << 8) | data[eth_offset + 1];

        if (ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ) {
            eth_offset += VLAN_TAG_LEN;
        } else if (ethertype == ETHERTYPE_IPV4) {
            eth_offset += ETHERTYPE_FIELD_LEN + ip_hl;
            break;
        } else if (ethertype == ETHERTYPE_IPV6) {
            eth_offset += ETHERTYPE_FIELD_LEN + IPV6_BASE_HEADER_LEN;
            break;
        } else {
            return opts;
        }
    }

    // Phase 2: eth_offset now points at the TCP header.
    // Verify the full TCP header (including options) fits in the capture.
    uint32_t tcp_options_end = eth_offset + tcp_hl;
    if (tcp_options_end > caplen) {
        return opts;
    }
    uint32_t tcp_opt_offset = eth_offset + TCP_BASE_HEADER_LEN;

    // Phase 3: Parse TCP options.
    // TLV format: 1 byte kind, 1 byte length (includes kind+len bytes),
    // then (length-2) data bytes. Kind 0 (EOL) and 1 (NOP) are single-byte.
    std::vector<uint32_t> option_kinds;
    uint32_t mss = 0;
    uint32_t window_scale = 0;

    while (tcp_opt_offset < tcp_options_end) {
        uint8_t opt_kind = data[tcp_opt_offset];

        if (opt_kind == TCP_OPT_EOL) {
            break;
        }

        option_kinds.push_back(opt_kind);

        if (opt_kind == TCP_OPT_NOP || tcp_opt_offset + 1 >= tcp_options_end) {
            tcp_opt_offset += 1;
            continue;
        }

        uint8_t opt_len = data[tcp_opt_offset + 1];
        if (opt_len < 2) {
            break;
        }

        if (opt_kind == TCP_OPT_MSS && tcp_opt_offset + 3 < tcp_options_end) {
            mss = (data[tcp_opt_offset + 2] << 8) | data[tcp_opt_offset + 3];
        }

        if (opt_kind == TCP_OPT_WINDOW_SCALE && tcp_opt_offset + 2 < tcp_options_end) {
            window_scale = data[tcp_opt_offset + 2];
        }

        tcp_opt_offset += opt_len;
    }

    // Build return record: TCP_Options { option_kinds, max_segment_size, window_scale }
    auto kinds_vec = zeek::make_intrusive<zeek::VectorVal>(
        zeek::cast_intrusive<zeek::VectorType>(opts_type->GetFieldType("option_kinds")));
    for (auto k : option_kinds) {
        kinds_vec->Append(zeek::val_mgr->Count(k));
    }

    opts->Assign(0, std::move(kinds_vec));
    opts->Assign(1, zeek::val_mgr->Count(mss));
    opts->Assign(2, zeek::val_mgr->Count(window_scale));

    return opts;
}
