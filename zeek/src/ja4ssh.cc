#include <string>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <vector>
#include <unordered_map>
#include "zeek/util.h"
#include "zeek/net_util.h"
#include "zeek/ZeekString.h"
#include "zeek/Val.h"
#include "zeek/ZVal.h"
#include "zeek/Conn.h"
#include "zeek/Desc.h"

#include "common.h"
#include "ja4ssh.h"

using namespace FINGERPRINT;

uint32_t get_mode(const std::vector<uint32_t> &vec) {
    // build frequency map
    std::unordered_map<uint32_t, uint32_t> frequency = {};

    // count frequency of each packet size
    for(auto size : vec ) {
        ++frequency[size];
    }

    // max is the highest frequency count (how many times we saw a given size of packet)
    uint32_t max = 0;
    // mode is the size itself which is what we care about
    uint32_t mode = 0;
    for(auto &idx : frequency) {
        // Deterministic tie-breaker: for equal frequency choose the smallest value.
        if( idx.second > max || (idx.second == max && idx.first < mode) ) {
            max = idx.second;
            mode = idx.first;
        }
    }

    return mode;
}

zeek::ValPtr do_ja4ssh(zeek::RecordVal* conn_record) {

    auto fp = cast_intrusive<zeek::RecordVal>(conn_record->GetField("fp"));
    auto ja4ssh = cast_intrusive<zeek::RecordVal>(fp->GetField("ja4ssh"));
    auto orig_pack_len = convert_count_vector_to_u32_cpp(cast_intrusive<zeek::VectorVal>(ja4ssh->GetField("orig_pack_len")));
    auto resp_pack_len = convert_count_vector_to_u32_cpp(cast_intrusive<zeek::VectorVal>(ja4ssh->GetField("resp_pack_len")));

    uint32_t orig_ack = cast_intrusive<zeek::IntVal>(ja4ssh->GetField("orig_ack"))->AsCount();
    uint32_t resp_ack = cast_intrusive<zeek::IntVal>(ja4ssh->GetField("resp_ack"))->AsCount();

    // mode of packet sizes per direction                                                                                                                       
    uint32_t orig_mode = get_mode(orig_pack_len);                                                                                                               
    uint32_t resp_mode = get_mode(resp_pack_len);                                                                                                               
                                                                                                                                                                
    // how many data packets per direction (vector length)                                                                                                      
    uint32_t orig_count = static_cast<uint32_t>(orig_pack_len.size());
    uint32_t resp_count = static_cast<uint32_t>(resp_pack_len.size());

    // ack counts are already extracted as uint32_t

    // format: c{orig_mode}s{resp_mode}_c{orig_count}s{resp_count}_c{orig_ack}s{resp_ack}
    char buf[128];
    snprintf(buf, sizeof(buf), "c%ds%d_c%ds%d_c%ds%d",
        orig_mode, 
        resp_mode,
        orig_count, 
        resp_count,
        orig_ack, 
        resp_ack);

    return zeek::make_intrusive<zeek::StringVal>(std::string(buf));
}
