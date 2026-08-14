#include <string>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <vector>
#include "zeek/util.h"
#include "zeek/net_util.h"
#include "zeek/ZeekString.h"
#include "zeek/Val.h"
#include "zeek/ZVal.h"
#include "zeek/Conn.h"
#include "zeek/Desc.h"

#include "common.h"
#include "ja4s.h"
#include "ssl-consts.h"

using namespace FINGERPRINT;

// Build the JA4S_a section: {proto}{version}{ext_count}{alpn}
static std::string make_a(TransportProto transport_proto,
                                 const std::string& conn_service,
                                 const std::string& alpn,
                                 int ext_count, 
                                 uint32_t version) {
    std::string proto = "t";
    if (transport_proto == TransportProto::TRANSPORT_UDP &&
        conn_service.find("QUIC") != std::string::npos) {
        proto = "q";
    }

    std::string ver = "00";
    auto it = TLS_VERSION_MAPPER.find(version);
    if (it != TLS_VERSION_MAPPER.end()) {
        ver = it->second;
    }

    // Capped at 99
    std::ostringstream ec_stream;
    if (ext_count > 99)
        ec_stream << "99";
    else
        ec_stream << std::setw(2) << std::setfill('0') << ext_count;

    // ALPN: first + last character, default "00"
    std::string alpn_code = "00";
    if (!alpn.empty() && alpn != "00") {
        alpn_code = std::string(1, alpn.front()) + std::string(1, alpn.back());
    }

    return proto + ver + ec_stream.str() + alpn_code;
}

zeek::ValPtr do_ja4s(zeek::RecordVal* conn_record, zeek::StringVal* delimiter) {
    auto fp = cast_intrusive<zeek::RecordVal>(conn_record->GetField("fp"));                                                                                     
    auto server_hello = cast_intrusive<zeek::RecordVal>(fp->GetField("server_hello"));
    
    uint32_t version = 0;
    if (server_hello->HasField("version")) {
        version = static_cast<uint32_t>(zeek::cast_intrusive<zeek::IntVal>(server_hello->GetField("version"))->AsCount());     
    }

    uint32_t cipher = 0;
    if (server_hello->HasField("cipher")) {
        cipher = static_cast<uint32_t>(zeek::cast_intrusive<zeek::IntVal>(server_hello->GetField("cipher"))->AsCount());
    }

    auto ec_vector = cast_intrusive<zeek::VectorVal>(server_hello->GetField("extension_codes"));
    auto extension_codes = convert_count_vector_to_u32_cpp(ec_vector);

    auto alpn = cast_intrusive<zeek::StringVal>(server_hello->GetField("alpn"))->ToStdString();

    auto conn_data = cast_intrusive<zeek::RecordVal>(conn_record->GetField("conn"));                                                                            
    TransportProto transport_proto = TransportProto::TRANSPORT_UNKNOWN;                                                                                         
    if (conn_data && conn_data->HasField("proto")) {                                                                                                            
        auto proto_val = zeek::cast_intrusive<zeek::EnumVal>(conn_data->GetField("proto"));                                                                     
        transport_proto = static_cast<TransportProto>(proto_val->AsInt());                                                                                      
    } 

    std::string service = "";
    if (conn_record->HasField("service")) {
        auto service_val = conn_record->GetField("service");
        service = table_to_json_string_cpp(service_val->AsTableVal());
    }

    std::string ja4s_a = make_a(transport_proto, service, alpn, static_cast<int>(extension_codes.size()), version);

    char cipher_buf[8];
    snprintf(cipher_buf, sizeof(cipher_buf), "%04x", cipher);
    std::string ja4s_b(cipher_buf);

    std::string ja4s_c = vector_of_count_to_str_cpp(extension_codes);

    const zeek::String* zstr = delimiter->AsStringVal()->AsString();
    std::string delimiter_val(reinterpret_cast<const char*>(zstr->Bytes()), zstr->Len());

    std::string ja4s = ja4s_a + delimiter_val + ja4s_b + delimiter_val + sha256_or_null__12_cpp(ja4s_c);
    std::string ja4s_r = ja4s_a + delimiter_val + ja4s_b + delimiter_val + ja4s_c;

    auto ja4s_type = zeek::id::find_type<zeek::RecordType>("FINGERPRINT::JA4S::Info");
    auto ja4s_result = zeek::make_intrusive<zeek::RecordVal>(ja4s_type);
    ja4s_result->Assign(1, zeek::make_intrusive<zeek::StringVal>(ja4s));
    ja4s_result->Assign(2, zeek::make_intrusive<zeek::StringVal>(ja4s_r));

    return ja4s_result;
}
