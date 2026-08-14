#include <string>
#include <cctype>
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
#include "zeek/analyzer/protocol/ssl/SSL.h"

#include "common.h"
#include "ja4.h"
#include "ssl-consts.h"

using namespace FINGERPRINT;

std::string b_hash(std::vector<uint32_t> input) {
    return FINGERPRINT::sha256_or_null__12_cpp(
        FINGERPRINT::vector_of_count_to_str_cpp(input)
    );
}

std::string c_hash(std::string input) { 
    return FINGERPRINT::sha256_or_null__12_cpp(input);
}

std::string make_a(TransportProto transport_proto, std::string conn_service, std::vector<std::string> sni, std::vector<std::string> alpns, std::vector<uint32_t> cipher_suites,
                    std::vector<uint32_t> extension_codes, int version) {
    // Get SSL protocol type
    std::string proto_for_hash = "0";
    if (transport_proto == TransportProto::TRANSPORT_UDP && 
        conn_service.find("QUIC") != std::string::npos) {
        proto_for_hash = "q";
    } else {
        proto_for_hash = "t"; // Assume TCP
    }

    // TLS version mapping
    std::string version_for_hash = "00";
    auto version_mapper = TLS_VERSION_MAPPER.find(version);

    if (version_mapper != TLS_VERSION_MAPPER.end()) {
        version_for_hash = version_mapper->second;
    }

    // Determine SNI status
    std::string sni_for_hash = "i";
    if (!sni.empty()) {
        sni_for_hash = "d";
    }

    // Cipher suite count, max 99
    std::ostringstream cs_stream;
    int cs_size = static_cast<uint32_t>(cipher_suites.size());
    if (cs_size > 99)
        cs_stream << "99";
    else
        cs_stream << std::setw(2) << std::setfill('0') << cs_size;
    std::string cs_count_for_hash = cs_stream.str();

    // Extension count, max 99
    std::ostringstream ec_stream;
    int ec_size = static_cast<uint32_t>(extension_codes.size());
    if (ec_size > 99)
        ec_stream << "99";
    else
        ec_stream << std::setw(2) << std::setfill('0') << ec_size;
    std::string ec_count_hash = ec_stream.str();


    // Get ALPN first and last character
    std::string alpn_for_hash = "00";
    if (!alpns.empty() && !alpns[0].empty()){
        const std::string& first_alpn = {alpns[0][0]};
        const std::string& last_alpn = {alpns[0].back()};
        alpn_for_hash = first_alpn.substr(0, 1) + last_alpn.substr(last_alpn.size() - 1, 1);
    }

    // Assemble JA4_a string
    std::string a = proto_for_hash + version_for_hash + sni_for_hash + cs_count_for_hash + ec_count_hash + alpn_for_hash;
    return a;
}

zeek::ValPtr do_ja4(zeek::RecordVal* conn_record, zeek::StringVal* delimiter) {

    const zeek::String* zstr = delimiter->AsStringVal()->AsString();
    std::string delimiter_val(reinterpret_cast<const char*>(zstr->Bytes()), zstr->Len());


    zeek::IntrusivePtr<zeek::RecordType> ja4_return_value_type = zeek::id::find_type<zeek::RecordType>("FINGERPRINT::JA4::Info");

    zeek::IntrusivePtr<zeek::RecordVal> ja4_return_value = zeek::make_intrusive<zeek::RecordVal>(ja4_return_value_type);

    zeek::IntrusivePtr<zeek::RecordVal> fingerprint = cast_intrusive<zeek::RecordVal>(conn_record->GetField("fp"));
    zeek::IntrusivePtr<zeek::RecordVal> client_hello = cast_intrusive<zeek::RecordVal>(fingerprint->GetField("client_hello"));
    zeek::IntrusivePtr<zeek::RecordVal> conn_data = cast_intrusive<zeek::RecordVal>(conn_record->GetField("conn"));
    
    bool sni_exists = client_hello->HasField("sni");
    std::vector<std::string> sni;
    if (sni_exists == false){
        sni = std::vector<std::string>();
    }
    else {
        zeek::IntrusivePtr<zeek::Val> sni_val = client_hello->GetField("sni");
        zeek::IntrusivePtr<zeek::VectorVal> sni_vec = cast_intrusive<zeek::VectorVal>(sni_val);
        sni = convert_string_vector_cpp(sni_vec);
    }

    std::vector<std::string> alpns;
    bool alpns_exists = client_hello->HasField("alpns");

    if (alpns_exists == false){
        alpns = std::vector<std::string>();
    }
    else {
        zeek::IntrusivePtr<zeek::Val> alpns_val = client_hello->GetField("alpns");
        zeek::IntrusivePtr<zeek::VectorVal> alpns_vec = cast_intrusive<zeek::VectorVal>(alpns_val);
        alpns = convert_string_vector_cpp(alpns_vec);
    }

    std::vector<uint32_t> cipher_suites;
    bool cipher_suites_exists = client_hello->HasField("cipher_suites");

    if (cipher_suites_exists == false){
        cipher_suites = std::vector<uint32_t>();
    }
    else {
        zeek::IntrusivePtr<zeek::Val> cipher_suites_val = client_hello->GetField("cipher_suites");
        zeek::IntrusivePtr<zeek::VectorVal> cipher_suites_vec = cast_intrusive<zeek::VectorVal>(cipher_suites_val);
        cipher_suites = convert_count_vector_to_u32_cpp(cipher_suites_vec);
    }

    std::vector<uint32_t> extension_codes;
    bool extension_codes_exists = client_hello->HasField("extension_codes");
    if (extension_codes_exists == false){
        extension_codes = std::vector<uint32_t>();
    }
    else {
        zeek::IntrusivePtr<zeek::Val> extension_codes_val = client_hello->GetField("extension_codes");
        zeek::IntrusivePtr<zeek::VectorVal> extension_codes_vec = cast_intrusive<zeek::VectorVal>(extension_codes_val);
        extension_codes = convert_count_vector_to_u32_cpp(extension_codes_vec);
    }

    uint32_t version = 0;
    bool version_exists = client_hello->HasField("version"); 
    if (version_exists == false){
        version = 0;
    }
    else {
        zeek::IntrusivePtr<zeek::Val> version_val = client_hello->GetField("version");
        version = static_cast<uint32_t>(zeek::cast_intrusive<zeek::IntVal>(version_val)->AsCount());
    }
   
    std::vector<uint32_t> signature_algos;
    bool signature_algos_exists = client_hello->HasField("signature_algos");
    if (signature_algos_exists == false){
        signature_algos = std::vector<uint32_t>();
    }
    else {
        zeek::IntrusivePtr<zeek::Val> signature_algos_val = client_hello->GetField("signature_algos");
        zeek::IntrusivePtr<zeek::VectorVal> signature_algos_vec = cast_intrusive<zeek::VectorVal>(signature_algos_val);
        signature_algos = convert_count_vector_to_u32_cpp(signature_algos_vec);
    }

    bool service_exists = conn_record->HasField("service");
    std::string service;
    if (service_exists == false){
        service = "";
    }
    else {
        zeek::IntrusivePtr<zeek::Val> service_str_value = conn_record->GetField("service");
        zeek::TableVal* service_table = service_str_value->AsTableVal();
        service = table_to_json_string_cpp(service_table);
    }
    
    // conn_data (c$conn) is &optional — may not exist yet
    zeek::IntrusivePtr<zeek::EnumVal> protocol_enum_val;
    TransportProto transport_proto = TransportProto::TRANSPORT_UNKNOWN;
    if (conn_data && conn_data->HasField("proto")) {
        zeek::IntrusivePtr<zeek::Val> proto_val = conn_data->GetField("proto");
        protocol_enum_val = zeek::cast_intrusive<zeek::EnumVal>(proto_val);
        transport_proto = static_cast<TransportProto>(protocol_enum_val->AsInt());
    }

    std::string ja4_a = make_a(transport_proto, service, sni, alpns, cipher_suites, extension_codes, version);
    std::vector<uint32_t> ja4_b = cipher_suites; 


    // Filtered extensions (excluding SNI and ALPN)
    std::vector<uint32_t> extensions;
    uint32_t code;
    for (int i = 0; i < extension_codes.size(); i++) {
        code = extension_codes[i];
        if (code == SSLExtension::SSL_EXTENSION_SERVER_NAME || code == SSLExtension::SSL_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION) continue;
        extensions.push_back(code);
    }

    std::string ja4_c = FINGERPRINT::vector_of_count_to_str_cpp(
        FINGERPRINT::order_vector_of_count_cpp(extensions)
    );

    if (signature_algos.size() > 0) {
        ja4_c += delimiter_val;
        ja4_c += FINGERPRINT::vector_of_count_to_str_cpp(signature_algos);
    }

    // ja4
    std::string ja4_string = ja4_a + delimiter_val +
                             b_hash(FINGERPRINT::order_vector_of_count_cpp(ja4_b)) +
                             delimiter_val + c_hash(ja4_c);

    ja4_return_value->Assign(1, zeek::make_intrusive<zeek::StringVal>(ja4_string));

    // ja4_r
    std::string ja4_r = ja4_a + delimiter_val +
                        FINGERPRINT::vector_of_count_to_str_cpp(FINGERPRINT::order_vector_of_count_cpp(ja4_b)) +
                        delimiter_val + ja4_c;
    
    ja4_return_value->Assign(3, zeek::make_intrusive<zeek::StringVal>(ja4_r));

    // ja4_o
    ja4_c = FINGERPRINT::vector_of_count_to_str_cpp(extension_codes);
    if (signature_algos.size() > 0) {
        ja4_c += delimiter_val;
        ja4_c += FINGERPRINT::vector_of_count_to_str_cpp(signature_algos);
    }

    std::string ja4_o = ja4_a + delimiter_val +
                        b_hash(ja4_b) + delimiter_val + c_hash(ja4_c);
    ja4_return_value->Assign(2, zeek::make_intrusive<zeek::StringVal>(ja4_o));

    // ja4_ro
    std::string ro = ja4_a + delimiter_val +
                    FINGERPRINT::vector_of_count_to_str_cpp(ja4_b) + delimiter_val + ja4_c;

    ja4_return_value->Assign(4, zeek::make_intrusive<zeek::StringVal>(ro));

    return ja4_return_value;
}