#include <string>
#include <cstdio>
#include <algorithm>
#include <vector>
#include "zeek/Val.h"
#include "zeek/ZeekString.h"

#include "common.h"
#include "ja4h.h"

using namespace FINGERPRINT;

static std::string make_a(const std::string& method,
                          const std::string& version,
                          const std::string& cookie,
                          const std::string& referer,
                          int header_count,
                          const std::string& language) {
    std::string cookie_flag = cookie.empty() ? "n" : "c";
    std::string referer_flag = referer.empty() ? "n" : "r";

    char count_buf[4];
    if (header_count > 99)
        snprintf(count_buf, sizeof(count_buf), "99");
    else
        snprintf(count_buf, sizeof(count_buf), "%02d", header_count);

    return method + version + cookie_flag + referer_flag + count_buf + language;
}

zeek::ValPtr do_ja4h(zeek::RecordVal* conn_record, zeek::StringVal* delimiter) {
    const zeek::String* zstr = delimiter->AsStringVal()->AsString();
    std::string delim(reinterpret_cast<const char*>(zstr->Bytes()), zstr->Len());

    auto fingerprint = cast_intrusive<zeek::RecordVal>(conn_record->GetField("fp"));
    auto http_client = cast_intrusive<zeek::RecordVal>(fingerprint->GetField("http_client"));

    std::string method =   cast_intrusive<zeek::StringVal>(http_client->GetField("method"))->ToStdString();
    std::string cookie =   cast_intrusive<zeek::StringVal>(http_client->GetField("cookie"))->ToStdString();
    std::string version =  cast_intrusive<zeek::StringVal>(http_client->GetField("version"))->ToStdString();
    std::string referer =  cast_intrusive<zeek::StringVal>(http_client->GetField("referer"))->ToStdString();
    std::string language = cast_intrusive<zeek::StringVal>(http_client->GetField("language"))->ToStdString();

    std::vector<std::string> header_names =   convert_string_vector_cpp(cast_intrusive<zeek::VectorVal>(http_client->GetField("header_names")));
    std::vector<std::string> header_names_o = convert_string_vector_cpp(cast_intrusive<zeek::VectorVal>(http_client->GetField("header_names_o")));
    std::vector<std::string> cookie_names =   convert_string_vector_cpp(cast_intrusive<zeek::VectorVal>(http_client->GetField("cookie_names")));
    std::vector<std::string> cookie_values =  convert_string_vector_cpp(cast_intrusive<zeek::VectorVal>(http_client->GetField("cookie_values")));

    // A section: {method}{version}{cookie_flag}{referer_flag}{header_count}{language}
    auto ja4h_a = make_a(method, version, cookie, referer, header_names.size(), language);

    // B section: header names (excluding Cookie & Referer)
    auto ja4h_b_o = vector_of_str_to_str_cpp(header_names_o);
    std::string ja4h_b_r = vector_of_str_to_str_cpp(header_names);
    auto ja4h_b = sha256_or_null__12_cpp(ja4h_b_r);
    // C section: cookie names
    auto ja4h_c_o = vector_of_str_to_str_cpp(cookie_names);
    std::sort(cookie_names.begin(), cookie_names.end());
    std::string ja4h_c_r = vector_of_str_to_str_cpp(cookie_names);
    auto ja4h_c = sha256_or_null__12_cpp(ja4h_c_r);

    // D section: cookie name=value pairs
    auto ja4h_d_o = vector_of_str_to_str_cpp(cookie_values);
    std::sort(cookie_values.begin(), cookie_values.end());
    std::string ja4h_d_r = vector_of_str_to_str_cpp(cookie_values);
    auto ja4h_d = sha256_or_null__12_cpp(ja4h_d_r);

    // Assemble the three fingerprint variants
    std::string ja4h    = ja4h_a + delim + ja4h_b   + delim + ja4h_c   + delim + ja4h_d;
    std::string ja4h_r  = ja4h_a + delim + ja4h_b_r + delim + ja4h_c_r + delim + ja4h_d_r;
    std::string ja4h_ro = ja4h_a + delim + ja4h_b_o + delim + ja4h_c_o + delim + ja4h_d_o;

    auto result_type = zeek::id::find_type<zeek::RecordType>("FINGERPRINT::JA4H::Info");
    auto result = zeek::make_intrusive<zeek::RecordVal>(result_type);
    result->Assign(1, zeek::make_intrusive<zeek::StringVal>(ja4h));
    result->Assign(2, zeek::make_intrusive<zeek::StringVal>(ja4h_r));
    result->Assign(3, zeek::make_intrusive<zeek::StringVal>(ja4h_ro));
    return result;
}
