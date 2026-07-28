#pragma once

#include <cstring>
#include <cctype>
#include <string>
#include <vector>
#include "zeek/Val.h"

namespace FINGERPRINT {
    std::string vector_of_count_to_str_cpp(const std::vector<uint32_t>& input,
        const std::string& format_str = "%04x",
        const std::string& dlimit = ",");
    std::string vector_of_str_to_str_cpp(const std::vector<std::string>& input,
        const std::string& format_str = "%s",
        const std::string& dlimit = ",");
    std::vector<uint32_t> order_vector_of_count_cpp(const std::vector<uint32_t>& input);
    uint32_t make_quadword_cpp(uint8_t byte1, uint8_t byte2);
    std::string sha256_or_null__12_cpp(std::string input);
    std::string table_to_json_string_cpp(const zeek::TableVal* table);
    std::vector<std::string> convert_string_vector_cpp(const zeek::IntrusivePtr<zeek::VectorVal>& vec_val);
    std::vector<uint32_t> convert_count_vector_to_u32_cpp(const zeek::IntrusivePtr<zeek::VectorVal>& vec_val);
}
