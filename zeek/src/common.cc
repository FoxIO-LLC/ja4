
#include <cstring>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include "zeek/util.h"
#include "zeek/net_util.h"
#include "zeek/ZeekString.h"
#include "zeek/Val.h"
#include "zeek/Desc.h"
#include <openssl/evp.h>

namespace FINGERPRINT {

    std::string vector_of_count_to_str_cpp(const std::vector<uint32_t>& input, 
                                           const std::string& format_str = "%04x", 
                                           const std::string& dlimit = ",") {
        std::ostringstream output;

        for (size_t i = 0; i < input.size(); ++i) {
            char buffer[64];
            std::snprintf(buffer, sizeof(buffer), format_str.c_str(), input[i]);
            output << buffer;
            if (i < input.size() - 1) {
                output << dlimit;
            }
        }

        return output.str();
    }

    std::string vector_of_str_to_str_cpp(const std::vector<std::string>& input, 
                                         const std::string& format_str = "%s", 
                                         const std::string& dlimit = ",") {
        std::ostringstream output;

        for (size_t i = 0; i < input.size(); ++i) {
            char buffer[1024];
            std::snprintf(buffer, sizeof(buffer), format_str.c_str(), input[i].c_str());
            output << buffer;
            if (i < input.size() - 1) {
                output << dlimit;
            }
        }

        return output.str();
    }

    // Returns a sorted version of the input vector based on ascending order
    std::vector<uint32_t> order_vector_of_count_cpp(const std::vector<uint32_t>& input) {
        // Create a vector of indices: [0, 1, 2, ..., N-1]
        std::vector<size_t> ordering(input.size());
        for (size_t i = 0; i < input.size(); ++i) {
            ordering[i] = i;
        }

        // Sort indices based on the values in 'input'
        std::sort(ordering.begin(), ordering.end(),
                    [&input](size_t a, size_t b) {
                        return input[a] < input[b];
                    });

        // Create the output vector using sorted indices
        std::vector<uint32_t> outvec;
        outvec.reserve(input.size());
        for (size_t idx : ordering) {
            outvec.push_back(input[idx]);
        }

        return outvec;
    }

    uint32_t make_quadword_cpp(uint8_t byte1, uint8_t byte2) {
        // Create lookup table for hex digit to value
        std::unordered_map<char, uint8_t> hex_map = {
            {'0', 0}, {'1', 1}, {'2', 2}, {'3', 3},
            {'4', 4}, {'5', 5}, {'6', 6}, {'7', 7},
            {'8', 8}, {'9', 9}, {'a', 10}, {'b', 11},
            {'c', 12}, {'d', 13}, {'e', 14}, {'f', 15}
        };

        // Convert byte1 and byte2 to two-digit lowercase hex strings
        std::ostringstream ss1, ss2;
        ss1 << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte1);
        ss2 << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte2);
        std::string b1 = ss1.str();
        std::string b2 = ss2.str();

        // Ensure lowercase
        for (char& c : b1) c = std::tolower(c);
        for (char& c : b2) c = std::tolower(c);

        // Validate hex digits
        if (hex_map.find(b1[0]) == hex_map.end() || hex_map.find(b1[1]) == hex_map.end() ||
            hex_map.find(b2[0]) == hex_map.end() || hex_map.find(b2[1]) == hex_map.end()) {
            throw std::invalid_argument("Invalid hex digit");
        }

        // Calculate total value
        uint32_t byte1_total = (hex_map[b1[0]] * 16 * 16 * 16) + (hex_map[b1[1]] * 16 * 16);
        uint32_t byte2_total = (hex_map[b2[0]] * 16) + (hex_map[b2[1]]);
        
        return byte1_total + byte2_total;
    }

    std::string sha256_or_null__12_cpp(std::string input){
        if (input == "") {
            return "000000000000";
        }

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;
        
        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mdctx, input.data(), input.length());
        EVP_DigestFinal_ex(mdctx, hash, &hash_len);
        EVP_MD_CTX_free(mdctx);
       
        // Convert hash to hex
        std::ostringstream hex_stream;
        for (unsigned int i = 0; i < hash_len && i < 6; ++i) {  // 6 bytes = 12 hex characters
            hex_stream << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }

        return hex_stream.str();  // First 12 hex characters
    }

    std::string table_to_json_string_cpp(const zeek::TableVal* table){
        zeek::ODesc d;
        
        table->Describe(&d);
    
        return d.Description();
    }
    
    std::vector<std::string> convert_string_vector_cpp(const zeek::IntrusivePtr<zeek::VectorVal>& vec_val) {
        std::vector<std::string> result;
        if ( ! vec_val )
            return result;
    
        unsigned int length = vec_val->Size();
        result.reserve(length);
    
        for ( int i = 0; i < length; ++i )
        {
            zeek::IntrusivePtr<zeek::Val> element_val = vec_val->ValAt(i);
            if ( ! element_val )
                continue;
    
            zeek::IntrusivePtr<zeek::StringVal> str_val = cast_intrusive<zeek::StringVal>(element_val);
    
            if ( ! str_val )
                continue;
    
            result.push_back(str_val->ToStdString());
        }
    
        return result;
    }
    
    
    std::vector<uint32_t> convert_count_vector_to_u32_cpp(const zeek::IntrusivePtr<zeek::VectorVal>& vec_val){
        std::vector<uint32_t> result;
        if ( ! vec_val )
            return result;
    
        unsigned int length = vec_val->Size();
        result.reserve(length);
    
        for ( int i = 0; i < length; ++i )
        {
            zeek::IntrusivePtr<zeek::Val> element_val = vec_val->ValAt(i);
    
            if ( ! element_val )
                continue;
    
            zeek::IntrusivePtr<zeek::IntVal> int_val = cast_intrusive<zeek::IntVal>(element_val);
    
            if ( ! int_val )
                continue;
    
            uint64_t full_value = int_val->AsCount();
    
            // Optional safety check to avoid overflow
            if ( full_value > UINT32_MAX ) {
                fprintf(stderr, "Warning: count %llu too large for uint32_t\n",
                        static_cast<unsigned long long>(full_value));
                continue;
            }
    
            result.push_back(static_cast<uint32_t>(full_value));
        }
    
        return result;
    }
}