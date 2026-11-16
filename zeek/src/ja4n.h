#pragma once

// JA4N (NTP) fingerprinting.
//
// JA4N is part of JA4+ and is licensed under the FoxIO License 1.1, not BSD.
// See ../../LICENSE and ../../License FAQ.md.
//
// The functions in this header deliberately have no Zeek dependencies so the
// algorithm can be compiled and differentially tested on its own.

#include <cstddef>
#include <cstdint>
#include <string>

namespace FINGERPRINT::JA4N {

// Fixed-length NTP header (RFC 5905 section 7.3). Shorter payloads, such as
// mode 6/7 control packets, have no fingerprintable fields.
inline constexpr size_t HEADER_LEN = 48;

// Returns true when a payload looks enough like NTP for a connection to be
// fingerprinted: at least a full header, stratum <= 16, version 1-4 and a
// non-zero mode. The reference applies this only to the first non-empty
// payload of each direction, never to every packet.
bool classify(const uint8_t* data, size_t len) noexcept;

// Returns the JA4N fingerprint for one NTP payload, or an empty string when
// the payload is shorter than HEADER_LEN. Bytes past the header (extension
// fields, MACs) are ignored.
//
//   data, len  - UDP payload
//   is_v6      - whether the connection is IPv6, which decides the reference
//                id section ("ipv4"/"ipv6") for stratum >= 2
//   now        - whole Unix seconds of the connection's first packet, used to
//                classify timestamps as recent or not. Using capture time
//                rather than wall-clock time keeps fingerprints reproducible.
std::string fingerprint(const uint8_t* data, size_t len, bool is_v6, int64_t now);

// The poll section: 2^poll seconds in decimal with the decimal point removed,
// so 6 is "64", 0 is "1", -1 is "05" and -4 is "00625". Exact for all int8_t.
std::string poll_seconds(int8_t poll);

} // namespace FINGERPRINT::JA4N
