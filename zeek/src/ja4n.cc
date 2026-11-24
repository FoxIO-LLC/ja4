// JA4N (NTP) fingerprinting. Part of JA4+, FoxIO License 1.1.
//
// Format:
//   (mode)(version)-(leap)-(stratum)-(poll)-(precision)-(rootdelay)(rootdisp)_
//   (ref)(org)(rec)(xmt)_(refid)_(poll seconds)
//
//   e.g. c4-0-1-6-17-02_1111_ipv4_64
//
// This follows the JA4N reference implementation in arkime/ja4 (ja4plus.c).

#include "ja4n.h"

#include <algorithm>
#include <array>

namespace FINGERPRINT::JA4N {

namespace {

// Seconds between the NTP epoch (1900) and the Unix epoch (1970).
constexpr int64_t NTP_UNIX_OFFSET = 2208988800LL;

// A timestamp within this many seconds of capture time counts as recent.
constexpr int64_t RECENT_SECS = 30LL * 24 * 3600;

// Indexed by the 3-bit NTP mode.
constexpr char MODE_CODES[] = "0apcsbn7";

constexpr char HEX_DIGITS[] = "0123456789abcdef";

uint32_t read_u32(const uint8_t* p) noexcept {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

uint64_t read_u64(const uint8_t* p) noexcept { return (uint64_t(read_u32(p)) << 32) | read_u32(p + 4); }

// Root delay and root dispersion are 16.16 fixed point, bucketed as zero,
// exactly one second, or anything else.
char root_code(uint32_t val) noexcept {
    if ( val == 0 )
        return '0';
    if ( val == 0x00010000 )
        return '1';
    return '2';
}

// '0' when unset (all 64 bits zero), '1' when the seconds part is within
// RECENT_SECS of now, otherwise '2'. Only the seconds part is compared, and
// it is not era-adjusted.
char timestamp_code(uint64_t ts, int64_t now) noexcept {
    if ( ts == 0 )
        return '0';

    // The seconds part is below 2^32 and fingerprint() clamps now to
    // +/-2^62, so neither subtraction can overflow.
    int64_t diff = (int64_t(ts >> 32) - NTP_UNIX_OFFSET) - now;
    if ( diff < 0 )
        diff = -diff;
    return diff <= RECENT_SECS ? '1' : '2';
}

bool is_print(uint8_t c) noexcept { return c >= 0x20 && c <= 0x7e; }

// How the reference id is interpreted depends only on the stratum (RFC 5905
// section 7.3): stratum 0 carries a kiss code, stratum 1 a clock source name,
// and higher strata an upstream server identifier. For IPv6 peers that
// identifier is a hash prefix that cannot be told apart from an IPv4 address,
// so for stratum 2+ only the connection's address family is reported.
void append_refid(std::string& out, const uint8_t* refid, uint8_t stratum, bool is_v6) {
    if ( stratum > 1 ) {
        out += is_v6 ? "ipv6" : "ipv4";
        return;
    }

    int printable = 0;
    int nulls = 0;
    for ( int i = 0; i < 4; i++ ) {
        if ( is_print(refid[i]) )
            printable++;
        else if ( refid[i] == 0 )
            nulls++;
    }

    if ( printable == 4 ) {
        out.append(reinterpret_cast<const char*>(refid), 4);
    }
    else if ( printable == 3 && nulls == 1 ) {
        for ( int i = 0; i < 4; i++ )
            out += refid[i] ? char(refid[i]) : '0';
    }
    else {
        // Hex of the first two bytes keeps the section four characters wide;
        // an all-zero id therefore becomes "0000".
        for ( int i = 0; i < 2; i++ ) {
            out += HEX_DIGITS[refid[i] >> 4];
            out += HEX_DIGITS[refid[i] & 0x0f];
        }
    }
}

} // namespace

std::string poll_seconds(int8_t poll) {
    // Little-endian decimal digits. 5^128 has 90 digits and 2^127 has 39.
    std::array<uint8_t, 96> digits{};
    size_t len = 1;
    digits[0] = 1;

    const int exponent = poll < 0 ? -int(poll) : int(poll);
    const int factor = poll < 0 ? 5 : 2;

    // For n > 0, 2^-n = 5^n / 10^n: the digits of 5^n, left-padded with zeros
    // to n fractional digits, after a leading "0".
    for ( int i = 0; i < exponent; i++ ) {
        int carry = 0;
        for ( size_t d = 0; d < len; d++ ) {
            const int v = digits[d] * factor + carry;
            digits[d] = uint8_t(v % 10);
            carry = v / 10;
        }
        while ( carry && len < digits.size() ) {
            digits[len++] = uint8_t(carry % 10);
            carry /= 10;
        }
    }

    std::string out;
    out.reserve(size_t(exponent) + 2);

    if ( poll < 0 ) {
        out += '0';
        for ( size_t i = len; i < size_t(exponent); i++ )
            out += '0';
    }

    for ( size_t i = len; i > 0; i-- )
        out += char('0' + digits[i - 1]);

    return out;
}

bool classify(const uint8_t* data, size_t len) noexcept {
    if ( ! data || len < HEADER_LEN )
        return false;

    if ( data[1] > 16 ) // stratum
        return false;

    const uint8_t version = (data[0] >> 3) & 0x07;
    const uint8_t mode = data[0] & 0x07;

    return version >= 1 && version <= 4 && mode != 0;
}

std::string fingerprint(const uint8_t* data, size_t len, bool is_v6, int64_t now) {
    if ( ! data || len < HEADER_LEN )
        return {};

    // Real capture times are nowhere near this; clamping only keeps the
    // timestamp arithmetic free of signed overflow for arbitrary callers.
    constexpr int64_t NOW_LIMIT = int64_t(1) << 62;
    now = std::clamp(now, -NOW_LIMIT, NOW_LIMIT);

    const uint8_t flags = data[0];
    const uint8_t stratum = data[1];
    const auto poll = int8_t(data[2]); // log2 seconds, signed (RFC 5905)
    const uint8_t precision = data[3];
    const uint32_t root_delay = read_u32(data + 4);
    const uint32_t root_disp = read_u32(data + 8);
    const uint8_t* refid = data + 12;
    const uint64_t ref_ts = read_u64(data + 16);
    const uint64_t org_ts = read_u64(data + 24);
    const uint64_t rec_ts = read_u64(data + 32);
    const uint64_t xmt_ts = read_u64(data + 40);

    std::string out;
    out.reserve(48);

    // Section a: mode, version, leap, stratum code, poll, precision, root codes
    out += MODE_CODES[flags & 0x07];
    out += char('0' + ((flags >> 3) & 0x07)); // version
    out += '-';
    out += char('0' + ((flags >> 6) & 0x03)); // leap indicator
    out += '-';
    out += stratum ? '1' : '0'; // a code, not the raw stratum
    out += '-';
    out += std::to_string(int(poll));
    out += '-';
    // Precision is a signed log2 exponent; the reference prints 256 minus
    // its unsigned byte value, so -20 is 20 and 0 is 256.
    out += std::to_string(256u - precision);
    out += '-';
    out += root_code(root_delay);
    out += root_code(root_disp);

    // Section b: reference, origin, receive and transmit timestamp codes
    out += '_';
    out += timestamp_code(ref_ts, now);
    out += timestamp_code(org_ts, now);
    out += timestamp_code(rec_ts, now);
    out += timestamp_code(xmt_ts, now);

    // Section c: reference id
    out += '_';
    append_refid(out, refid, stratum, is_v6);

    // Section d: poll interval in seconds
    out += '_';
    out += poll_seconds(poll);

    return out;
}

} // namespace FINGERPRINT::JA4N
