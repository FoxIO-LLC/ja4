import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import cache_update, epoch_diff  # noqa: E402
from ja4 import first_last_alpn, hops, to_ja4s  # noqa: E402
from ja4h import to_ja4h  # noqa: E402
from ja4x import to_ja4x  # noqa: E402


def test_epoch_diff_spans_seconds():
    t1 = "2020-01-17T20:43:36.000000Z"
    t2 = "2020-01-17T20:43:37.250000Z"
    # 1.25 s of round-trip time -> 625000 microseconds one-way
    assert epoch_diff(t1, t2) == 625000


def test_epoch_diff_sub_second_precision():
    t1 = "2020-01-17T20:43:36.000000Z"
    t2 = "2020-01-17T20:43:36.000500Z"
    assert epoch_diff(t1, t2) == 250


def test_hops_uses_the_regular_initial_ttl_ladder():
    assert hops(64) == 0
    assert hops(60) == 4
    assert hops(128) == 0
    assert hops(120) == 8
    assert hops(200) == 55


def _ja4h_referer_flag(headers):
    x = {
        "hl": "http",
        "stream": "9",
        "method": "GET",
        "headers": ["GET / HTTP/1.1"] + headers,
    }
    result = to_ja4h(x, debug_stream=-1)
    # JA4H layout: method(2) version(2) cookie(1) referer(1) ...
    return result["JA4H"][5]


def test_ja4h_referer_flag_requires_exact_header():
    assert _ja4h_referer_flag(["Referer: https://example.com/"]) == "r"


def test_ja4h_referer_flag_ignores_lookalike_headers():
    assert _ja4h_referer_flag(["X-Referer: https://example.com/"]) == "n"


def test_first_last_alpn_matches_the_rust_implementation():
    assert first_last_alpn("h2") == "h2"
    assert first_last_alpn("http/1.1") == "h1"
    assert first_last_alpn("x") == "x0"
    # a non-ascii character becomes '9', per character
    assert first_last_alpn("\u00e9x") == "9x"
    assert first_last_alpn("x\u00e9") == "x9"
    # an empty ALPN value behaves like a missing one
    assert first_last_alpn("") == "00"
    assert first_last_alpn(None) == "00"
    # several offered protocols: the first one counts
    assert first_last_alpn(["h2", "h3"]) == "h2"


def test_to_ja4s_survives_an_empty_alpn_value():
    x = {
        "hl": "tls",
        "stream": 7,
        "quic": False,
        "version": "0x0303",
        "ciphers": ["0x1301"],
        "extensions": ["0x0016"],
        "alpn_list": "",
    }
    cache_update(x, "stream", 7, -1)
    to_ja4s(x, debug_stream=-1)
    # JA4S layout: transport(1) version(2) extension count(2) alpn(2)
    assert x["JA4S"][5:7] == "00"


def _ja4x_input(extension_lengths, nr_oids):
    return {
        "hl": "x509af",
        "stream": 3,
        "extension_lengths": extension_lengths,
        "cert_extensions": [f"2.5.29.{i}" for i in range(10, 10 + nr_oids)],
        "issuer_sequence": ["1"],
        "subject_sequence": ["1"],
        "rdn_oids": ["2.5.4.3", "2.5.4.3"],
    }


def test_to_ja4x_two_digit_count_is_one_certificate():
    # tshark reports a lone certificate's counts as plain strings
    x = _ja4x_input("10", nr_oids=10)
    cache_update(x, "stream", 3, -1)
    to_ja4x(x, debug_stream=-1)
    assert "JA4X.1" in x
    assert "JA4X.2" not in x


def test_to_ja4x_string_and_list_counts_agree():
    as_string = _ja4x_input("3", nr_oids=3)
    as_list = _ja4x_input(["3"], nr_oids=3)
    cache_update(as_string, "stream", 4, -1)
    cache_update(as_list, "stream", 5, -1)
    to_ja4x(as_string, debug_stream=-1)
    to_ja4x(as_list, debug_stream=-1)
    assert as_string["JA4X.1"] == as_list["JA4X.1"]
