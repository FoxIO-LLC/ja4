import subprocess
import pytest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent # Directory of this script
ROOT_DIR = SCRIPT_DIR.parent.parent # Root directory of the project

PCAP_DIR = ROOT_DIR / "pcap" # Directory containing PCAP files
EXPECTED_DIR = SCRIPT_DIR / "testdata" # Directory containing expected output files

pcap_files = sorted(PCAP_DIR.rglob("*.pcap*"))
if not pcap_files:
    pytest.fail(f"No PCAP files found in {PCAP_DIR.resolve()}")

def get_expected_output(pcap_file):
    expected_file = EXPECTED_DIR / (pcap_file.name + ".json")
    with expected_file.open() as f:
        return [line.strip() for line in f.readlines()]


def _tshark_has_brotli() -> bool:
    result = subprocess.run(
        ["tshark", "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    return "+brotli" in result.stdout


TSHARK_HAS_BROTLI = _tshark_has_brotli()

# Captures with brotli-compressed certificates (RFC 8879). Their expected
# output includes JA4X, which needs a tshark built with brotli.
BROTLI_CERT_PCAP = "chrome-cloudflare-quic-with-secrets.pcapng"

# Run tshark on each PCAP file and compare the output to the expected output
@pytest.mark.parametrize("pcap_file", pcap_files)
def test_tshark_output_matches_expected(pcap_file):
    if pcap_file.name == BROTLI_CERT_PCAP and not TSHARK_HAS_BROTLI:
        pytest.skip("tshark lacks brotli; covered by the no-brotli test")
    result = subprocess.run(
        [
            "tshark",
            "-r", str(pcap_file),
            "-Y", "ja4",
            "-T", "json",
            "-e", "frame.number",
            "-e", "ja4.ja4s_r",
            "-e", "ja4.ja4s",
            "-e", "ja4.ja4x_r",
            "-e", "ja4.ja4x",
            "-e", "ja4.ja4h",
            "-e", "ja4.ja4h_r",
            "-e", "ja4.ja4h_ro",
            "-e", "ja4.ja4l",
            "-e", "ja4.ja4l_delta",
            "-e", "ja4.ja4ls",
            "-e", "ja4.ja4ls_delta",
            "-e", "ja4.ja4ssh",
            "-e", "ja4.ja4t",
            "-e", "ja4.ja4ts",
            "-e", "ja4.ja4d"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 0, f"tshark failed: {result.stderr}"

    actual_lines = [line.strip() for line in result.stdout.strip().splitlines()]
    expected_lines = get_expected_output(pcap_file)

    assert actual_lines == expected_lines, f"Mismatch for {pcap_file.name}"


@pytest.mark.skipif(TSHARK_HAS_BROTLI, reason="needs a tshark built without brotli")
def test_compressed_certificate_without_brotli() -> None:
    """Undecompressable certificates yield no JA4X; the rest still works."""
    result = subprocess.run(
        [
            "tshark",
            "-r", str(PCAP_DIR / BROTLI_CERT_PCAP),
            "-Y", "ja4.ja4s || tls.handshake.type == 25",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "ja4.ja4s",
            "-e", "ja4.ja4x",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 0, f"tshark failed: {result.stderr}"
    rows = [line.split("\t") for line in result.stdout.splitlines()]
    assert rows == [
        ["6", "t130200_1301_234ea6891581", ""],
        ["8", "", ""],
        ["49", "q130200_1301_234ea6891581", ""],
        ["51", "", ""],
    ]


# Regression for FoxIO #269 / Wireshark #20600:
# JA4+ leaf fields must be available to custom columns and -T fields
# even when the ja4 protocol itself is not referenced.
COLUMN_CASES = [
    # (pcap, ja4 field, expected value on the first matching frame)
    ("tls-alpn-h2.pcap",     "ja4.ja4s", "t1204h2_cca9_1428ce7b4018"),
    ("tls-alpn-h2.pcap",     "ja4.ja4t", "65535_2-1-3-1-1-8-4-0-0_1346_6"),
    ("CVE-2018-6794.pcap",   "ja4.ja4t", "8192_2-1-3-1-1-4_1460_8"),
    ("http1-with-cookies.pcapng", "ja4.ja4h",
     "ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442"),
]


def _first_nonempty(lines):
    for line in lines:
        line = line.strip()
        if line:
            return line
    return ""


@pytest.mark.parametrize("pcap_name,field,expected", COLUMN_CASES)
def test_ja4_custom_column_is_populated(pcap_name, field, expected):
    """JA4+ custom columns must work without -Y ja4."""
    pcap_file = PCAP_DIR / pcap_name
    col_fmt = f'gui.column.format:"No.","%m","JA4","%Cus:{field}:0:R"'
    result = subprocess.run(
        ["tshark", "-r", str(pcap_file), "-o", col_fmt],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert result.returncode == 0, f"tshark failed: {result.stderr}"
    assert expected in result.stdout, (
        f"{field} missing from custom column for {pcap_name}.\n"
        f"Output:\n{result.stdout}"
    )


@pytest.mark.parametrize("pcap_name,field,expected", COLUMN_CASES)
def test_ja4_fields_extraction_without_protocol_filter(pcap_name, field, expected):
    """-T fields must extract JA4+ leaf fields without -Y ja4."""
    pcap_file = PCAP_DIR / pcap_name
    result = subprocess.run(
        ["tshark", "-r", str(pcap_file), "-T", "fields", "-e", field],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert result.returncode == 0, f"tshark failed: {result.stderr}"
    assert _first_nonempty(result.stdout.splitlines()) == expected, (
        f"{field} extraction wrong for {pcap_name}.\n"
        f"Output:\n{result.stdout}"
    )


def test_ja4s_alpn_encoding():
    tls_alpn_codes = [
        "00",  # empty list
        "00",  # empty first value, then h2
        "hh",  # h
        "h1",  # http/1.1, then h2
        "20",  # 20
        "ab",  # ab
        "60",  # 61 20
        "21",  # 20 61
        "3b",  # 30 ab
        "01",  # 30 ab cd 31
        "hz",  # 68 00 7a
        "08",  # 00 68
        "60",  # 68 00
        "ab",  # ab, then h2
        "ad",  # ab cd
        "3d",  # 30 31 ab cd
    ]
    expected = [("t120000_002f_000000000000", "t120000_002f_")]  # absent extension
    expected.extend(
        (f"t1201{code}_002f_0b08e3dcc50f", f"t1201{code}_002f_0010")
        for code in tls_alpn_codes
    )
    expected.append(("dd201ad_002f_0b08e3dcc50f", "dd201ad_002f_0010"))  # DTLS 1.2, ab cd

    result = subprocess.run(
        [
            "tshark", "-r", str(EXPECTED_DIR / "ja4s-alpn.pcap"),
            "-d", "udp.port==4433,dtls", "-T", "fields",
            "-e", "ja4.ja4s", "-e", "ja4.ja4s_r",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, f"tshark failed: {result.stderr}"
    actual = [tuple(line.split("\t")) for line in result.stdout.splitlines()]
    assert actual == expected
