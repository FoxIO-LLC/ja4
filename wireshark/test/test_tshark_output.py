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

# Run tshark on each PCAP file and compare the output to the expected output
@pytest.mark.parametrize("pcap_file", pcap_files)
def test_tshark_output_matches_expected(pcap_file):
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
