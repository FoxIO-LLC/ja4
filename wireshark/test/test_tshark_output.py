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
            "-e", "ja4.ja4ls",
            "-e", "ja4.ja4ssh",
            "-e", "ja4.ja4t",
            "-e", "ja4.ja4ts"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 0, f"tshark failed: {result.stderr}"

    actual_lines = [line.strip() for line in result.stdout.strip().splitlines()]
    expected_lines = get_expected_output(pcap_file)

    assert actual_lines == expected_lines, f"Mismatch for {pcap_file.name}"
