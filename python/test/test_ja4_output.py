import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent.parent

PCAP_DIR = ROOT_DIR / "pcap"
EXPECTED_DIR = SCRIPT_DIR / "testdata"
JA4_SCRIPT = ROOT_DIR / "python" / "ja4.py"

pcap_files = sorted(PCAP_DIR.rglob("*.pcap*"))
if not pcap_files:
    pytest.fail(f"No PCAP files found in {PCAP_DIR.resolve()}")


def get_expected_output(pcap_file: Path):
    expected_file = EXPECTED_DIR / f"{pcap_file.name}.json"
    with expected_file.open() as f:
        return json.load(f)


@pytest.mark.parametrize("pcap_file", pcap_files)
def test_ja4_output_matches_expected(pcap_file, tmp_path):
    output_file = tmp_path / f"{pcap_file.name}.json"
    result = subprocess.run(
        [
            sys.executable,
            str(JA4_SCRIPT),
            str(pcap_file),
            "-J",
            "-r",
            "-o",
            "-f",
            str(output_file),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 0, f"ja4.py failed: {result.stderr}"

    actual = json.loads(output_file.read_text())
    expected = get_expected_output(pcap_file)

    assert actual == expected, f"Mismatch for {pcap_file.name}"
