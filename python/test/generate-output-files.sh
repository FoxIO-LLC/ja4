#!/bin/bash

# This script generates output files for the JA4 Python tests.
# Run the script from its directory.

PCAP_DIR="../../pcap"
OUT_DIR="./testdata"
JA4_SCRIPT="../ja4.py"

mkdir -p "$OUT_DIR"

# If arguments are given, use them as files; otherwise, use all files in $PCAP_DIR
if [ "$#" -gt 0 ]; then
    PCAP_FILES=("$@")
else
    PCAP_FILES=("$PCAP_DIR"/*.pcap*)
fi

# Loop through each pcap file and generate the output
for pcap in "${PCAP_FILES[@]}"; do
    base=$(basename "$pcap")
    out="$OUT_DIR/${base}.json"
    python3 "$JA4_SCRIPT" "$pcap" -J -r -o -f "$out"
done
