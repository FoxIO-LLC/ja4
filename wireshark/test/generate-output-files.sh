#!/bin/bash

# This script generates output files for the JA4 dissector tests.
# Run the script from its directory.

PCAP_DIR="../../pcap"
OUT_DIR="./testdata"
FIELDS="-Y ja4 -T json \
-e frame.number \
-e ja4.ja4s_r \
-e ja4.ja4s \
-e ja4.ja4x_r \
-e ja4.ja4x \
-e ja4.ja4h \
-e ja4.ja4h_r \
-e ja4.ja4h_ro \
-e ja4.ja4l \
-e ja4.ja4ls \
-e ja4.ja4ssh \
-e ja4.ja4t \
-e ja4.ja4ts"

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
    tshark -r "$pcap" $FIELDS > "$out"
done
