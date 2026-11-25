# Flow 10.1.0.68 sends five client messages with poll 6, 7, 8, 7, 6. Each
# ntp.log record carries the fingerprint of its own message, so a value seen
# earlier in the connection shows up again on every message that produces it.
#
# @TEST-EXEC: zeek -C -r $TRACES/ja4n-synthetic.pcap %INPUT
# @TEST-EXEC: zeek-cut id.orig_h id.resp_h mode ja4n < ntp.log | awk -F'\t' '$1 == "10.1.0.68" || $2 == "10.1.0.68"' > output
# @TEST-EXEC: btest-diff output
