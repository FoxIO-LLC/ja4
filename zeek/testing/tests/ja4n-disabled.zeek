# With JA4N disabled the ja4n column is still in ntp.log but never set.
#
# @TEST-EXEC: zeek -C -r $TRACES/ja4n-synthetic.pcap %INPUT
# @TEST-EXEC: test ! -f ja4n.log
# @TEST-EXEC: zeek-cut ja4n < ntp.log | sort -u > output
# @TEST-EXEC: btest-diff output

redef FINGERPRINT::JA4N_enabled = F;
