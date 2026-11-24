# On Zeek versions that write ntp_control.log and ntp_private.log, those
# records get the ja4n field too. Flow 10.1.0.64 is a single mode 7 message
# whose reference fingerprint is 72-0-0-3-214-00_0000_0000_8.
#
# @TEST-REQUIRES: zeek -b base/protocols/ntp -e 'event zeek_init() { if ( "NTP::PrivateInfo" !in global_ids() ) exit(1); }'
# @TEST-EXEC: zeek -C -r $TRACES/ja4n-synthetic.pcap %INPUT
# @TEST-EXEC: test ! -f ntp_control.log || grep -q '^#fields.*ja4n$' ntp_control.log
# @TEST-EXEC: zeek-cut id.orig_h id.resp_h mode ja4n < ntp_private.log | awk -F'\t' '$4 != "-"' > output
# @TEST-EXEC: btest-diff output
