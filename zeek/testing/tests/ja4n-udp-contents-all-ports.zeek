# Another script asking for every UDP payload must not change JA4N: payloads
# on other ports are still ignored.
#
# @TEST-EXEC: zeek -C -r $TRACES/ja4n-synthetic.pcap && %DIR/../scripts/ja4n-messages < ntp.log > reference
# @TEST-EXEC: zeek -C -r $TRACES/ja4n-synthetic.pcap %INPUT && %DIR/../scripts/ja4n-messages < ntp.log > actual
# @TEST-EXEC: diff -u reference actual

redef udp_content_deliver_all_orig = T;
redef udp_content_deliver_all_resp = T;

event udp_contents(u: connection, is_orig: bool, contents: string) { }
