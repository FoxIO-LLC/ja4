# JA4N against the Arkime golden values for this pcap. gre-sample.pcap is
# byte-identical to arkime/arkime tests/pcap/gre-sample.pcap; the expected
# lines below are the "ntp.ja4n" values in arkime/ja4 pcap/gre-sample.test
# (commit 27099fb11f351f35d69f4ce366374aa91536af04), not output of this plugin.
#
# @TEST-EXEC: zeek -C -r $TRACES/gre-sample.pcap %INPUT
# @TEST-EXEC: %DIR/../scripts/ja4n-normalize < ja4n.log > actual
# @TEST-EXEC: diff -u arkime-golden actual
# @TEST-EXEC: cp ja4n.log output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE arkime-golden
129.170.17.4:123	66.59.111.190:123	c4-0-1-6-17-02_1111_ipv4_64
129.170.17.4:123	66.59.111.190:123	s4-0-1-6-11-22_1111_ipv4_64
18.26.4.105:123	66.59.111.190:123	c4-0-1-6-17-02_1111_ipv4_64
18.26.4.105:123	66.59.111.190:123	s4-0-1-6-18-22_1111_ipv4_64
66.59.111.182:123	66.59.111.190:123	c4-0-1-6-17-02_1111_ipv4_64
66.59.111.182:123	66.59.111.190:123	s4-0-1-6-17-22_1111_ipv4_64
@TEST-END-FILE
