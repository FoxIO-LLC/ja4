# The ja4n field in JSON ntp.log output, paired with each record's uid.
#
# @TEST-EXEC: zeek -C -r $TRACES/gre-sample.pcap %INPUT LogAscii::use_json=T
# @TEST-EXEC: grep -oE '"(uid|ja4n)":"[^"]*"' ntp.log | paste - - > output
# @TEST-EXEC: btest-diff output
