# @TEST-EXEC: zeek -C -r $TRACES/gre-sample.pcap %INPUT LogAscii::use_json=T
# @TEST-EXEC: cp ja4n.log output
# @TEST-EXEC: btest-diff output
