# @TEST-EXEC: zeek -C -r $TRACES/dtls-udp.pcap %INPUT
# @TEST-EXEC: zeek-cut ja4 ja4s < ssl.log | sort > output
# @TEST-EXEC: btest-diff output
