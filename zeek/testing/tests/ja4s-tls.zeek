# @TEST-EXEC: zeek -C -r $TRACES/tls-handshake.pcapng %INPUT
# @TEST-EXEC: zeek-cut ja4s < ssl.log | sort > output
# @TEST-EXEC: btest-diff output
