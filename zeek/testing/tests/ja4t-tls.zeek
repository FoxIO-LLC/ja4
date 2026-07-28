# @TEST-EXEC: zeek -C -r $TRACES/latest.pcapng %INPUT
# @TEST-EXEC: zeek-cut ja4t ja4ts < conn.log | sort > output
# @TEST-EXEC: btest-diff output
