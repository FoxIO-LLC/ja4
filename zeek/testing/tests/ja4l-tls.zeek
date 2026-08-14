# @TEST-EXEC: zeek -C -r $TRACES/latest.pcapng %INPUT
# @TEST-EXEC: zeek-cut ja4l ja4ls < conn.log | sort > output
# @TEST-EXEC: btest-diff output
