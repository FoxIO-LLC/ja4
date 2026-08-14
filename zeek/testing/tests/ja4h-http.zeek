# @TEST-EXEC: zeek -C -r $TRACES/http1-with-cookies.pcapng %INPUT
# @TEST-EXEC: zeek-cut ja4h < http.log | sort > output
# @TEST-EXEC: btest-diff output
