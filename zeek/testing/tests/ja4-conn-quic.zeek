# @TEST-EXEC: zeek -C -r $TRACES/chrome-cloudflare-quic-with-secrets.pcapng %INPUT
# @TEST-EXEC: zeek-cut ja4l ja4ls ja4l_delta ja4ls_delta ja4t ja4ts < conn.log | sort > output
# @TEST-EXEC: btest-diff output
