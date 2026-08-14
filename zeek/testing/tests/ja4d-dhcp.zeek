# @TEST-EXEC: zeek -C -r $TRACES/dhcp.pcapng %INPUT
# @TEST-EXEC: zeek-cut ja4d < ja4d.log | sort > output
# @TEST-EXEC: btest-diff output
