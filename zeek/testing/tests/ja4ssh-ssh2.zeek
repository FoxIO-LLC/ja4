# @TEST-EXEC: zeek -C -r $TRACES/ssh2.pcapng %INPUT
# @TEST-EXEC: zeek-cut ja4ssh < ja4ssh.log | sort > output
# @TEST-EXEC: btest-diff output
