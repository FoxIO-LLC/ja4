# @TEST-EXEC: zeek -C -r ${TRACES}/ipv6.pcapng ../../../__load__.zeek %INPUT
# @TEST-EXEC: btest-diff conn.log
