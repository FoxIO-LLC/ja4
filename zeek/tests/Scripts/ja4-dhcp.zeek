# @TEST-EXEC: zeek -C -r ${TRACES}/dhcp.pcapng ../../../__load__.zeek %INPUT
# @TEST-EXEC: btest-diff ja4d.log
