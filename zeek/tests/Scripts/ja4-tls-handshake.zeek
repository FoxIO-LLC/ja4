# @TEST-EXEC: zeek -C -r ${TRACES}/tls-handshake.pcapng ../../../__load__.zeek %INPUT
# @TEST-EXEC: btest-diff ssl.log
