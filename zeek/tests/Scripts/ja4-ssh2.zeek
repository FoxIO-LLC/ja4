# @TEST-EXEC: zeek -C -r ${TRACES}/ssh2.pcapng ../../../__load__.zeek %INPUT
# @TEST-EXEC: btest-diff ja4ssh.log
