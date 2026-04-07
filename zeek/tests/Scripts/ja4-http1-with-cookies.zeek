# @TEST-EXEC: zeek -C -r ${TRACES}/http1-with-cookies.pcapng ../../../__load__.zeek %INPUT
# @TEST-EXEC: btest-diff http.log
