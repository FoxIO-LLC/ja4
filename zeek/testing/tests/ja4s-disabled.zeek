# @TEST-EXEC: zeek -e 'redef FINGERPRINT::JA4S_enabled = F;' -C -r $TRACES/tls-handshake.pcapng %INPUT
# @TEST-EXEC: zeek-cut ja4s < ssl.log | sort > output
# @TEST-EXEC: btest-diff output
