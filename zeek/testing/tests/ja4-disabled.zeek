# @TEST-EXEC: zeek -e 'redef FINGERPRINT::JA4_enabled = F;' -C -r $TRACES/tls-handshake.pcapng %INPUT
# @TEST-EXEC: zeek-cut ja4 < ssl.log | sort > output
# @TEST-EXEC: btest-diff output
