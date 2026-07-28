# @TEST-EXEC: zeek -e 'redef FINGERPRINT::JA4T_enabled = F;' -C -r $TRACES/latest.pcapng %INPUT
# @TEST-EXEC: zeek-cut ja4t ja4ts < conn.log | sort > output
# @TEST-EXEC: btest-diff output
