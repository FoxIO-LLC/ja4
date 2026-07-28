# @TEST-EXEC: zeek -e 'redef FINGERPRINT::JA4D_enabled = F;' -C -r $TRACES/dhcp.pcapng %INPUT
# @TEST-EXEC: test ! -f ja4d.log
