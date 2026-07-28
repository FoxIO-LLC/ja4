# @TEST-EXEC: zeek -e 'redef FINGERPRINT::JA4SSH_enabled = F;' -C -r $TRACES/ssh2.pcapng %INPUT
# @TEST-EXEC: test ! -f ja4ssh.log
