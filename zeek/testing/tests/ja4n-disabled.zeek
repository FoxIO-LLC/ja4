# @TEST-EXEC: zeek -C -r $TRACES/ja4n-synthetic.pcap %INPUT
# @TEST-EXEC: test ! -f ja4n.log

redef FINGERPRINT::JA4N_enabled = F;
