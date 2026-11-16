# Flow 10.1.0.68 carries three distinct client fingerprints (poll 6, 7, 8);
# with a cap of two only the first two are logged.
#
# @TEST-EXEC: zeek -C -r $TRACES/ja4n-synthetic.pcap %INPUT
# @TEST-EXEC: %DIR/../scripts/ja4n-normalize < ja4n.log | grep '^10\.1\.0\.68:' > output
# @TEST-EXEC: btest-diff output

redef FINGERPRINT::JA4N::max_fingerprints_per_conn = 2;
