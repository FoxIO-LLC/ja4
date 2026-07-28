# @TEST-EXEC: zeek -NN FINGERPRINT::JA4 |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
