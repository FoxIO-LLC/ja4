# `ja4x`

`ja4x` CLI utility reads X.509 certificate files, DER or PEM encoded, and prints JA4X fingerprints, Issuer, and Subject information.

## Usage

```
Print JA4X fingerprints of X.509 certificates

Usage: ja4x [OPTIONS] [CERTS]...

Arguments:
  [CERTS]...  X.509 certificate(s)

Options:
  -j, --json      JSON output (default is YAML)
  -r, --with-raw  Include raw (unhashed) fingerprints in the output
  -h, --help      Print help
  -V, --version   Print version
```

## Sample output

```
path: sample.pem
ja4x: a373a9f83c6b_2bab15409345_7bf9a7bf7029
issuerCountryName: US
issuerOrganizationName: DigiCert Inc
issuerCommonName: DigiCert TLS RSA SHA256 2020 CA1
subjectCountryName: US
subjectStateOrProvinceName: California
subjectLocalityName: San Francisco
subjectOrganizationName: Cisco OpenDNS LLC
subjectCommonName: api.opendns.com
```
