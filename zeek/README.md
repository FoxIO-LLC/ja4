# JA4+ for Zeek <!-- omit from toc -->

A compiled Zeek plugin implementing JA4+ network fingerprinting. Replaces the pure-script implementation with C++ BiF functions for performance-critical fingerprints.

JA4SSH will output to its own log.

C++ accelerated (BiF):

JA4 &rarr; `ssl.log`
JA4S &rarr; `ssl.log`
JA4H &rarr; `http.log`
JA4SSH &rarr; `ja4ssh.log`
JA4T &rarr; `conn.log` (raw packet parsing)

Pure script (bundled):

JA4L &rarr; `conn.log`
JA4LS &rarr; `conn.log`
JA4TS &rarr; `conn.log`
JA4D &rarr; `ja4d.log`
JA4D6 &rarr; `ja4d.log` (awaiting Zeek DHCPv6 suppport)
JA4X &rarr; `x509.log` (awaiting Zeek object support)

See [JA4+ and implementations into other open source tools](../README.md) for more detail on JA4+ and implementations into other open source tools.

## Table of Contents <!-- omit from toc -->

- [Install](#install)
- [Requirements](#requirements)
- [Usage](#usage)
- [Config](#config)
- [Tests](#tests)
- [Creating a Release](#creating-a-release)
- [License](#license)

## Install

Run the following command on your Zeek nodes:

```sh
zkg install zeek/foxio/ja4
```

## Requirements

Zeek 7.0+ is required (tested with 8.0.6).
C++20 compiler (Clang 19+ or GCC 12+).
CMake 3.15+.

## Usage

```sh
# Plugin auto-loads JA4/JA4S/JA4H/JA4SSH/JA4T/JA4L/JA4D
zeek -C -r trace.pcap
```

Fingerprint fields are added to `ssl.log`, `conn.log`, and `http.log`, plus dedicated `ja4ssh.log` / `ja4d.log` streams.

## Config

Individual JA4+ methods (`JA4_enabled`, `JA4S_enabled`, `JA4H_enabled`, `JA4SSH_enabled`, `JA4T_enabled`, `JA4TS_enabled`, `JA4L_enabled`, `JA4D_enabled`) can be toggled at runtime without rebuilding, via `-e` or a `redef` script:

```sh
zeek -e 'redef FINGERPRINT::JA4H_enabled = F;' -C -r trace.pcap
```

Disabling a method stops it from computing and populating its field(s), but the log column(s) it uses still exist — they'll simply be empty.

The `_raw` flags (`JA4_raw`, `JA4S_raw`, `JA4H_raw`) work differently: they control whether extra (non-hashed) log columns exist at all. These must be set in `config.zeek` before building — they cannot be toggled via runtime `redef`.

## Tests

btest suite (requires btest in PATH):

```sh
cd tests && btest
```

## Creating a Release

To create a Zeek release, push a tag that is a pure semantic version (e.g., `v1.2.3`), with no prefix:

```sh
git tag v1.2.3
git push origin v1.2.3
```

## License

See [License FAQ](../License%20FAQ.md) for details.
