# JA4+ for Zeek <!-- omit from toc -->

A compiled Zeek plugin implementing JA4+ network fingerprinting. Replaces the pure-script implementation with C++ BiF functions for performance-critical fingerprints.

For the non-plugin, scripts-only version of JA4+, see: https://github.com/FoxIO-LLC/ja4-zeek-scripts

C++ accelerated (BiF):
  
JA4 &rarr; `ssl.log`  
JA4S &rarr; `ssl.log`  
JA4H &rarr; `http.log`  
JA4SSH &rarr; `ja4ssh.log` (new log file)  
JA4N &rarr; `ntp.log`
  
Pure script (bundled):

JA4L &rarr; `conn.log`  
JA4L-Delta &rarr; `conn.log`  
JA4LS &rarr; `conn.log`  
JA4LS-Delta &rarr; `conn.log`  
JA4T &rarr; `conn.log`  
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
# Plugin auto-loads JA4/JA4S/JA4H/JA4SSH/JA4T/JA4L/JA4D/JA4N
zeek -C -r trace.pcap
```

Fingerprint fields are added to `ssl.log`, `conn.log`, `http.log`, and `ntp.log`, plus dedicated `ja4ssh.log` / `ja4d.log` streams.

## Config

Individual JA4+ methods (`JA4_enabled`, `JA4S_enabled`, `JA4H_enabled`, `JA4SSH_enabled`, `JA4T_enabled`, `JA4TS_enabled`, `JA4L_enabled`, `JA4D_enabled`, `JA4N_enabled`) can be toggled at runtime without rebuilding, via `-e` or a `redef` script:

```sh
zeek -e 'redef FINGERPRINT::JA4H_enabled = F;' -C -r trace.pcap
```

Disabling a method stops it from computing and populating its field(s), but the log column(s) it uses still exist — they'll simply be empty.

The `_raw` flags (`JA4_raw`, `JA4S_raw`, `JA4H_raw`) work differently: they control whether extra (non-hashed) log columns exist at all. These must be set in `config.zeek` before building — they cannot be toggled via runtime `redef`.

### JA4N

JA4N fingerprints NTP and follows the JA4N reference implementation in [arkime/ja4](https://github.com/arkime/ja4) (`ja4plus.c`). Each UDP connection with port 123 on either side is a candidate. It is fingerprinted once the first non-empty payload of either direction (only the first one per direction is checked) looks like NTP (at least 48 bytes, stratum 16 or less, version 1-4, non-zero mode); from then on every payload of 48 bytes or more in both directions is fingerprinted, without re-checking those fields, so later fingerprints can show any version (0-7) or mode. Whether a message came from client or server is in the fingerprint's mode character.

The fingerprint goes in a `ja4n` column on the `ntp.log` record for the same message, so every logged message of a fingerprinted connection carries its own value. On Zeek versions that write `ntp_control.log` and `ntp_private.log` (modes 6 and 7), those get the column too. The column is empty for messages that produced no fingerprint. A message that Zeek's NTP analyzer does not log, such as mode 0 or a payload it cannot parse, has no record to hold its fingerprint, so its fingerprint is not logged anywhere.

The timestamp section compares NTP timestamps with the whole seconds of the connection's first packet, so results are reproducible from a pcap.

Notes:

- The plugin adds `123/udp` to Zeek's `udp_content_ports` so payloads reach the `udp_contents` event. Other scripts handling `udp_contents` will also see NTP payloads.
- Classification is per Zeek connection. Zeek ends idle UDP connections after `udp_inactivity_timeout` (default 1 min), so a client polling every 64 s or more starts a new connection for each exchange, and each one is classified again.
- Like the rest of Zeek, packets with bad UDP checksums are dropped unless checksums are ignored (`-C`).
- The reference clamps the payload to the UDP header's length field; Zeek uses the IP payload length. The two differ only for malformed packets whose UDP length is shorter than the datagram.

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
