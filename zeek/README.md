# JA4+ for Zeek <!-- omit from toc -->

This will add JA4+ fingerprints to respective protocol zeek logs.  
JA4SSH will output to it's own log.  

JA4 &rarr; `ssl.log`  
JA4S &rarr; `ssl.log`  
JA4H &rarr; `http.log`  
JA4L &rarr; `conn.log`  
JA4LS &rarr; `conn.log`  
JA4T &rarr; `conn.log`  
JA4TS &rarr; `conn.log`  
JA4SSH &rarr; `ja4ssh.log`  
JA4D &rarr; `ja4d.log`  
JA4D6 &rarr; `ja4d.log` (awaiting Zeek DHCPv6 suppport)  
JA4X &rarr; `x509.log` (awaiting Zeek object support)  

See [JA4+ and implementations into other open source tools](../README.md) for more detail on JA4+ and implementations into other open source tools.

## Table of Contents <!-- omit from toc -->

- [Install](#install)
- [Requirements](#requirements)
- [Config](#config)
- [Creating a Release](#creating-a-release)
- [License](#license)

## Install

Run the following command on your Zeek nodes:

```sh
zkg install zeek/foxio/ja4
```

If you don't have the zeek package manager, copy this directory to `zeek/share/zeek/site/ja4` and add this line to either `__load__.zeek` or `local.zeek` in `zeek/share/zeek/site/`:

```txt
@load ja4
```

## Requirements

Zeek 5+ is supported.  
Zeek 6+ is required for QUIC support.  

## Config

Individual JA4+ methods can be enabled or disabled in config.zeek.  
The raw output for JA4+ methods (non-hashed) can also be enabled in config.zeek

## Creating a Release

To create a Zeek release, push a tag that is a pure semantic version (e.g., `v1.2.3`), with no prefix:

```sh
git tag v1.2.3
git push origin v1.2.3
```

## License

See [License FAQ](../License%20FAQ.md) for details.
