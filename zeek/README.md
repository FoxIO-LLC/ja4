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
JA4X &rarr; `x509.log` (still in development)  

See [JA4+ and implementations into other open source tools](../README.md) for more detail on JA4+ and implementations into other open source tools.

## Table of Contents <!-- omit from toc -->

- [Install](#install)
- [Requirements](#requirements)
- [Config](#config)
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

## License

See [License FAQ](../License%20FAQ.md) for details.
