# JA4+ for Zeek
UNDER ACTIVE DEVELOPMENT  
This will be updated on a daily basis until main development is complete.

This will add JA4+ fingerprints to respective protocol zeek logs.  
JA4SSH will output to it's own log.  

See https://github.com/FoxIO-LLC/ja4 for more detail on JA4+ and implementations into other open source tools.

## Install
We will add to the Zeek package manager once development is complete.

Until then, copy this directory to zeek/share/zeek/site/ja4plus and add this line to either __load__.zeek or local.zeek in zeek/share/zeek/site/:
```
@load ja4plus
```

## Config
Individual JA4+ methods can be enabled or disabled in config.zeek.  
The raw output for JA4+ methods (non-hashed) can also be enabled in config.zeek

## License
See [License FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md) for details.
