# JA4+ for Zeek
This will add JA4+ fingerprints to zeek logs.

Note: Only works on Zeek Version 6+, we're working on compatibility for old versions.

Included fingerprints:  
JA4 - ```ssl.log```

Fingerprints still in development for Zeek:  
JA4S - ```ssl.log```  
JA4H - ```http.log```  
JA4L - ```conn.log```  
JA4X - ```x509.log```  
JA4SSH - ```ssh.log```  

See https://github.com/FoxIO-LLC/ja4 for more detail on JA4+ and other implmentations.

## Install
(in progress) If using the [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/), run:  
```
zkg install ja4
```

Otherwise, download the zeek files to zeek/share/zeek/site/ja4 and add this line to either __load__.zeek or local.zeek:
```
@load ja4
```

## Configuration
By default this will add ja4 to ssl.log. To add the raw, original, or raw+original fingerprints, uncomment the applicable line in ja4.zeek:
```
  # ja4_r: string &optional &log;
  # ja4_o: string &optional &log;
  # ja4_ro: string &optional &log;
```
...
```
  # c$ssl$ja4_r = c$fp$ja4$r; # JA4_r (raw fingerprint)
  # c$ssl$ja4_o = c$fp$ja4$o; # JA4_o (Original Ordering, not sorted, fingerprint)
  # c$ssl$ja4_ro = c$fp$ja4$ro; # JA4_ro (raw fingerprint with original ordering, closest to what was seen on the wire)
```
