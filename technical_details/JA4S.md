# JA4S: TLS Server/Session Fingerprint

![JA4S](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.png)

JA4S Algorithm:  
(q or t)  
(2 character tls version)  
(2 character number of extensions)  
(first and last character of the ALPN chosen)  
_  
(cipher suite chosen in hex)  
_  
(truncated sha256 hash of the extensions in the order that they appear)

In the Server Hello packet, there is always a single cipher, the cipher that the server chose to communicate in. So with JA4S, we don’t need to count the number of ciphers or hash them, instead we can just show the cipher chosen. Also with Server Hellos, the extensions are not being randomized, that means we can hash those in the order they are seen rather than sorting them.

An example where the extensions are: 0005,0017,ff01,0000  
Sha256: 4e8089b08790aebafde4a993a4e554d9ed0fff21124965a9e91beabf80879946  
Truncated to the first 12 characters: 4e8089b08790 

JA4S Example:  
t (TLS over TCP)  
12 (no supported versions extension here so this is x0303, TLS 1.2)  
04 (4 extensions)  
00 (first and last character of the ALPN chosen by the server, 00 here as there’s no ALPN extension)  
_  
c030 (the cipher suite chosen by the server in hex)  
_  
4e8089b08790 (truncated sha256 hash of the extensions in the order they were seen)
```
JA4S = t120400_c030_4e8089b08790 
```
### Raw Output
The program should allow for raw outputs. JA4S doesn’t sort so -o does nothing here.
-r (raw fingerprint)

The raw fingerprint for JA4S would look like this:
```
JA4S_r = t120400_c030_0005,0017,ff01,0000
```
