# JA4X: X509 TLS Certificate Fingerprint
Credit: W.

![JA4X](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4X.png)

JA4X looks at the TLS certificate (X500/X509/X520). These certificates are encrypted in TLS 1.3 but are sent in clear text in TLS 1.2. This fingerprint can identify the application that was used to generate the certificate. This fingerprint may be used best in scanning and identifying connections to certain self signed certs as well as a pivot point in hunting.

(12 character truncated sha256 of the Issuer RDNs in the order they are seen)
_
(12 character truncated sha256 of the Subject RDNs in the order they are seen)
_
(12 character truncated sha256 of the extensions in the order they are seen)
```
Example JA4X = 96a6439c8f5c_96a6439c8f5c_aae71e8db6d7
```

When truncating SHA256 we are using the first 12 characters.

We use only the hex values for the RDNs, comma separated, to build out the fingerprint string. As an example: 
```
Issuer = 550403,550406,550408,55040a = 96a6439c8f5c
Subject = 550403,550406,550408,55040a = 96a6439c8f5c
Extensions = 551d0f,551d25,551d11 = aae71e8db6d7

JA4X = 96a6439c8f5c_96a6439c8f5c _aae71e8db6d7
```
## Raw Output
The program should allow for raw outputs. JA4X doesn’t sort so -o does nothing here.
-r (raw fingerprint)

The raw fingerprint for JA4 would look like this:
```
JA4X_r = 550403,550406,550408,55040a_550403,550406,550408,55040a_551d0f,551d25,551d11
```
