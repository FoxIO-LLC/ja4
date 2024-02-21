# JA4+ Technical Details  

| Full Name | Short Name | Description |
|---|---|---|
| JA4 | JA4 | [TLS Client Fingerprinting](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)  
| JA4Server | JA4S | [TLS Server Response / Session Fingerprinting](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.md)  
| JA4HTTP | JA4H | [HTTP Client Fingerprinting](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md)  
| JA4Latency | JA4L | [Latency Measurment / Light Distance](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4L.md)  
| JA4X509 | JA4X | [X509 TLS Certificate Fingerprinting](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4X.md)  
| JA4SSH | JA4SSH | [SSH Traffic Fingerprinting](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4SSH.md)  
| JA4TCP | JA4T | [TCP Client Fingerprinting](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4T.md)  
| JA4TCPServer | JA4TS | [TCP Server Response Fingerprinting](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4T.md)  
| JA4TCPScan | JA4TScan | [Active TCP Fingerprint Scanner](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4T.md)  

The full name or short name can be used interchangeably. Additional JA4+ methods are in the works...

### JA4+ General Rules
1. JA4+ fingerprints are split into an a_b_c format. If one wants to show just the c section of JA4H, that is represented as 'JA4H_c'. 
2. All hex values used to generate fingerprint hashes are in lowercase hex.
3. All fingerprint outputs are lowercase. In the case of JA4_a, it's a lowercase string, JA4_bc is lowercase hex, and so on.
4. '_r' denotes a raw, unhashed fingerprint. '_ro' denotes a raw, unhashed fingerprint in its original ordering (not sorted). So a raw ja4 fingerprint is represented as 'ja4_r'.  
5. If a hashed section is empty, the output is 000000000000 instead of a hash of an empty section. This is more conducive for analysis.
6. If a search only contains the first two sections of a fingerprint, for example JA4H=ge11cn060000_4e59edc1297a, that is an implied * at the end of the fingerprint as the fingerprint generating tool would output all fields, for example JA4H=ge11cn060000_4e59edc1297a_4da5efaf0cbd_000000000000.


### License
See [Licensing](https://github.com/FoxIO-LLC/ja4/tree/main#licensing) in the repo root. We are committed to work with vendors and open source projects to help implement JA4+ into those tools. Please contact john@foxio.io with any questions.
