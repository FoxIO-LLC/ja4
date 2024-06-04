# JA4+ Network Fingerprinting

JA4+ is a suite of network fingerprinting methods that are easy to use and easy to share. These methods are both human and machine readable to facilitate more effective threat-hunting and analysis. The use-cases for these fingerprints include scanning for threat actors, malware detection, session hijacking prevention, compliance automation, location tracking, DDoS detection, grouping of threat actors, reverse shell detection, and many more.

Please read our blogs for details on how JA4+ works, why it works, and examples of what can be detected/prevented with it:  
[JA4+ Network Fingerprinting](https://blog.foxio.io/ja4%2B-network-fingerprinting) (JA4/S/H/L/X/SSH)  
[JA4T: TCP Fingerprinting](https://blog.foxio.io/ja4t-tcp-fingerprinting) (JA4T/TS/TScan)  
[Investigating Surfshark and NordVPN with JA4T](https://blog.foxio.io/investigating-surfshark-and-nordvpn-with-ja4t) (JA4T)


To understand how to read JA4+ fingerprints, see [Technical Details](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md)

This repo includes JA4+ in Python, Rust, Zeek and C, as a Wireshark plugin. 

Tools that support JA4+:  
| Tool/Vendor | JA4+ Support |
|-------------|--------------|
[Wireshark](https://github.com/FoxIO-LLC/ja4/tree/main/wireshark) | JA4+
[Zeek](https://github.com/FoxIO-LLC/ja4/tree/main/zeek) | JA4+
[Arkime](https://arkime.com/settings#ja4plus) | JA4+
[Suricata](https://docs.suricata.io/en/latest/rules/ja-keywords.html#ja4-hash) | JA4
[GreyNoise](https://www.greynoise.io/) | JA4+ (you have to ask for it)
[Hunt](https://hunt.io/) | JA4+
[Driftnet](https://driftnet.io/) | JA4X
[DarkSail](https://darksail.ai) | JA4+
[GoLang](https://github.com/driftnet-io/go-ja4x) | JA4X
[nzyme](https://www.nzyme.org/) | JA4+ (under development)
[Netresec's CapLoader](https://www.netresec.com/?page=Blog&month=2023-11&post=CapLoader-1-9-6-Released) | JA4+ (under development)
[Netresec's NetworkMiner](https://www.netresec.com/?page=NetworkMiner) | JA4+ (under development)
[NGINX](https://github.com/FoxIO-LLC/ja4-nginx-module) | JA4+ (under development)
[F5 BIG-IP](https://github.com/f5devcentral/f5-ja4) | JA4+
[nfdump](https://github.com/phaag/nfdump) | JA4+
[ntop's ntopng](https://github.com/ntop/ntopng) | JA4+
[ntop's nDPI](https://github.com/ntop/nDPI) | JA4
[Team Cymru](https://www.team-cymru.com/) | JA4+ (you have to ask for it)
[NetQuest](https://netquestcorp.com/) | JA4+ (under development)
[Censys](https://censys.com/) | JA4+ (under development)
[Exploit.org's Netryx](https://github.com/OWASP/www-project-netryx) | JA4 and JA4H
[Cloudflare](https://developers.cloudflare.com/bots/concepts/ja3-ja4-fingerprint/) | JA4
[Fastly](https://www.fastly.com/documentation/reference/vcl/variables/client-connection/tls-client-ja4/) | JA4
with more to be announced...  

## Examples

| Application |JA4+ Fingerprints |
|----|----|
| Chrome | ```JA4=t13d1516h2_8daaf6152771_02713d6af862``` (TCP) <br/> ```JA4=q13d0312h3_55b375c5d22e_06cda9e17597``` (QUIC) <br/> ```JA4=t13d1517h2_8daaf6152771_b0da82dd1658``` (pre-shared key) <br/> ```JA4=t13d1517h2_8daaf6152771_b1ff8ab2d16f``` (no key) |
| IcedID Malware Dropper | ```JA4H=ge11cn020000_9ed1ff1f7b03_cd8dafe26982``` |
| IcedID Malware | ```JA4=t13d201100_2b729b4bf6f3_9e7b989ebec8``` <br/> ```JA4S=t120300_c030_5e2616a54c73``` |
| Sliver Malware | ```JA4=t13d190900_9dc949149365_97f8aa674fd9``` <br/> ```JA4S=t130200_1301_a56c5b993250``` <br/> ```JA4X=000000000000_4f24da86fad6_bf0f0589fc03``` <br/> ```JA4X=000000000000_7c32fa18c13e_bf0f0589fc03``` |
| Cobalt Strike | ```JA4H=ge11cn060000_4e59edc1297a_4da5efaf0cbd``` <br/> ```JA4X=2166164053c1_2166164053c1_30d204a01551``` |
| SoftEther VPN | ```JA4=t13d880900_fcb5b95cb75a_b0d3b4ac2a14``` (client) <br/> ```JA4S=t130200_1302_a56c5b993250``` <br/> ```JA4X=d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae``` |
| Qakbot | ```JA4X=2bab15409345_af684594efb4_000000000000``` |
| Pikabot | ```JA4X=1a59268f55e5_1a59268f55e5_795797892f9c``` |
| Darkgate | ```JA4H=po10nn060000_cdb958d032b0``` |
| LummaC2 | ```JA4H=po11nn050000_d253db9d024b``` |
| Evilginx | ```JA4=t13d191000_9dc949149365_e7c285222651``` |
| Reverse SSH Shell | ```JA4SSH=c76s76_c71s59_c0s70``` |
| Windows 10 | ```JA4T=64240_2-1-3-1-1-4_1460_8``` |
| Epson Printer | ```JA4TScan=28960_2-4-8-1-3_1460_3_1-4-8-16``` |

For more examples, see [ja4plus-mapping.csv](https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv)  
For a complete database, see [ja4db.com](https://ja4db.com/)  

## Plugins

[Wireshark](https://github.com/FoxIO-LLC/ja4/tree/main/wireshark)  
[Zeek](https://github.com/FoxIO-LLC/ja4/tree/main/zeek)  
[Arkime](https://arkime.com/settings#ja4plus)  

## Binaries

Recommended to have tshark version 4.0.6 or later for full functionality. See: https://pkgs.org/search/?q=tshark  

Download the latest JA4 binaries from: [Releases](https://github.com/FoxIO-LLC/ja4/releases).

### JA4+ on Ubuntu  
```
sudo apt install tshark
./ja4 [options] [pcap]
```

### JA4+ on Mac
1) Install Wireshark https://www.wireshark.org/download.html which will install tshark
2) Add tshark to $PATH
```
ln -s /Applications/Wireshark.app/Contents/MacOS/tshark /usr/local/bin/tshark
./ja4 [options] [pcap]
```

### JA4+ on Windows
1) Install Wireshark for Windows from https://www.wireshark.org/download.html which will install tshark.exe  
tshark.exe is at the location where wireshark is installed, for example: C:\Program Files\Wireshark\thsark.exe  
2) Add the location of tshark to your "PATH" environment variable in Windows.  
   (System properties > Environment Variables... > Edit Path)  
3) Open cmd, navigate the ja4 folder
```
ja4 [options] [pcap]
```

## Database

The official JA4+ database of fingerprints, associated applications and recommended detection logic is here: [ja4db.com](https://ja4db.com/)  
This database is under very active development. Expect orders of magnitude more fingerprint combinations and data over the next few months (Aug 2024).

A sample [ja4plus-mapping.csv](https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv) is also available for quick reference.

## JA4+ Details

JA4+ is a set of simple yet powerful network fingerprints for multiple protocols that are both human and machine readable, facilitating improved threat-hunting and security analysis. If you are unfamiliar with network fingerprinting, I encourage you to read my blogs releasing JA3 [here](https://medium.com/salesforce-engineering/tls-fingerprinting-with-ja3-and-ja3s-247362855967), JARM [here](https://medium.com/salesforce-engineering/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a), and this excellent blog by Fastly on the [State of TLS Fingerprinting](https://www.fastly.com/blog/the-state-of-tls-fingerprinting-whats-working-what-isnt-and-whats-next) which outlines the history of the aforementioned along with their problems. JA4+ brings dedicated support, keeping the methods up-to-date as the industry changes. 

All JA4+ fingerprints have an a_b_c format, delimiting the different sections that make up the fingerprint. This allows for hunting and detection utilizing just ab or ac or c only. If one wanted to just do analysis on incoming cookies into their app, they would look at JA4H_c only. This new locality-preserving format facilitates deeper and richer analysis while remaining simple, easy to use, and allowing for extensibility. 

For example; GreyNoise is an internet listener that identifies internet scanners and is implementing JA4+ into their product. They have an actor who scans the internet with a constantly changing single TLS cipher. This generates a massive amount of completely different JA3 fingerprints but with JA4, only the b part of the JA4 fingerprint changes, parts a and c remain the same. As such, GreyNoise can track the actor by looking at the JA4_ac fingerprint (joining a+c, dropping b).

Current methods and implementation details:  
| Full Name | Short Name | Description |
|---|---|---|
| JA4 | JA4 | TLS Client Fingerprinting  
| JA4Server | JA4S | TLS Server Response / Session Fingerprinting
| JA4HTTP | JA4H | HTTP Client Fingerprinting
| JA4Latency | JA4L | Client to Server Latency Measurment / Light Distance
| JA4LatencyServer | JA4LS | Server to Client Latency Measurement / Light Distance
| JA4X509 | JA4X | X509 TLS Certificate Fingerprinting
| JA4SSH | JA4SSH | SSH Traffic Fingerprinting
| JA4TCP | JA4T | TCP Client Fingerprinting
| JA4TCPServer | JA4TS | TCP Server Response Fingerprinting
| [JA4TCPScan](https://github.com/FoxIO-LLC/ja4tscan) | [JA4TScan](https://github.com/FoxIO-LLC/ja4tscan) | [Active TCP Fingerprint Scanner](https://github.com/FoxIO-LLC/ja4tscan)

The full name or short name can be used interchangeably. Additional JA4+ methods are in the works...

To understand how to read JA4+ fingerprints, see [Technical Details](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md)

## Licensing

__JA4: TLS Client Fingerprinting__ is [open-source, BSD 3-Clause](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4), same as JA3. FoxIO does not have patent claims and is not planning to pursue patent coverage for JA4 TLS Client Fingerprinting. This allows any company or tool currently utilizing JA3 to immediately upgrade to JA4 without delay.

__JA4S, JA4L, JA4LS, JA4H, JA4X, JA4SSH, JA4T, JA4TS, JA4TScan and all future additions, (collectively referred to as JA4+)__ are licensed under the [FoxIO License 1.1](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE). This license is permissive for most use cases, including for academic and internal business purposes, but is not permissive for monetization. If, for example, a company would like to use JA4+ internally to help secure their own company, that is permitted. If, for example, a vendor would like to sell JA4+ fingerprinting as part of their product offering, they would need to request an OEM license from us.

All JA4+ methods are patent pending.  
JA4+ is a trademark of FoxIO

JA4+ can and is being implemented into open source tools, see the [License FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md) for details.

This licensing allows us to provide JA4+ to the world in a way that is open and immediately usable, but also provides us with a way to fund continued support, research into new methods, and the development of the JA4+ Database. We want everyone to have the ability to utilize JA4+ and are happy to work with vendors and open source projects to help make that happen.

## Q&A

Q: Why are you sorting the ciphers? Doesn’t the ordering matter?  
A: It does but in our research we’ve found that applications and libraries choose a unique cipher list more than unique ordering. This also reduces the effectiveness of “cipher stunting,” a tactic of randomizing cipher ordering to prevent JA3 detection.

Q: Why are you sorting the extensions?  
A: Earlier in 2023, Google [updated Chromium](https://chromestatus.com/feature/5124606246518784) browsers to randomize their extension ordering. Much like cipher stunting, this was a tactic to prevent JA3 detection and “make the TLS ecosystem more robust to changes.” Google was worried server implementers would assume the Chrome fingerprint would never change and end up building logic around it, which would cause issues whenever Google went to update Chrome. 

So I want to make this clear: JA4 fingerprints will change as application TLS libraries are updated, about once a year. Do not assume fingerprints will remain constant in an environment where applications are updated. In any case, sorting the extensions gets around this and adding in Signature Algorithms preserves uniqueness. 

Q: Doesn't TLS 1.3 make fingerprinting TLS clients harder?  
A: No, it makes it easier! Since TLS 1.3, clients have had a much larger set of extensions and even though TLS1.3 only supports a few ciphers, browsers and applications still support many more.

## JA4+ was created by: 
[John Althouse](https://www.linkedin.com/in/johnalthouse/), with feedback from:

Josh Atkins  
Jeff Atkinson  
Joshua Alexander  
W.  
Joe Martin  
Ben Higgins  
Andrew Morris  
Chris Ueland  
Ben Schofield  
Matthias Vallentin  
Valeriy Vorotyntsev  
Timothy Noel  
Gary Lipsky  
And engineers working at GreyNoise, Hunt, Google, ExtraHop, F5, Driftnet and others.  

Contact John Althouse at john@foxio.io for licensing and questions.

<sub><sup>Copyright (c) 2024, FoxIO</sup></sub>
