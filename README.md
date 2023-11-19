# JA4+ Network Fingerprinting

JA4+ is a suite of network fingerprinting methods that are easy to use and easy to share. These methods are both human and machine readable to facilitate more effective threat-hunting and analysis. The use-cases for these fingerprints include scanning for threat actors, malware detection, session hijacking prevention, compliance automation, location tracking, DDoS detection, grouping of threat actors, reverse shell detection, and many more.

Please read this blog post for more details: [JA4+ Network Fingerprinting](https://medium.com/foxio/ja4-network-fingerprinting-9376fe9ca637)

This repo includes JA4+ scripts in Python as well as Rust Binaries. 

JA4+ support is being added to:  
[GreyNoise](https://www.greynoise.io/)  
[Hunt](https://hunt.io/)  
[Driftnet](https://driftnet.io/)  
[Darksail](https://darksail.ai)  
[Arkime](https://arkime.com/)  
[GoLang](https://github.com/driftnet-io/go-ja4x) (JA4X)  
[Suricata](https://github.com/OISF/suricata/pull/9634)  
[Wireshark](https://github.com/FoxIO-LLC/ja4/tree/main/wireshark)  
[Zeek](https://github.com/FoxIO-LLC/ja4/tree/main/zeek)  
[nzyme](https://www.nzyme.org/)  
[CapLoader](https://www.netresec.com/?page=Blog&month=2023-11&post=CapLoader-1-9-6-Released)  
[NetworkMiner](https://www.netresec.com/?page=NetworkMiner)  
[NGINX](https://hub.docker.com/r/thatcherthornberry/nginx-ja4)  
with more to be announced...  

## Examples

| Application |JA4+ Fingerprints |
|----|----|
| Chrome | JA4=t13d1516h2_8daaf6152771_e5627efa2ab1 (TCP) <br/> JA4=q13d0310h3_55b375c5d22e_cd85d2d88918 (QUIC) <br/> JA4=t13d1516h2_8daaf6152771_02713d6af862 (ECH) |
| IcedID Malware Dropper | JA4H=ge11cn020000_9ed1ff1f7b03_cd8dafe26982 |
| IcedID Malware | JA4=t13d201100_2b729b4bf6f3_9e7b989ebec8 <br/> JA4S=t120300_c030_5e2616a54c73 |
| Sliver Malware | JA4=t13d190900_9dc949149365_97f8aa674fd9 <br/> JA4S=t130200_1301_a56c5b993250 <br/> JA4X=000000000000_4f24da86fad6_bf0f0589fc03 <br/> JA4X=000000000000_7c32fa18c13e_bf0f0589fc03 |
| Cobalt Strike | JA4H=ge11cn060000_4e59edc1297a_4da5efaf0cbd <br/> JA4X=2166164053c1_2166164053c1_30d204a01551 |
| SoftEther VPN | JA4=t13d880900_fcb5b95cb75a_b0d3b4ac2a14 (client) <br/> JA4S=t130200_1302_a56c5b993250 <br/> JA4X=d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae |
| Qakbot | JA4X=2bab15409345_af684594efb4_000000000000 |
| Pikabot | JA4X=1a59268f55e5_1a59268f55e5_795797892f9c |
| Darkgate | JA4H=po10nn060000_cdb958d032b0 |
| LummaC2 | JA4H=po11nn050000_d253db9d024b |
| Evilginx | JA4=t13d191000_9dc949149365_e7c285222651 |
| Reverse SSH Shell | JA4SSH=c76s76_c71s59_c0s70 |

## Plugins

[Wireshark](https://github.com/FoxIO-LLC/ja4/tree/main/wireshark)  
[Zeek](https://github.com/FoxIO-LLC/ja4/tree/main/zeek)  

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

An official JA4+ database of fingerprints, associated applications and recommended detection logic is in the process of being built.

## JA4+ Details

JA4+ is a set of simple yet powerful network fingerprints for multiple protocols that are both human and machine readable, facilitating improved threat-hunting and security analysis. If you are unfamiliar with network fingerprinting, I encourage you to read my blogs releasing JA3 [here](https://medium.com/salesforce-engineering/tls-fingerprinting-with-ja3-and-ja3s-247362855967), JARM [here](https://medium.com/salesforce-engineering/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a), and this excellent blog by Fastly on the [State of TLS Fingerprinting](https://www.fastly.com/blog/the-state-of-tls-fingerprinting-whats-working-what-isnt-and-whats-next) which outlines the history of the aforementioned along with their problems. JA4+ brings dedicated support, keeping the methods up-to-date as the industry changes. 

All JA4+ fingerprints have an a_b_c format, delimiting the different sections that make up the fingerprint. This allows for hunting and detection utilizing just ab or ac or c only. If one wanted to just do analysis on incoming cookies into their app, they would look at JA4H_c only. This new locality-preserving format facilitates deeper and richer analysis while remaining simple, easy to use, and allowing for extensibility. 

For example; GreyNoise is an internet listener that identifies internet scanners and is implementing JA4+ into their product. They have an actor who scans the internet with a constantly changing single TLS cipher. This generates a massive amount of completely different JA3 fingerprints but with JA4, only the b part of the JA4 fingerprint changes, parts a and c remain the same. As such, GreyNoise can track the actor by looking at the JA4_ac fingerprint (joining a+c, dropping b).

Current methods and implementation details:  
[JA4: TLS Client Fingerprinting](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)  
[JA4S: TLS Server/Session Fingerprinting](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.md)  
[JA4H: HTTP Client Fingerprinting](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md)  
[JA4L: Light Distance Locality](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4L.md)  
[JA4X: X509 TLS Certificate Fingerprinting](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4X.md)  
[JA4SSH: SSH Traffic Fingerprinting](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4SSH.md)  
Additional JA4+ methods are in the works...

## Licensing

__JA4: TLS Client Fingerprinting__ is [open-source, BSD 3-Clause](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4), same as JA3. FoxIO does not have patent claims and is not planning to pursue patent coverage for JA4 TLS Client Fingerprinting. This allows any company or tool currently utilizing JA3 to immediately upgrade to JA4 without delay.

__JA4S, JA4L, JA4H, JA4X, JA4SSH, and all future additions, (collectively referred to as JA4+)__ are licensed under the [FoxIO License 1.1](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE). This license is permissive for most use cases, including for academic and internal business purposes, but is not permissive for monetization. If, for example, a company would like to use JA4+ internally to help secure their own company, that is permitted. If, for example, a vendor would like to sell JA4+ fingerprinting as part of their product offering, they would need to request an OEM license from us.

All JA4+ methods are patent pending.

JA4+ can and is being implemented into open source tools, see the [License FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md) for details.

This licensing allows us to provide JA4+ to the world in a way that is open and immediately usable, but also provides us with a way to fund continued support, research into new methods, and the development of the upcoming JA4 Database. We want everyone to have the ability to utilize JA4+ and are happy to work with vendors and open source projects to help make that happen.

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
