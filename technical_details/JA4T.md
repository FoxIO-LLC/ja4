# JA4T: TCP Fingerprint

![JA4T](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4T.png)

| Full Name | Short Name | Decription |
|-------|-------|------|
JA4TCP | JA4T | TCP Client Fingerprint |
JA4TCPServer | JA4TS | TCP Server Response Fingerprint |
JA4TCPScan | JA4TScan | Active TCP Server Fingerprint Scanner |

JA4T fingerprints the TCP SYN packet sent from the client.  
JA4TS fingerprints the TCP SYN ACK response packet(s) sent from the server.  
JA4TScan fingerprints servers by envoking TCP retransmissions.

These methods are inspired by:  
p0f - Michał Zalewski - last update 2014  
hershel+ - Zain Shamsi & Dmitri Loguinov - last update 2018  
gait - Charles Smutz & Brandon A. Thomas - active zeek scipts

The goal of JA4T/S/Scan was to make a small and extemely useful TCP fingerprint that does not require a database, that is easy to eyeball and pivot on in hunting and log analysis. Each OS, device, and some applications have their own TCP fingerprint, their own way of using the TCP stack. And differences in Window Size and Maximum Segment Size can provide clues as to the network characteristics.

JA4T Examples:

| OS/Device/Application | JA4T |
|----|----|
| Windows 10 | 64240_2-1-3-1-1-4_1460_8 |
| WSL Ubuntu on Windows 10 | 64240_2-4-8-1-3_1460_7 |
| Ubuntu 22.04 | 65535_2-4-8-1-3_1460_8 |
| Amazon AWS Linux 2 | 62727_2-4-8-1-3_8961_7 |
| Mac OSX / iPhone | 65535_2-1-3-1-1-8-4-0-0_1460_6 |
| Nmap | 1024_2_1460_00 |
| Zmap | 65535_00_00_00 |
| Web Scanner | 1024_00_00_00 |

JA4TScan Examples:

| OS/Device/Application | JA4TScan |
|-----|-----|
| Windows 10 | 64240_2-1-3-1-1-4_1460_8_1-2-4-8-R6 |
| Windows 2003 | 16384_2-1-3-1-1-8-1-1-4_1460_00_2-7 |
| Amazon AWS Linux 2 | 62727_2-4-8-1-3_8961_7_1-2-4-8-16 |
| Mac OSX / iPhone | 65535_2-1-3-1-1-8-4-0-0_1460_6_1-2-4-8-16-32-12 |
| F5 Big IP | 4380_2-1-3-1-1-8-1-1-4_1460_1_3-6 |
| HP ILO | 5840_2_1460_00_3-6-12-24-48-60-60-60-60-60 |
| Epson Printer | 28960_2-4-8-1-3_1460_3_1-4-8-16 |

![exampleja4t1](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/exampleja4t1.png)

__JA4T Fingerprint format:__

WindowSize_TCPOptions_MSSValue_WindowScale

The TCP Window Size is captured in decimal, 64240 in the example screenshot.

TCP options are limited to 1 byte. List to TCP options (kinds): https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml Most modern operating systems use TCP options 2,3,4, and 8. Some specific devices will use options up to 255. Option 1 is used to pad the options to be divisible by 4 and option 0 is sometimes used to denote the end of the options list.

In the above screenshot example, we have options 2,1,3,1,1,4. These would be captured as their decimal values, hyphen delimited:  
2-1-3-1-1-4

The MSS value is captured in Decimal. In the above example, the MSS value is 1460.

The Window scale is captured in Decimal as well. In the above example, the Window scale is 8.

If any field does not exist, then the output is 00. For example, a packet with a Window of 1024 and no TCP options, and therefore no Window scale would be:
JA4T = 1024_00_00_00

Using the above screenshot example:

JA4T = 64240_2-1-3-1-1-4_1460_8

__JA4TS and JA4TScan Fingerprint formats:__

WindowSize_TCPOptions_MSSValue_WindowScale_TimeSinceLastSYNACK  
a_b_c_d_e

JA4TS takes into account the number of SYNACK TCP Retransmissions, or RST, as well as the time delay between each retransmission or RST. Different OS/Devices will retransmit a different amount of times and at different intervals.

If no retransmissions are seen, as there shouldn't be in normal network communications, the fingerprint will omit section e. If retransmissions are seen, the fingerprint will fill out section e.

Note that the JA4TS is dependant on the JA4T that was sent to it. If, for example, a client sent a SYN packet with no TCP options, the server will respond with a SYN ACK with no TCP options. That is NOT the TCP fingerprint of the server, but is a fingerprint of the server's response.

JA4TScan is a tool that sends a very specific SYN packet and then listens to all SYN ACK responses. This DOES build out a TCP fingerprint of the server, similar to how JARM works for TLS servers.

![exampleja4t2](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/exampleja4t2.png)

In the above example, there are 5 TCP retransmissions with different delays between them. To find the delay between them we start with the timestamp of the first SYNACK and subtract it from the next SYNACK, rounding the result to the nearest whole number in seconds. In the above example:

1. 15.621983  
2. 16.626151 - 15.621983 = 1.004 = 1  
3. 18.642179 - 16.626151 = 2.016 = 2  
4. 22.738154 - 18.642179 = 4.096 = 4  
5. 30.930163 - 22.738154 = 8.192 = 8  
6. 47.058146 - 30.930163 = 16.128 = 16  

Thereby JA4TS builds out the fingerprint as follows:

1. 62727_2_8961_00  
2. 62727_2_8961_00_1  
3. 62727_2_8961_00_1-2  
4. 62727_2_8961_00_1-2-4  
5. 62727_2_8961_00_1-2-4-8  
6. 62727_2_8961_00_1-2-4-8-16  

With 62727_2_8961_00_1-2-4-8-16 being the final fingerprint in this example.

Because it is not known when the last retransmission will come in, a timeout is requred as to not fill up state tables. The max is 10 retransmissions counted and the timeout is 2 minutes after the last SYNACK.

Some systems will send several SYNACK retransmissions and just stop while others will send a RST (reset) after a few retransmissions. For example:

![exampleja4t3](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/exampleja4t3.png)

In this case, the final TCP packet, a RST packet, should be appended to the last JA4TS denoted with “R” and its delay. In the above example:

1. 16.681435  
2. 17.683799 - 16.681435 = 1.002 = 1  
3. 19.691548 - 17.683799 = 2.008 = 2  
4. 23.703045 - 19.691548 = 4.011 = 4  
5. 31.714762 - 23.703045 = 8.012 = 8  
6. RST 37.723966 - 31.714762 = RST 6.009 = R6

Thereby the JA4TS fingerprints for each SYN ACK in order would be:

1. 65535_2-1-3-1-1-4_65495_8  
2. 65535_2-1-3-1-1-4_65495_8_1  
3. 65535_2-1-3-1-1-4_65495_8_1-2  
4. 65535_2-1-3-1-1-4_65495_8_1-2-4  
5. 65535_2-1-3-1-1-4_65495_8_1-2-4-8  
6. 65535_2-1-3-1-1-4_65495_8_1-2-4-8-R6

With 65535_2-1-3-1-1-4_65495_8_1-2-4-8-R6 being the final fingerprint of the server.

Note that RST packets do not contain TCP options or window sizes, as such the program will need to be aware of the previous JA4TS. 

