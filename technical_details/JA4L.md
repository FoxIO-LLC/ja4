# JA4L: Light Distance

![JA4L](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4L.png)

JA4L measures the light distance/latency between the first few packets in a connection. We use the first few packets as these are low-level machine generated so there is nearly zero processing delay in creating and sending these packets. This essentially measures the estimated distance between the client and server. Time is measured in microseconds (µs). 1ms = 1000µs. Microseconds are a standard unit of time measurement in packet captures.

If the packet capture/program is running server side, this will measure the distance of the client from the server and if this is running client side, this will measure the distance of the server from the client. If this is running on a network tap, it will measure the distance of each from the network tap location.

JA4L is split up into 2 measurements, client and server. For TCP, these are determined by looking at the TCP 3-way handshake. UDP, we’re looking at the QUIC handshake.

### TCP:

In the TCP 3-way handshake, first the client sends a SYN packet. The timestamp that the syn packet is seen is captured by the program as value “A”. Additionally, the IP TTL from the client is captured.

Then the server responds with a SYN ACK packet. The timestamp of that packet is value “B”. Additionally, the IPv4 TTL or IPv6 Hop Count from the server is captured.

Then the client will respond with an ACK packet, thus completing the TCP 3-way handshake. The timestamp of that packet is value “C”
```
JA4L-C = {(C - B) / 2}_Client TTL
JA4L-S = {(B - A) / 2}_Server TTL
```
Example:  
```
JA4L-C = 11_128  
JA4L-S = 1759_42  
```
### QUIC:
QUIC setup spans several packets.

1. Client sends an Initial QUIC Packet. This timestamp is “A”  
2. Server responds with its Initial QUIC Packet. This timestamp is “B”  
3. Server sends several handshake packets to the client. This could be 1 - 5 packets depending on the server, these are ignored.  
4. The last packet from the server before the client sends a packet is “C”  
5. Client’s 2nd packet, the handshake packet, is “D”  
```
JA4L-C = { (D - C) / 2 }_Client TTL  
JA4L-S = { (B - A) / 2 }_Server TTL
```
## Measuring Distance and Location

With JA4L we can determine the distance between the client and server using this formula:  
_D = jc/p_

D = Distance  
j = JA4L_a  
c = Speed of light per µs in fiber (0.128 miles/µs or 0.206km/µs)
p = Propagation delay factor  

Typical propagation delay depends on terrain and how many networks are involved.  
Poor terrain factor = 2 (around mountains, water)  
Good terrain factor = 1.5 (along highway, under sea cables)  
SpaceX factor = … needs to be tested  

We can use the TTL to calculate the hop count, which can help inform the propagation delay factor. (The table below is a good starting point but more testing needs to be done.)

| Hop Count | Propagation Delay Factor |
|----------|-----------|
| <= 21 | 1.5 |
| 22 | 1.6 |
| 23 | 1.7 |
| 24 | 1.8 |
| 25 | 1.9 |
| >=26 | 2.0 |

To calculate the number of hops a connection went through, subtract the TTL from its estimated initial TTL.

Cisco, F5, most networking devices use a TTL of 255  
Windows uses a TTL of 128  
Mac, Linux, phones, and IoT devices use a TTL of 64

Most routes on the Internet have less than 64 hops. Therefore if the observed TTL, JA4L_b, is <64, the estimated initial TTL is 64. Within 65-128, the estimated initial TTL is 128. And if the TTL is >128 then the estimated initial TTL is 255.

With a JA4L-S of 2449_42, the observed TTL of 42 means the initial TTL was likely 64, a Linux server. 64-42 gives us a hop count of 22.

2449x0.128/1.6=195  
We can conclude that this server is within 195 miles of the client. The server may be closer than this, but it is physically impossible for it to be farther away as the speed of light is constant. If there are multiple JA4Ls for the same host, the lowest value should be taken as the most accurate. 
In this example, the actual distance was 194 miles.

Utilizing multiple locations, one can passively triangulate the physical location of any client or server down to a city area. 

