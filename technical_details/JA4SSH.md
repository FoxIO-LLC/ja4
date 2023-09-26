# JA4SSH: SSH Traffic Fingerprint

![JA4SSH](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4SSH.png)

Runs every n packets per SSH TCP stream. n = 200 by default but is configurable. So by default JA4SSH is running every 200 packets per SSH TCP stream. This means each SSH stream will have multiple JA4SSH results.

### JA4SSH:  
c(mode of client TCP payload length)  
s(mode of server TCP payload length)  
_  
c(total ssh packets sent from client)  
s(total ssh packets sent from server)  
_  
c(ack packets seen from client)  
s(ack packets seen from server)
```
Example JA4SH = c36s36_c55s75_c70s0
```
### How to measure the mode for TCP payload lengths across 200 packets in the session:

Reminder: We’re looking at the TCP payload lengths, not the packet length. In wireshark this is under “tcp.len”. And this is only for SSH (layer 7) packets. This does not include TCP ACK packets or other layer 4 packets.

We’re looking for the mode, or the value that appears the most number of times in the data set, not the mean or median.

So if 36 bytes appear 20 times, and 128 bytes appear 10 times and 200 bytes appear 15 times, the mode is 36. If there is a collision, the program choses the smaller byte value.

JA4SSH calculates this for both the client and server separately.

### Counting the SSH packets:

JA4SSH counts the number of SSH (layer 7) packets sent from the client and server separately. This does not include ACK packets, TCP replays or any other layer 4 packets. 

### Counting the ACK packets:

JA4SSH counts the number of bare TCP ACK packets sent from the client and server separately.

### Example JA4SSH:
c36 (36 bytes was the mode for ssh packet lengths sent from client)
s36 (36 bytes was the mode for ssh packet lengths sent from server)
_
c55 (55 SSH packets were sent from the client)
s75 (75 SSH packets were sent from the server)
_
c70 (70 ack packets were sent from the client)
s0 (0 ack packets were sent from the server)
```
JA4SSH = c36s36_c55s75_c70s0
```

Forward SSH shell (notice the ACKs come from the client):
```
JA4SSH = c36s36_c51s80_c69s0
```
Reverse SSH shell (notice the ACKs come from the server):
```
JA4SSH = c76s76_c71s59_c0s70
```
SCP file transfer (always c112s1460):
```
JA4SSH = c112s1460_c0s179_c21s0
```
