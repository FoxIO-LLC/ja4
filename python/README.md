# JA4+

Recommended to have tshark version 4.0.6 or later for full functionality. See: https://pkgs.org/search/?q=tshark  

### JA4+ on Ubuntu  
```
sudo apt install tshark
python3 ja4.py
```

### JA4+ on Mac
1) Install python3 https://www.python.org/downloads/macos/
2) Install Wireshark https://www.wireshark.org/download.html which will install tshark
3) Add tshark to $PATH
```
ln -s /Applications/Wireshark.app/Contents/MacOS/tshark /usr/local/bin/tshark
python3 ja4.py
```

### JA4+ on Windows
1) Install python3 using the Windows Installer https://www.python.org/downloads/windows/
2) Install Wireshark for Windows from https://www.wireshark.org/download.html, this will install tshark.exe  
tshark.exe is at the location where wireshark is installed, for example: C:\Program Files\Wireshark\thsark.exe  
3) Add the location of tshark to your "PATH" environment variable in Windows. This is important for pyshark to work correctly.  
   (System properties > Environment Variables... > Edit Path)  
4) Open cmd, navigate the ja4 folder
```
python3 ja4.py
```


## Usage
A set of python scripts for extracting JA4 fingerprints from PCAP files

```
positional arguments:
  pcap                  The pcap file to process

optional arguments:
  -h, --help            show this help message and exit
  -key KEY              The key file to use for decryption
  -v, --verbose         verbose mode
  -J, --json            output in JSON
  --ja4, --ja4          Output JA4 fingerprints only
  --ja4s, --ja4s        Output JA4S fingerprints only
  --ja4l, --ja4l        Output JA4L-C/S fingerprints only
  --ja4h, --ja4h        Output JA4H fingerprints only
  --ja4x, --ja4x        Output JA4X fingerprints only
  --ja4ssh, --ja4ssh      Output JA4SSH fingerprints only
  -r, --raw_fingerprint
                        Output raw fingerprint
  -o, --original_rendering
                        Output original rendering
  -f [OUTPUT], --output [OUTPUT]
                        Send output to file <filename>
  -s [STREAM], --stream [STREAM]
```

### Running ja4.py on pcap without a key file
```
#For default output:
ja4 capturefile.pcapng 

#For JSON output:
ja4 capturefile.pcapng -J

#To dump segments such as headers/cookies/ciphers, etc we can use -v
ja4 capturefile.pcapng -Jv

#To inspect a particular stream, use the -s option followed by the stream number
ja4 capturefile.pcapng -Jv -s 17

#Use the --ja4[s|h|l|x|ssh] options to specify a filter on the type of packets. for example the following outputs JA4H fingerprints only
ja4 capturefile.pcapng -J --ja4h

#Use the keyfile to decrypt TLS packets if the capture does not show the decrypted http headers
ja4 capturefile.pcapng -Jv -key sslkeylog.log
```

## Results - JSON format
The script allows to dump the output in JSON using the -J switch as follows:

```
ja4 <pcap-filename> -J
```

The output is as follows:
```
{
    "stream": 2,
    "src": "192.168.1.168",
    "dst": "142.251.163.95",
    "srcport": "50053",
    "dstport": "443",
    "client_ttl": "128",
    "domain": "optimizationguide-pa.googleapis.com",
    "JA4": "q13d0310h3_55b375c5d22e_cd85d2d88918",
    "server_ttl": "60",
    "JA4S": "q130200_1301_234ea6891581",
    "JA4L-S": "2380_60",
    "JA4L-C": "46_128"
}
{
    "stream": 3,
    "src": "192.168.1.168",
    "dst": "20.112.52.29",
    "srcport": "50154",
    "dstport": "80",
    "JA4H": "ge11nn07enus_bc8d2ed93139_000000000000_000000000000"
}
{
    "stream": 4,
    "src": "192.168.1.169",
    "dst": "44.212.59.210",
    "srcport": "64339",
    "dstport": "22",
    "client_ttl": "128",
    "server_ttl": "115",
    "JA4L-S": "2925_115",
    "JA4L-C": "20_128",
    "ssh_extras": {
        "hassh": "ec7378c1a92f5a8dde7e8b7a1ddf33d1",
        "hassh_server": "2307c390c7c9aba5b4c9519e72347f34",
        "ssh_protocol_client": "SSH-2.0-OpenSSH_for_Windows_8.1",
        "ssh_protocol_server": "SSH-2.0-OpenSSH_8.7",
        "encryption_algorithm": "aes256-gcm@openssh.com"
    },
    "JA4SSH.1": "c36s36_c38s93_c60s8",
    "JA4SSH.2": "c36s36_c40s95_c62s3",
    "JA4SSH.3": "c36s36_c51s80_c68s1",
    "JA4SSH.4": "c36s36_c12s12_c11s1"
}
```
