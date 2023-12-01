# JA4+ Plugin for Wireshark

![JA4](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/screenshot.png)

This has been tested on Wireshark ver. 4.2.0 on Mac and Windows, ver 4.0.6 on Linux.

Create an issue or contact john@foxio.io with any questions.

## Install
#### Windows
1. Copy [windows/ja4.dll](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/windows/ja4.dll) to your global plugins directory under epan.  
```C:\Program Files\Wireshark\plugins\4.2\epan\```  
2. Start Wireshark

#### Mac
1. For Macs with ARM chips (M1/M2/etc) copy [mac/arm/ja4.so](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/mac/arm/ja4.so), for Macs with Intel chips (x86/x64) copy [mac/intel/ja4.so](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/mac/intel/ja4.so), to your global plugins directory under epan.  
```/Applications/Wireshark.app/Contents/PlugIns/wireshark/4-2/epan/```  
2. Start Wireshark

#### Linux
1. Copy [linux/ja4.so](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/linux/ja4.so) to your global plugins directory under epan.  
```plugins/4.0/epan/```  
2. Start Wireshark

## Config
JA4+ fields are under ja4.*  
JA4: ```ja4.ja4```  
JA4S: ```ja4.ja4s```  
JA4H: ```ja4.ja4h```  
JA4L-C: ```ja4.ja4lc```  
JA4L-S: ```ja4.ja4ls```  
JA4X: ```ja4.ja4x```  
JA4SSH: ```ja4.ja4ssh```  

Add JA4+ to your columns for easy identification and sorting. Go to ```Preferences...``` and add as follows:

![Config](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/column-config.png)

## Licensing
See [Licensing](https://github.com/FoxIO-LLC/ja4/tree/main#licensing) under repo root.
