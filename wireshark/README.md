# JA4+ Plugin for Wireshark

![JA4](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/screenshot.png)

This has been tested on Wireshark ver. 4.2.0
The current plugin is for Windows, a Mac version is coming soon.
Source code is coming soon.

## Install
1. Copy [ja4.dll](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/ja4.dll) to your global plugins directory under epan.  
Windows: ```C:\Program Files\Wireshark\plugins\4.2\epan\```  
Mac: ```/Applications/Wireshark.app/Contents/PlugIns/wireshark/4-2/epan/```  (Mac version coming soon)
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
