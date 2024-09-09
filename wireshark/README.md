# JA4+ Plugin for Wireshark

![JA4](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/screenshot.png)

This has been tested on Wireshark ver. 4.4.0 and 4.2.0 on Mac and Windows, ver 4.0.6 on Linux.

Create an issue or contact john@foxio.io with any questions.

## Install
#### Windows
1. Copy [binaries/windows/4.4.0/ja4.dll](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/binaries/windows/4.4.0/ja4.dll) to your global plugins directory under epan.  
```C:\Program Files\Wireshark\plugins\4.4\epan\```  
2. Start Wireshark

#### Mac
1. For Macs with ARM chips (M1/M2/etc) copy [binaries/macos/4.4.0/arm/ja4.so](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/binaries/macos/4.4.0/arm/ja4.so), for Macs with Intel chips (x86/x64) copy [binaries/macos/4.4.0/intel/ja4.so](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/binaries/macos/4.4.0/intel/ja4.so), to your global plugins directory under epan.  
```/Applications/Wireshark.app/Contents/PlugIns/wireshark/4-4/epan/```  
2. Start Wireshark

#### Linux
1. Copy [binaries/linux/4.0.6/ja4.so](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/binaries/linux/4.0.6/ja4.so) to your global plugins directory under epan.  
```plugins/4.0/epan/```  
2. Start Wireshark

## Config
JA4+ fields are under ja4.*  
JA4: ```tls.handshake.ja4```  
JA4S: ```ja4.ja4s```  
JA4H: ```ja4.ja4h```  
JA4L: ```ja4.ja4l```  
JA4LS: ```ja4.ja4ls```  
JA4X: ```ja4.ja4x```  
JA4SSH: ```ja4.ja4ssh```  
JA4T: ```ja4.ja4t```  
JA4TS: ```ja4.ja4ts```  

Add JA4+ to your columns for easy identification and sorting. Go to ```Preferences...``` and add as follows:

![Config](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/column-config.png)

Alternatively, they can be added to the preferences by modifiying the user's "preferences" file using a text editor. In the text editor, find the section labeled  "User Interface: Columns" and add the following items:
```
	"JA4T", "%Cus:ja4.ja4t:0:R",
	"JA4TS", "%Cus:ja4.ja4ts:0:R",
	"JA4", "%Cus:tls.handshake.ja4:0:R",
	"JA4S", "%Cus:ja4.ja4s:0:R",
	"JA4H", "%Cus:ja4.ja4h:0:R",
	"JA4L", "%Cus:ja4.ja4l:0:R",
	"JA4LS", "%Cus:ja4.ja4ls:0:R",
	"JA4X", "%Cus:ja4.ja4x:0:R",
	"JA4SSH", "%Cus:ja4.ja4ssh:0:R"
```

The preference file is located in the following locations:
#### Windows
%APPDATA%\Wireshark\preferences
#### Mac
~/.config/wireshark/preferences
#### Linux
~/.config/wireshark/preferences

## Licensing
See [Licensing](https://github.com/FoxIO-LLC/ja4/tree/main#licensing) under repo root.
